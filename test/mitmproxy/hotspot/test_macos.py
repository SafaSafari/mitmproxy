import plistlib
import sys

import pytest

from .helpers import config
from .helpers import FakeRunner
from mitmproxy.hotspot import macos
from mitmproxy.hotspot.base import HotspotError


class TestInternetSharing:
    def backend(self, runner, tmp_path, monkeypatch, **kwargs):
        monkeypatch.setattr(macos, "NAT_PLIST", tmp_path / "com.apple.nat.plist")
        monkeypatch.setattr(macos, "which", lambda *a: True)
        monkeypatch.setattr(sys, "platform", "darwin")
        return macos.InternetSharingBackend(config(**kwargs), 8080, runner)

    def test_available(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(macos, "which", lambda *a: True)
        assert macos.InternetSharingBackend.available()

    async def test_uplink(self, tmp_path, monkeypatch):
        runner = FakeRunner(
            {"route -n get default": "  gateway: 1.2.3.4\n  interface: en0\n"}
        )
        b = self.backend(runner, tmp_path, monkeypatch)
        assert await b.uplink_device() == "en0"

        b = self.backend(FakeRunner(), tmp_path, monkeypatch, share="en5")
        assert await b.uplink_device() == "en5"

        with pytest.raises(HotspotError, match="uplink interface"):
            await self.backend(FakeRunner(), tmp_path, monkeypatch).uplink_device()

    async def test_start_stop(self, tmp_path, monkeypatch):
        runner = FakeRunner({"route -n get default": "  interface: en0\n"})
        b = self.backend(runner, tmp_path, monkeypatch, ssid="net", password="hunter22")
        status = await b.start()

        assert status.interface == macos.BRIDGE_INTERFACE
        assert status.redirector == "pf"
        settings = plistlib.loads(macos.NAT_PLIST.read_bytes())
        assert settings["NAT"]["AirPort"]["SSID_STR"] == "net"
        assert settings["NAT"]["PrimaryInterface"]["Device"] == "en0"
        assert runner.ran("launchctl kickstart")

        await b.stop()
        assert runner.ran("launchctl kill SIGTERM")
        assert not macos.NAT_PLIST.exists()

    async def test_restores_previous_config(self, tmp_path, monkeypatch):
        runner = FakeRunner(
            {"route -n get default": "  interface: en0\n"},
            fail=("launchctl kickstart",),
        )
        b = self.backend(runner, tmp_path, monkeypatch)
        macos.NAT_PLIST.write_bytes(b"previous")
        with pytest.raises(HotspotError, match="System Settings"):
            await b.start()
        assert macos.NAT_PLIST.read_bytes() == b"previous"

    async def test_cleanup_on_redirector_failure(self, tmp_path, monkeypatch):
        runner = FakeRunner(
            {"route -n get default": "  interface: en0\n"}, fail=("pfctl -a",)
        )
        b = self.backend(runner, tmp_path, monkeypatch)
        with pytest.raises(HotspotError):
            await b.start()
        assert not macos.NAT_PLIST.exists()

    async def test_unwritable_plist(self, tmp_path, monkeypatch):
        runner = FakeRunner({"route -n get default": "  interface: en0\n"})
        b = self.backend(runner, tmp_path, monkeypatch)
        monkeypatch.setattr(macos, "NAT_PLIST", tmp_path / "nope" / "x" / "nat.plist")
        monkeypatch.setattr(
            macos.Path, "mkdir", lambda *a, **kw: (_ for _ in ()).throw(OSError("nope"))
        )
        with pytest.raises(HotspotError, match="needs to run as root"):
            await b.start()


class TestPfRedirector:
    def test_ruleset(self):
        r = macos.PfRedirector("bridge100", "192.168.2.1", 8080, runner=FakeRunner())
        rules = r.ruleset()
        assert "block drop in on bridge100 proto udp to port 443" in rules
        assert "no rdr on bridge100 proto tcp to 192.168.2.1" in rules
        assert "rdr pass on bridge100 inet proto tcp" in rules
        assert "127.0.0.1 port 8080" in rules

    def test_minimal_ruleset(self):
        r = macos.PfRedirector(
            "bridge100", None, 8080, block_quic=False, runner=FakeRunner()
        )
        assert r.ruleset().count("\n") == 1

    def test_available(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(macos, "which", lambda *a: True)
        assert macos.PfRedirector.available()

    async def test_start_stop(self):
        runner = FakeRunner({"pfctl -E": "pf enabled\nToken : 12345678\n"})
        r = macos.PfRedirector("bridge100", None, 8080, runner=runner)
        await r.start()
        assert r.token == "12345678"
        await r.stop()
        assert runner.ran("pfctl -X 12345678")
        assert r.token is None

    async def test_start_without_token(self):
        r = macos.PfRedirector("bridge100", None, 8080, runner=FakeRunner())
        await r.start()
        assert r.token is None
        await r.stop()
