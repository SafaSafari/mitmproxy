import sys

import pytest

from .helpers import config
from .helpers import FakeRunner
from mitmproxy import hotspot
from mitmproxy.hotspot import base
from mitmproxy.hotspot import linux
from mitmproxy.hotspot.base import HotspotConfig
from mitmproxy.hotspot.base import HotspotError


class TestRun:
    async def test_stdout(self):
        out = await base.run(sys.executable, "-c", "print('hello')")
        assert out.strip() == "hello"

    async def test_stdin(self):
        out = await base.run(
            sys.executable,
            "-c",
            "import sys; sys.stdout.write(sys.stdin.read())",
            stdin="ping",
        )
        assert out == "ping"

    async def test_capture_stderr(self):
        out = await base.run(
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('Token : 42')",
            capture_stderr=True,
        )
        assert "Token : 42" in out

    async def test_check(self):
        with pytest.raises(HotspotError, match="exit code 3"):
            await base.run(sys.executable, "-c", "raise SystemExit(3)")
        assert (
            await base.run(sys.executable, "-c", "raise SystemExit(3)", check=False)
            == ""
        )

    async def test_not_found(self):
        with pytest.raises(HotspotError, match="Failed to run"):
            await base.run("./mitmproxy-does-not-exist")

    async def test_timeout(self):
        with pytest.raises(HotspotError, match="Timed out"):
            await base.run(
                sys.executable, "-c", "import time; time.sleep(10)", timeout=0.2
            )


def test_which():
    assert not base.which("mitmproxy-does-not-exist")


class TestConfig:
    def test_defaults(self):
        assert HotspotConfig.parse("") == HotspotConfig()
        assert HotspotConfig.parse("   ") == HotspotConfig()

    def test_ssid_shorthand(self):
        assert HotspotConfig.parse("my-network").ssid == "my-network"

    def test_pairs(self):
        c = HotspotConfig.parse(
            "ssid=net,pass=hunter22,iface=wlan0,uplink=eth0,gw=10.0.0.1,band=a"
        )
        assert c.ssid == "net"
        assert c.password == "hunter22"
        assert c.interface == "wlan0"
        assert c.share == "eth0"
        assert c.gateway == "10.0.0.1"
        assert c.band == "a"

    def test_comma_in_value(self):
        # `network` is not an option name, so it stays part of the SSID.
        assert HotspotConfig.parse("ssid=my,network,band=bg").ssid == "my,network"

    def test_booleans(self):
        assert HotspotConfig.parse("quic=allow").block_quic is False
        assert HotspotConfig.parse("quic=block").block_quic is True
        assert HotspotConfig.parse("redirect=off").redirect is False
        assert HotspotConfig.parse("redirect=1").redirect is True

    def test_empty_value(self):
        assert HotspotConfig.parse("password=").password is None

    @pytest.mark.parametrize(
        "spec,error",
        [
            ("nope=1", "invalid hotspot option"),
            ("quic=maybe", "invalid value"),
            ("password=short", "8 and 63"),
            ("ssid=" + "x" * 33, "1 and 32 bytes"),
            ("band=ac", "bg"),
            ("backend=carrier-pigeon", "unknown backend"),
            ("backend=manual", "requires an interface"),
        ],
    )
    def test_invalid(self, spec, error):
        with pytest.raises(ValueError, match=error):
            HotspotConfig.parse(spec)

    def test_open_network(self):
        assert HotspotConfig.parse("ssid=open,password=").validated().password is None


class TestRegistry:
    def test_backend_names(self):
        assert set(base.HotspotBackend._registry) == set(base.BACKEND_NAMES)

    def test_explicit_backend(self, monkeypatch):
        monkeypatch.setattr(linux, "which", lambda *a: True)
        monkeypatch.setattr(sys, "platform", "linux")
        b = hotspot.create_backend(config(backend="nmcli"), 8080)
        assert isinstance(b, linux.NetworkManagerBackend)

    def test_explicit_backend_unavailable(self, monkeypatch):
        monkeypatch.setattr(linux, "which", lambda *a: False)
        with pytest.raises(HotspotError, match="not available"):
            hotspot.create_backend(config(backend="nmcli"), 8080)

    def test_unknown_backend(self):
        # HotspotConfig rejects these, but the registry guards against it as well.
        with pytest.raises(HotspotError, match="Unknown hotspot backend"):
            hotspot.create_backend(HotspotConfig(backend="nope"), 8080)

    def test_autodetect_prefers_nmcli(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        assert isinstance(
            hotspot.create_backend(config(), 8080), linux.NetworkManagerBackend
        )

    def test_autodetect_falls_back_to_hostapd(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: "nmcli" not in a)
        assert isinstance(hotspot.create_backend(config(), 8080), linux.HostapdBackend)

    def test_autodetect_nothing_available(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: False)
        with pytest.raises(HotspotError, match="No usable hotspot backend"):
            hotspot.create_backend(config(), 8080)

    def test_redirector_autodetect(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: "nft" not in a)
        assert isinstance(
            hotspot.create_redirector("wlan0", None, 8080), linux.IptablesRedirector
        )

    def test_no_redirector(self, monkeypatch):
        monkeypatch.setattr(base.TrafficRedirector, "_registry", {})
        with pytest.raises(HotspotError, match="Cannot redirect hotspot traffic"):
            hotspot.create_redirector("wlan0", None, 8080)


@pytest.fixture
def fake_stack(monkeypatch):
    """
    A backend and redirector that only record what they were asked to do.

    The registries are swapped out before the classes are defined, so the fakes
    register into a throwaway dict that monkeypatch discards afterwards.
    """
    monkeypatch.setattr(base.HotspotBackend, "_registry", {})
    monkeypatch.setattr(base.TrafficRedirector, "_registry", {})
    log: list[str] = []

    class FakeRedirector(base.TrafficRedirector):
        name = "fake-redirector"

        async def start(self) -> None:
            log.append(f"start {self.interface} {self.gateway} {self.port}")

        async def stop(self) -> None:
            log.append("stop")

    class FakeBackend(base.HotspotBackend):
        name = "fake-backend"

        async def start(self) -> base.HotspotStatus:
            status = base.HotspotStatus(
                backend=self.name,
                ssid=self.config.ssid,
                password=self.config.password,
                interface="wlan0",
                address="10.0.0.1",
            )
            await self.start_redirector(status)
            return status

        async def stop(self) -> None:
            await self.stop_redirector()

    return FakeBackend, FakeRedirector, log


class TestBackendLifecycle:
    def test_default_availability(self, fake_stack):
        backend_cls, _, _ = fake_stack
        # neither declares a platform, so both are available anywhere.
        assert backend_cls.available()

    async def test_redirector_is_wired_up(self, fake_stack):
        backend_cls, redirector_cls, log = fake_stack
        b = backend_cls(config(ssid="net"), 8080, FakeRunner())

        status = await b.start()
        assert status.redirector == "fake-redirector"
        assert log == ["start wlan0 10.0.0.1 8080"]
        assert status.to_json() == {
            "backend": "fake-backend",
            "ssid": "net",
            "password": "mitmproxy",
            "interface": "wlan0",
            "address": "10.0.0.1",
            "redirector": "fake-redirector",
        }

        await b.stop()
        assert log[-1] == "stop"
        # stopping twice must not stop the redirector twice.
        await b.stop()
        assert log.count("stop") == 1

    async def test_redirect_disabled(self, fake_stack, caplog):
        backend_cls, redirector_cls, log = fake_stack
        b = backend_cls(config(redirect=False), 8080, FakeRunner())
        status = await b.start()
        assert status.redirector is None
        assert log == []
        assert "10.0.0.1:8080 as an HTTP proxy" in caplog.text

    async def test_redirector_failure_is_explained(self, fake_stack, monkeypatch):
        backend_cls, redirector_cls, log = fake_stack

        async def boom(self):
            raise HotspotError("nft: Operation not permitted")

        monkeypatch.setattr(redirector_cls, "start", boom)
        b = backend_cls(config(), 8080, FakeRunner())
        with pytest.raises(HotspotError, match="requires root") as e:
            await b.start()
        assert "Operation not permitted" in str(e.value)
