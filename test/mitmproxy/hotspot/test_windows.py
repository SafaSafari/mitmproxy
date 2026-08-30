import sys

import pytest

from .helpers import config
from .helpers import FakeRunner
from .helpers import target
from mitmproxy.hotspot import base
from mitmproxy.hotspot import windows
from mitmproxy.hotspot.base import HotspotError


class TestWindowsHotspot:
    def backend(self, runner, **kwargs):
        return windows.MobileHotspotBackend(config(**kwargs), target(), runner)

    def test_quote(self):
        assert windows._quote('a"b$c`d') == 'a`"b`$c``d'

    def test_available(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(windows, "which", lambda *a: True)
        assert windows.MobileHotspotBackend.available()

    async def test_start_stop(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        runner = FakeRunner()
        b = self.backend(runner, ssid="net", password="hunter22", redirect=False)
        status = await b.start()
        assert status.backend == "winhotspot"
        assert status.address is None
        script = " ".join(runner.calls[0])
        assert '$config.Ssid = "net"' in script
        assert '$config.Passphrase = "hunter22"' in script
        assert "StartTetheringAsync" in script

        await b.stop()
        assert any("StopTetheringAsync" in " ".join(c) for c in runner.calls)

    async def test_hosted_network_fallback(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        runner = FakeRunner(fail=("powershell.exe",))
        b = self.backend(runner, ssid="net", password="hunter22", redirect=False)
        await b.start()
        assert b.hosted_network
        assert runner.ran("netsh wlan set hostednetwork", "ssid=net")
        assert runner.ran("netsh wlan start hostednetwork")

        await b.stop()
        assert runner.ran("netsh wlan stop hostednetwork")
        assert not b.hosted_network

    async def test_cleanup_on_redirector_failure(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(base.TrafficRedirector, "_registry", {})
        runner = FakeRunner()
        b = self.backend(runner, ssid="net", password="hunter22")
        with pytest.raises(HotspotError, match="Cannot send hotspot traffic"):
            await b.start()
        assert any("StopTetheringAsync" in " ".join(c) for c in runner.calls)

    async def test_both_fail(self):
        runner = FakeRunner(fail=("powershell.exe", "netsh"))
        with pytest.raises(HotspotError, match="as administrator"):
            await self.backend(runner, redirect=False).start()


def test_windivert_is_windows_only(monkeypatch):
    assert not windows.WinDivertRedirector.supported()
    monkeypatch.setattr(sys, "platform", "win32")
    assert windows.WinDivertRedirector.available()
