import sys

import pytest

from .helpers import config
from .helpers import FakeRunner
from .helpers import target
from mitmproxy import hotspot
from mitmproxy.hotspot import linux
from mitmproxy.hotspot import manual
from mitmproxy.hotspot.base import HotspotError


class TestManual:
    async def test_start_stop(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        runner = FakeRunner()
        b = manual.ManualBackend(
            config(interface="bridge100", gateway="192.168.2.1"), target(), runner
        )
        status = await b.start()
        assert status.backend == "manual"
        assert status.interface == "bridge100"
        assert status.address == "192.168.2.1"
        await b.stop()
        assert runner.ran("nft delete table")

    def test_not_chosen_automatically(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: False)
        with pytest.raises(HotspotError, match="No usable hotspot backend"):
            hotspot.create_backend(config(interface="wlan0"), target())
