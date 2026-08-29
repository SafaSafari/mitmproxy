"""
The `manual` hotspot backend.

Sometimes the access point already exists: a phone in tethering mode, a spare
travel router, a `nmcli` hotspot that was set up by hand, or a macOS Internet
Sharing session that was enabled through System Settings. In those cases there
is nothing to create -- mitmproxy only needs to install the rules that send the
clients' traffic through the proxy.

This backend is never chosen automatically, because it cannot tell whether the
interface it is pointed at actually carries hotspot clients.
"""

from __future__ import annotations

from mitmproxy.hotspot.base import HotspotBackend
from mitmproxy.hotspot.base import HotspotStatus


class ManualBackend(HotspotBackend):
    """Redirect traffic on an existing access point without managing it."""

    name = "manual"

    async def start(self) -> HotspotStatus:
        assert self.config.interface  # guaranteed by HotspotConfig.validated()
        status = HotspotStatus(
            backend=self.name,
            ssid=self.config.ssid,
            password=self.config.password,
            interface=self.config.interface,
            address=self.config.gateway,
        )
        await self.start_redirector(status)
        return status

    async def stop(self) -> None:
        await self.stop_redirector()
