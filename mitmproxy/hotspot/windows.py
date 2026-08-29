"""
Windows access point and traffic redirection for mitmproxy's `hotspot` mode.

The access point is Windows' built-in Mobile Hotspot, which is driven through
the `NetworkOperatorTetheringManager` WinRT API. Older machines whose drivers
still support the legacy hosted network are handled by the `netsh` fallback.

Redirection reuses the WinDivert-based forwarding redirector that mitmproxy
already ships for transparent mode (`mitmproxy.platform.windows`). It hooks
WinDivert's `NETWORK_FORWARD` layer, which is exactly the traffic that a
hotspot client produces.
"""

from __future__ import annotations

import logging

from mitmproxy.hotspot.base import HotspotBackend
from mitmproxy.hotspot.base import HotspotError
from mitmproxy.hotspot.base import HotspotStatus
from mitmproxy.hotspot.base import TrafficRedirector
from mitmproxy.hotspot.base import which

logger = logging.getLogger(__name__)

POWERSHELL = "powershell.exe"

_AWAIT_HELPER = """
$ErrorActionPreference = "Stop"
function Await($op, $type) {
    $task = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and
                       $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } |
        Select-Object -First 1
    $task = $task.MakeGenericMethod($type).Invoke($null, @($op))
    $task.Wait(60000) | Out-Null
    return $task.Result
}
[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType=WindowsRuntime] | Out-Null
[Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType=WindowsRuntime] | Out-Null
$connProfile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
if ($connProfile -eq $null) { throw "No internet connection profile found." }
$manager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($connProfile)
$resultType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]
"""

# Only the tail is formatted: the helper above contains literal braces.
_START_TEMPLATE = """
$config = $manager.GetCurrentAccessPointConfiguration()
$config.Ssid = "{ssid}"
$config.Passphrase = "{password}"
Await ($manager.ConfigureAccessPointAsync($config)) $resultType | Out-Null
$result = Await ($manager.StartTetheringAsync()) $resultType
# 0 is Success, 1 is "already on".
if ($result.Status -ne 0 -and $result.Status -ne 1) {{
    throw "StartTetheringAsync failed with status $($result.Status): $($result.AdditionalErrorMessage)"
}}
"""

_STOP_SCRIPT = (
    _AWAIT_HELPER
    + """
Await ($manager.StopTetheringAsync()) $resultType | Out-Null
"""
)


def _quote(value: str) -> str:
    """Escape a value for embedding in a double-quoted PowerShell string."""
    return value.replace("`", "``").replace('"', '`"').replace("$", "`$")


class MobileHotspotBackend(HotspotBackend):
    """An access point provided by the Windows Mobile Hotspot."""

    name = "winhotspot"
    platforms = ("win32",)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.hosted_network = False
        """Whether we fell back to the legacy `netsh` hosted network."""

    @classmethod
    def available(cls) -> bool:
        return cls.supported() and which(POWERSHELL)

    async def powershell(self, script: str) -> str:
        return await self.run(
            POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", script
        )

    async def start_hosted_network(self) -> None:
        """Start the legacy hosted network, which some older drivers still support."""
        await self.run(
            "netsh",
            "wlan",
            "set",
            "hostednetwork",
            "mode=allow",
            f"ssid={self.config.ssid}",
            f"key={self.config.password or ''}",
        )
        await self.run("netsh", "wlan", "start", "hostednetwork")
        self.hosted_network = True

    async def start(self) -> HotspotStatus:
        script = _AWAIT_HELPER + _START_TEMPLATE.format(
            ssid=_quote(self.config.ssid), password=_quote(self.config.password or "")
        )
        try:
            await self.powershell(script)
        except HotspotError as e:
            logger.debug(f"Mobile Hotspot unavailable ({e}), trying hosted network.")
            try:
                await self.start_hosted_network()
            except HotspotError as fallback_error:
                raise HotspotError(
                    f"Failed to start a Windows hotspot.\n"
                    f"Mobile Hotspot: {e}\n"
                    f"Hosted network: {fallback_error}\n"
                    f"Make sure mitmproxy runs as administrator and that your Wi-Fi "
                    f"adapter supports acting as an access point."
                ) from e

        status = HotspotStatus(
            backend=self.name,
            ssid=self.config.ssid,
            password=self.config.password,
            # Windows does not expose a stable adapter name for the hotspot,
            # and the WinDivert redirector does not filter by interface anyway.
            interface=self.config.interface or "Local Area Connection* 1",
            address=None,
        )
        try:
            await self.start_redirector(status)
        except Exception:
            await self.stop()
            raise
        return status

    async def stop(self) -> None:
        await self.stop_redirector()
        if self.hosted_network:
            await self.run("netsh", "wlan", "stop", "hostednetwork", check=False)
            self.hosted_network = False
        else:
            try:
                await self.powershell(_STOP_SCRIPT)
            except HotspotError as e:  # pragma: no cover
                logger.debug(f"Failed to stop Mobile Hotspot: {e}")


class WinDivertRedirector(TrafficRedirector):
    """
    Redirects client traffic into mitmproxy using WinDivert.

    This is the same mechanism that mitmproxy's transparent mode uses on Windows;
    it captures forwarded packets before Windows routes them onward.
    """

    name = "windivert"
    platforms = ("win32",)

    async def start(self) -> None:  # pragma: no cover on non-Windows
        from mitmproxy import platform

        if self.port != 8080:
            logger.warning(
                f"The Windows redirector always redirects to port 8080, but this "
                f"hotspot listens on port {self.port}. Traffic will not be intercepted; "
                f"start mitmproxy with `--mode hotspot@8080` instead."
            )
        try:
            platform.init_transparent_mode()
        except Exception as e:
            raise HotspotError(
                f"Failed to start the WinDivert redirector: {e}. "
                f"Hotspot mode needs to run as administrator on Windows."
            ) from e

    async def stop(self) -> None:  # pragma: no cover on non-Windows
        # The redirector is a process-wide singleton that mitmproxy keeps running
        # for the lifetime of the process, the same way transparent mode does.
        pass
