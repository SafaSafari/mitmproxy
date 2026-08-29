"""
macOS access point and traffic redirection for mitmproxy's `hotspot` mode.

The access point is macOS' built-in Internet Sharing, which is configured
through `/Library/Preferences/SystemConfiguration/com.apple.nat.plist` and
started through `launchd`. Traffic is redirected with `pf`.

Internet Sharing is a somewhat reluctant citizen on the command line: recent
macOS versions require the feature to be approved once through System Settings.
If we cannot start it, we say so instead of pretending that the hotspot is up.
"""

from __future__ import annotations

import logging
import plistlib
from pathlib import Path

from mitmproxy.hotspot.base import HotspotBackend
from mitmproxy.hotspot.base import HotspotError
from mitmproxy.hotspot.base import HotspotStatus
from mitmproxy.hotspot.base import TrafficRedirector
from mitmproxy.hotspot.base import which

logger = logging.getLogger(__name__)

NAT_PLIST = Path("/Library/Preferences/SystemConfiguration/com.apple.nat.plist")
SERVICE = "system/com.apple.InternetSharing"
ANCHOR = "com.apple/mitmproxy-hotspot"
"""
We load our rules into an anchor below `com.apple`, which macOS' stock
`/etc/pf.conf` already references. That way we do not have to edit pf.conf.
"""
BRIDGE_INTERFACE = "bridge100"
"""The interface Internet Sharing creates for its Wi-Fi clients."""
BRIDGE_GATEWAY = "192.168.2.1"


class InternetSharingBackend(HotspotBackend):
    """An access point provided by macOS Internet Sharing."""

    name = "internetsharing"
    platforms = ("darwin",)

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.previous_config: bytes | None = None

    @classmethod
    def available(cls) -> bool:
        return cls.supported() and which("launchctl", "networksetup")

    async def uplink_device(self) -> str:
        """Return the BSD device name of the interface that provides internet access."""
        if self.config.share:
            return self.config.share
        out = await self.run("route", "-n", "get", "default", check=False)
        for line in out.splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "interface":
                return value.strip()
        raise HotspotError(
            "Could not determine the uplink interface. "
            "Specify one explicitly with `--mode hotspot:share=<interface>`."
        )

    def nat_settings(self, uplink: str) -> dict:
        """Build the Internet Sharing configuration that shares `uplink` over Wi-Fi."""
        return {
            "NAT": {
                "AirPort": {
                    "40BitEncrypt": 1,
                    "Channel": 0,
                    "Enabled": 1,
                    "SSID_STR": self.config.ssid,
                    "WEP_ENABLED": bool(self.config.password),
                    "WEP_KEY_STR": self.config.password or "",
                },
                "Enabled": 1,
                "PrimaryInterface": {
                    "Device": uplink,
                    "Enabled": 1,
                    "HardwareKey": "",
                },
                "PrimaryService": "",
                "SharingDevices": ["en0"],
            }
        }

    async def start(self) -> HotspotStatus:
        uplink = await self.uplink_device()
        try:
            self.previous_config = NAT_PLIST.read_bytes()
        except OSError:
            self.previous_config = None

        try:
            NAT_PLIST.parent.mkdir(parents=True, exist_ok=True)
            NAT_PLIST.write_bytes(plistlib.dumps(self.nat_settings(uplink)))
        except OSError as e:
            raise HotspotError(
                f"Cannot write {NAT_PLIST}: {e}. Hotspot mode needs to run as root on macOS."
            ) from e

        try:
            await self.run("launchctl", "enable", SERVICE, check=False)
            await self.run("launchctl", "kickstart", "-k", SERVICE)
        except HotspotError as e:
            await self.restore_config()
            raise HotspotError(
                f"Failed to start macOS Internet Sharing: {e}\n"
                f"Recent macOS versions require Internet Sharing to be enabled once in "
                f"System Settings > General > Sharing. Alternatively, share your connection "
                f"manually and then run mitmproxy with "
                f"`--mode hotspot:backend=manual,iface={BRIDGE_INTERFACE}`."
            ) from e

        status = HotspotStatus(
            backend=self.name,
            ssid=self.config.ssid,
            password=self.config.password,
            interface=self.config.interface or BRIDGE_INTERFACE,
            address=BRIDGE_GATEWAY,
        )
        try:
            await self.start_redirector(status)
        except Exception:
            await self.stop()
            raise
        return status

    async def restore_config(self) -> None:
        """Put the previous Internet Sharing configuration back in place."""
        try:
            if self.previous_config is None:
                NAT_PLIST.unlink(missing_ok=True)
            else:
                NAT_PLIST.write_bytes(self.previous_config)
        except OSError as e:  # pragma: no cover
            logger.debug(f"Failed to restore {NAT_PLIST}: {e}")
        finally:
            self.previous_config = None

    async def stop(self) -> None:
        await self.stop_redirector()
        await self.run("launchctl", "kill", "SIGTERM", SERVICE, check=False)
        await self.run("launchctl", "disable", SERVICE, check=False)
        await self.restore_config()


class PfRedirector(TrafficRedirector):
    """Redirects client traffic into mitmproxy using `pf`."""

    name = "pf"
    platforms = ("darwin", "freebsd", "openbsd")

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.token: str | None = None
        """The reference token that keeps pf enabled while we are running."""

    @classmethod
    def available(cls) -> bool:
        return cls.supported() and which("pfctl")

    def ruleset(self) -> str:
        rules = []
        if self.block_quic:
            # mitmproxy's transparent listener is TCP-only; dropping QUIC makes
            # clients fall back to TCP instead of silently bypassing us.
            rules.append(f"block drop in on {self.interface} proto udp to port 443")
        if self.gateway:
            # traffic addressed at us (DHCP, DNS, mitm.it) must not be redirected.
            rules.append(f"no rdr on {self.interface} proto tcp to {self.gateway}")
        rules.append(
            f"rdr pass on {self.interface} inet proto tcp from any to any "
            f"-> 127.0.0.1 port {self.port}"
        )
        return "\n".join(rules) + "\n"

    async def start(self) -> None:
        await self.run("pfctl", "-a", ANCHOR, "-f", "-", stdin=self.ruleset())
        # -E enables pf and bumps its reference count, -X below drops it again.
        # pfctl prints the token on stderr.
        out = await self.run("pfctl", "-E", check=False, capture_stderr=True)
        self.token = _pf_token(out)

    async def stop(self) -> None:
        await self.run("pfctl", "-a", ANCHOR, "-F", "all", check=False)
        if self.token:
            await self.run("pfctl", "-X", self.token, check=False)
            self.token = None


def _pf_token(output: str) -> str | None:
    """Extract the reference token that `pfctl -E` prints, if any."""
    for line in output.splitlines():
        if "Token" in line:
            return line.rpartition(":")[2].strip()
    return None
