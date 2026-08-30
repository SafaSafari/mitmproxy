"""
Linux access points and traffic redirection for mitmproxy's `hotspot` mode.

Two backends are available:

 - `nmcli` drives NetworkManager, which is what almost every Linux desktop runs.
   NetworkManager takes care of DHCP, DNS, and NAT for us.
 - `hostapd` is the fallback for machines without NetworkManager. It runs
   `hostapd` and `dnsmasq` directly and configures addressing and NAT by hand.

Client traffic reaches mitmproxy in one of two ways:

 - `iproute2` sends it into mitmproxy's tun interface using policy routing.
   mitmproxy terminates the interface itself, which is what makes UDP (and
   therefore QUIC) interceptable. This is the default.
 - `nftables` / `iptables` rewrite the destination of TCP connections so that
   they land in a transparent listener. Simpler, but TCP-only.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import signal
import tempfile
from pathlib import Path

from mitmproxy.hotspot.base import HotspotBackend
from mitmproxy.hotspot.base import HotspotError
from mitmproxy.hotspot.base import HotspotStatus
from mitmproxy.hotspot.base import TrafficRedirector
from mitmproxy.hotspot.base import which

logger = logging.getLogger(__name__)

CONNECTION_NAME = "mitmproxy-hotspot"
"""The NetworkManager profile that the nmcli backend creates and deletes."""
TABLE_NAME = "mitmproxy_hotspot"
"""The nftables table / iptables chain that holds our redirection rules."""

HOSTAPD_GATEWAY = "10.42.42.1"
HOSTAPD_PREFIX = 24
HOSTAPD_DHCP_RANGE = ("10.42.42.10", "10.42.42.250")

ROUTE_TABLE = "8420"
"""The routing table that holds the default route into mitmproxy's tun interface."""
ROUTE_PRIORITY = "8420"
"""The `ip rule` priority that sends client traffic to `ROUTE_TABLE`."""


def wireless_interfaces() -> list[str]:
    """Return the names of all wireless interfaces, as reported by sysfs."""
    try:
        candidates = sorted(Path("/sys/class/net").iterdir())
    except OSError:  # pragma: no cover
        return []
    return [x.name for x in candidates if (x / "wireless").exists()]


class _LinuxBackend(HotspotBackend):
    """Shared helpers for the Linux backends."""

    platforms = ("linux",)

    async def default_route_interface(self) -> str | None:
        """Return the interface of the default route, i.e. our likely uplink."""
        if self.config.share:
            return self.config.share
        out = await self.run("ip", "-4", "route", "show", "default", check=False)
        if m := re.search(r"\bdev\s+(\S+)", out):
            return m.group(1)
        return None


class NetworkManagerBackend(_LinuxBackend):
    """An access point managed by NetworkManager."""

    name = "nmcli"

    @classmethod
    def available(cls) -> bool:
        return cls.supported() and which("nmcli")

    async def wifi_interface(self) -> str:
        """Return the interface to run the access point on."""
        if self.config.interface:
            return self.config.interface
        out = await self.run("nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status")
        for line in out.splitlines():
            device, _, device_type = line.partition(":")
            if device_type.strip() == "wifi":
                return device
        raise HotspotError(
            "NetworkManager does not report any Wi-Fi device. "
            "Specify one explicitly with `--mode hotspot:iface=<interface>`."
        )

    async def gateway_address(self, connection: str) -> str | None:
        """Read back the address NetworkManager assigned to the access point."""
        out = await self.run(
            "nmcli",
            "-t",
            "-f",
            "IP4.ADDRESS",
            "connection",
            "show",
            connection,
            check=False,
        )
        if m := re.search(r"(\d+\.\d+\.\d+\.\d+)/\d+", out):
            return m.group(1)
        return None

    async def start(self) -> HotspotStatus:
        interface = await self.wifi_interface()

        # a leftover profile from a previous crash would make `connection add` fail.
        await self.run("nmcli", "connection", "delete", CONNECTION_NAME, check=False)
        await self.run(
            # fmt: off
            "nmcli",
            "connection",
            "add",
            "type",
            "wifi",
            "ifname",
            interface,
            "con-name",
            CONNECTION_NAME,
            "autoconnect",
            "no",
            "ssid",
            self.config.ssid,
            # fmt: on
        )
        try:
            settings = [
                "802-11-wireless.mode",
                "ap",
                "802-11-wireless.band",
                self.config.band or "bg",
                # `shared` makes NetworkManager run DHCP + DNS and set up NAT.
                "ipv4.method",
                "shared",
                "ipv6.method",
                "ignore",
            ]
            if self.config.password:
                settings += [
                    "wifi-sec.key-mgmt",
                    "wpa-psk",
                    "wifi-sec.psk",
                    self.config.password,
                ]
            await self.run("nmcli", "connection", "modify", CONNECTION_NAME, *settings)
            await self.run("nmcli", "connection", "up", CONNECTION_NAME)
        except HotspotError:
            await self.run(
                "nmcli", "connection", "delete", CONNECTION_NAME, check=False
            )
            raise

        status = HotspotStatus(
            backend=self.name,
            ssid=self.config.ssid,
            password=self.config.password,
            interface=interface,
            address=await self.gateway_address(CONNECTION_NAME),
        )
        try:
            await self.start_redirector(status)
        except Exception:
            await self.stop()
            raise
        return status

    async def stop(self) -> None:
        await self.stop_redirector()
        await self.run("nmcli", "connection", "down", CONNECTION_NAME, check=False)
        await self.run("nmcli", "connection", "delete", CONNECTION_NAME, check=False)


class HostapdBackend(_LinuxBackend):
    """An access point built from `hostapd` and `dnsmasq`."""

    name = "hostapd"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.rundir: Path | None = None
        self.uplink: str | None = None
        self.interface: str | None = None

    @classmethod
    def available(cls) -> bool:
        return cls.supported() and which("hostapd", "dnsmasq", "ip")

    async def wifi_interface(self) -> str:
        if self.config.interface:
            return self.config.interface
        if interfaces := wireless_interfaces():
            return interfaces[0]
        raise HotspotError(
            "No wireless interface found in /sys/class/net. "
            "Specify one explicitly with `--mode hotspot:iface=<interface>`."
        )

    def hostapd_conf(self, interface: str) -> str:
        conf = [
            f"interface={interface}",
            "driver=nl80211",
            f"ssid={self.config.ssid}",
            f"hw_mode={'a' if self.config.band == 'a' else 'g'}",
            "channel=36" if self.config.band == "a" else "channel=6",
            "auth_algs=1",
            "wmm_enabled=1",
        ]
        if self.config.password:
            conf += [
                "wpa=2",
                f"wpa_passphrase={self.config.password}",
                "wpa_key_mgmt=WPA-PSK",
                "rsn_pairwise=CCMP",
            ]
        return "\n".join(conf) + "\n"

    def dnsmasq_conf(self, interface: str) -> str:
        start, end = HOSTAPD_DHCP_RANGE
        return (
            "\n".join(
                [
                    f"interface={interface}",
                    "bind-interfaces",
                    "except-interface=lo",
                    f"listen-address={HOSTAPD_GATEWAY}",
                    f"dhcp-range={start},{end},12h",
                    f"dhcp-option=3,{HOSTAPD_GATEWAY}",
                    f"dhcp-option=6,{HOSTAPD_GATEWAY}",
                    "server=8.8.8.8",
                    "server=1.1.1.1",
                ]
            )
            + "\n"
        )

    async def start(self) -> HotspotStatus:
        interface = self.interface = await self.wifi_interface()
        self.uplink = await self.default_route_interface()
        self.rundir = Path(tempfile.mkdtemp(prefix="mitmproxy-hotspot-"))
        hostapd_conf = self.rundir / "hostapd.conf"
        dnsmasq_conf = self.rundir / "dnsmasq.conf"
        hostapd_conf.write_text(self.hostapd_conf(interface))
        dnsmasq_conf.write_text(self.dnsmasq_conf(interface))

        try:
            await self.run_elevated("ip", "link", "set", "dev", interface, "down")
            await self.run_elevated("ip", "addr", "flush", "dev", interface)
            await self.run_elevated(
                "ip",
                "addr",
                "add",
                f"{HOSTAPD_GATEWAY}/{HOSTAPD_PREFIX}",
                "dev",
                interface,
            )
            await self.run_elevated("ip", "link", "set", "dev", interface, "up")
            await self.run_elevated(
                "hostapd",
                "-B",
                "-P",
                str(self.rundir / "hostapd.pid"),
                str(hostapd_conf),
            )
            await self.run_elevated(
                "dnsmasq",
                f"--conf-file={dnsmasq_conf}",
                f"--pid-file={self.rundir / 'dnsmasq.pid'}",
            )
            await self.run_elevated("sysctl", "-w", "net.ipv4.ip_forward=1")
            if self.uplink:
                await self.enable_nat(self.uplink)
        except Exception:
            await self.stop()
            raise

        status = HotspotStatus(
            backend=self.name,
            ssid=self.config.ssid,
            password=self.config.password,
            interface=interface,
            address=HOSTAPD_GATEWAY,
        )
        try:
            await self.start_redirector(status)
        except Exception:
            await self.stop()
            raise
        return status

    async def enable_nat(self, uplink: str) -> None:
        """Masquerade client traffic behind `uplink` so that clients reach the internet."""
        if which("nft"):
            await self.run_elevated(
                "nft",
                "-f",
                "-",
                stdin=(
                    f"table ip {TABLE_NAME}_nat\n"
                    f"delete table ip {TABLE_NAME}_nat\n"
                    f"table ip {TABLE_NAME}_nat {{\n"
                    f"  chain postrouting {{\n"
                    f"    type nat hook postrouting priority srcnat; policy accept;\n"
                    f'    oifname "{uplink}" masquerade\n'
                    f"  }}\n"
                    f"}}\n"
                ),
            )
        else:
            await self.run_elevated(
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                uplink,
                "-j",
                "MASQUERADE",
            )

    async def disable_nat(self, uplink: str) -> None:
        if which("nft"):
            await self.run_elevated(
                "nft", "delete", "table", "ip", f"{TABLE_NAME}_nat", check=False
            )
        else:
            await self.run_elevated(
                "iptables",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-o",
                uplink,
                "-j",
                "MASQUERADE",
                check=False,
            )

    def terminate(self, pidfile: Path) -> None:
        """Send SIGTERM to the daemon whose pid is stored in `pidfile`."""
        try:
            pid = int(pidfile.read_text().strip())
        except (OSError, ValueError):
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:  # pragma: no cover
            logger.debug(f"Failed to stop {pidfile.stem}: {e}")

    async def stop(self) -> None:
        await self.stop_redirector()
        if self.uplink:
            await self.disable_nat(self.uplink)
            self.uplink = None
        if self.rundir is not None:
            self.terminate(self.rundir / "hostapd.pid")
            self.terminate(self.rundir / "dnsmasq.pid")
            shutil.rmtree(self.rundir, ignore_errors=True)
            self.rundir = None
        if self.interface is not None:
            await self.run_elevated(
                "ip",
                "addr",
                "del",
                f"{HOSTAPD_GATEWAY}/{HOSTAPD_PREFIX}",
                "dev",
                self.interface,
                check=False,
            )
            self.interface = None


class TunRouter(TrafficRedirector):
    """
    Routes hotspot clients into mitmproxy's tun interface with policy routing.

    A single `ip rule` matching on the access point's interface is enough: it only
    ever sees *forwarded* packets, because anything addressed at the machine
    itself -- DHCP, DNS, `mitm.it` -- is resolved by the kernel's `local` table
    first, which sits at rule priority 0 and therefore wins.
    """

    name = "iproute2"
    capture = "tun"
    platforms = ("linux",)

    @classmethod
    def available(cls) -> bool:
        return cls.supported() and which("ip", "sysctl")

    async def start(self) -> None:
        tun = self.target.tun
        assert tun
        await self.stop()  # `ip rule add` stacks, so start from a clean slate

        await self.run("sysctl", "-w", "net.ipv4.ip_forward=1")
        await self.run("ip", "link", "set", "dev", tun, "up")
        await self.run(
            "ip", "route", "add", "default", "dev", tun, "table", ROUTE_TABLE
        )
        await self.run(
            "ip",
            "rule",
            "add",
            "iif",
            self.interface,
            "lookup",
            ROUTE_TABLE,
            "priority",
            ROUTE_PRIORITY,
        )

        try:
            await self.run("sysctl", "-w", "net.ipv6.conf.all.forwarding=1")
            await self.run(
                "ip",
                "-6",
                "route",
                "add",
                "default",
                "dev",
                tun,
                "table",
                ROUTE_TABLE,
            )
            await self.run(
                "ip",
                "-6",
                "rule",
                "add",
                "iif",
                self.interface,
                "lookup",
                ROUTE_TABLE,
                "priority",
                ROUTE_PRIORITY,
            )
        except HotspotError as e:  # pragma: no cover
            logger.debug(f"Not routing IPv6 hotspot traffic into {tun}: {e}")

    async def stop(self) -> None:
        for family in ([], ["-6"]):
            await self.run(
                "ip",
                *family,
                "rule",
                "del",
                "iif",
                self.interface,
                "lookup",
                ROUTE_TABLE,
                "priority",
                ROUTE_PRIORITY,
                check=False,
            )
            await self.run(
                "ip", *family, "route", "flush", "table", ROUTE_TABLE, check=False
            )


class NftablesRedirector(TrafficRedirector):
    """Redirects client traffic into mitmproxy using nftables."""

    name = "nftables"
    platforms = ("linux",)

    @classmethod
    def available(cls) -> bool:
        return cls.supported() and which("nft")

    def ruleset(self, family: str) -> str:
        """Build the nftables ruleset for the given address `family` (`ip` or `ip6`)."""
        rules = []
        if self.gateway and family == "ip":
            # traffic addressed at us (DHCP, DNS, mitm.it) must not be redirected.
            rules.append(
                f'    iifname "{self.interface}" ip daddr {self.gateway} return'
            )
        rules.append(
            f'    iifname "{self.interface}" meta l4proto tcp redirect to :{self.port}'
        )
        forward = ""
        if self.block_quic:
            # mitmproxy's transparent listener is TCP-only; dropping QUIC makes
            # clients fall back to TCP instead of silently bypassing us.
            forward = (
                f"  chain forward {{\n"
                f"    type filter hook forward priority filter; policy accept;\n"
                f'    iifname "{self.interface}" udp dport 443 drop\n'
                f"  }}\n"
            )
        newline = "\n"
        return (
            f"table {family} {TABLE_NAME}\n"
            f"delete table {family} {TABLE_NAME}\n"
            f"table {family} {TABLE_NAME} {{\n"
            f"  chain prerouting {{\n"
            f"    type nat hook prerouting priority dstnat; policy accept;\n"
            f"{newline.join(rules)}\n"
            f"  }}\n"
            f"{forward}"
            f"}}\n"
        )

    async def start(self) -> None:
        await self.run("nft", "-f", "-", stdin=self.ruleset("ip"))
        try:
            await self.run("nft", "-f", "-", stdin=self.ruleset("ip6"))
        except HotspotError as e:  # pragma: no cover
            logger.debug(f"Not redirecting IPv6 hotspot traffic: {e}")

    async def stop(self) -> None:
        for family in ("ip", "ip6"):
            await self.run("nft", "delete", "table", family, TABLE_NAME, check=False)


class IptablesRedirector(TrafficRedirector):
    """Redirects client traffic into mitmproxy using iptables."""

    name = "iptables"
    platforms = ("linux",)

    @classmethod
    def available(cls) -> bool:
        return cls.supported() and which("iptables")

    async def start(self) -> None:
        await self.stop()  # make sure we start from a clean slate
        await self.run("iptables", "-t", "nat", "-N", TABLE_NAME)
        if self.gateway:
            await self.run(
                "iptables",
                "-t",
                "nat",
                "-A",
                TABLE_NAME,
                "-d",
                self.gateway,
                "-j",
                "RETURN",
            )
        await self.run(
            "iptables",
            "-t",
            "nat",
            "-A",
            TABLE_NAME,
            "-p",
            "tcp",
            "-j",
            "REDIRECT",
            "--to-port",
            str(self.port),
        )
        await self.run(
            "iptables",
            "-t",
            "nat",
            "-I",
            "PREROUTING",
            "1",
            "-i",
            self.interface,
            "-j",
            TABLE_NAME,
        )
        if self.block_quic:
            await self.run(
                "iptables",
                "-I",
                "FORWARD",
                "1",
                "-i",
                self.interface,
                "-p",
                "udp",
                "--dport",
                "443",
                "-j",
                "DROP",
            )

    async def stop(self) -> None:
        await self.run(
            "iptables",
            "-D",
            "FORWARD",
            "-i",
            self.interface,
            "-p",
            "udp",
            "--dport",
            "443",
            "-j",
            "DROP",
            check=False,
        )
        await self.run(
            "iptables",
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-i",
            self.interface,
            "-j",
            TABLE_NAME,
            check=False,
        )
        await self.run("iptables", "-t", "nat", "-F", TABLE_NAME, check=False)
        await self.run("iptables", "-t", "nat", "-X", TABLE_NAME, check=False)
