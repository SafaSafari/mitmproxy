"""
Building blocks for mitmproxy's `hotspot` proxy mode.

This module contains everything that is not operating-system specific:
the parsed mode configuration, the subprocess helper that all backends use,
and the two abstract interfaces that the platform modules implement.

A hotspot consists of two independent halves:

 1. An *access point* (`HotspotBackend`) that hands out an SSID and assigns
    addresses to clients. This is the part that differs wildly between
    operating systems.
 2. A *redirector* (`TrafficRedirector`) that forces the traffic of every
    connected client through mitmproxy's transparent proxy listener.

Both halves are pluggable so that users can, for example, keep an access point
that they created themselves and only let mitmproxy install the redirection
rules (`--mode hotspot:backend=manual,iface=wlan0`).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import sys
from abc import ABCMeta
from abc import abstractmethod
from collections.abc import Awaitable
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from typing import ClassVar

logger = logging.getLogger(__name__)

DEFAULT_SSID = "mitmproxy"
DEFAULT_PASSWORD = "mitmproxy"

BACKEND_NAMES = ("nmcli", "hostapd", "internetsharing", "winhotspot", "manual")
"""All backend names that `HotspotConfig` accepts for `backend=`."""


class HotspotError(Exception):
    """Raised when a hotspot cannot be created, configured, or torn down."""


CommandRunner = Callable[..., Awaitable[str]]
"""
Runs a command and returns its stdout.

Backends never call `asyncio.create_subprocess_exec` directly, they go through a
`CommandRunner` instead. This keeps them testable without a Wi-Fi card attached.
"""


async def run(
    *args: str,
    check: bool = True,
    timeout: float = 60,
    stdin: str | None = None,
    capture_stderr: bool = False,
) -> str:
    """
    Run `args`, optionally feeding it `stdin`, and return the decoded stdout.

    Some tools print the information we are after on stderr; `capture_stderr`
    appends it to the returned output.

    Raises `HotspotError` if the command cannot be found, times out, or -- unless
    `check` is disabled -- exits with a non-zero status.
    """
    cmd = " ".join(args)
    logger.debug(f"hotspot: running {cmd}")
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as e:
        raise HotspotError(f"Failed to run {cmd!r}: {e}") from e

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(stdin.encode() if stdin is not None else None), timeout
        )
    except (TimeoutError, asyncio.TimeoutError):
        proc.kill()
        await proc.wait()
        raise HotspotError(f"Timed out after {timeout}s while running {cmd!r}.")

    out = stdout.decode(errors="replace")
    err = stderr.decode(errors="replace")
    if check and proc.returncode != 0:
        raise HotspotError(
            f"{cmd!r} failed with exit code {proc.returncode}: "
            f"{err.strip() or out.strip()}"
        )
    if capture_stderr:
        return out + err
    return out


def which(*executables: str) -> bool:
    """Return whether all of `executables` are on `PATH`."""
    return all(shutil.which(x) is not None for x in executables)


@dataclass(frozen=True)
class HotspotConfig:
    """The parsed configuration of a `hotspot` mode spec."""

    ssid: str = DEFAULT_SSID
    """The network name that clients will see."""
    password: str | None = DEFAULT_PASSWORD
    """The WPA2 passphrase. Unset (`password=`) creates an open network."""
    interface: str | None = None
    """The wireless interface that hosts the access point. Autodetected if unset."""
    share: str | None = None
    """The uplink interface that provides internet access. Autodetected if unset."""
    gateway: str | None = None
    """
    The address clients use as their gateway. Determined by the backend if unset.

    Traffic addressed at the gateway itself (DHCP, DNS, `mitm.it`) is exempt from
    redirection, so the `manual` backend usually wants this set.
    """
    band: str | None = None
    """`bg` for 2.4 GHz or `a` for 5 GHz. Backend default if unset."""
    backend: str | None = None
    """Force a specific backend instead of picking the best available one."""
    redirect: bool = True
    """Install the rules that force client traffic through mitmproxy."""
    block_quic: bool = True
    """
    Drop QUIC from clients so that browsers fall back to TCP.

    mitmproxy's transparent listener is TCP-only, so without this a browser would
    happily talk HTTP/3 straight past us.
    """

    _ALIASES: ClassVar[dict[str, str]] = {
        "ssid": "ssid",
        "password": "password",
        "pass": "password",
        "iface": "interface",
        "interface": "interface",
        "share": "share",
        "uplink": "share",
        "gateway": "gateway",
        "gw": "gateway",
        "band": "band",
        "backend": "backend",
        "redirect": "redirect",
        "quic": "block_quic",
    }
    _BOOLS: ClassVar[dict[str, bool]] = {
        "true": True,
        "false": False,
        "yes": True,
        "no": False,
        "on": True,
        "off": False,
        "1": True,
        "0": False,
        "allow": False,
        "block": True,
    }

    @classmethod
    def parse(cls, data: str) -> HotspotConfig:
        """
        Parse the mode data of a `hotspot` spec.

        The data is a comma-separated list of `key=value` pairs. As a shorthand,
        data without any `=` is taken as the SSID, so `hotspot:my-network` and
        `hotspot:ssid=my-network` are equivalent.

        Raises `ValueError` on unknown keys or invalid values.
        """
        data = data.strip()
        if not data:
            return cls()
        if "=" not in data:
            return cls(ssid=data).validated()

        values: dict[str, Any] = {}
        for part in _split_pairs(data, cls._ALIASES):
            key, _, value = part.partition("=")
            key = key.strip().lower()
            try:
                attr = cls._ALIASES[key]
            except KeyError:
                raise ValueError(
                    f"invalid hotspot option {key!r}, "
                    f"expected one of {', '.join(sorted(cls._ALIASES))}"
                )
            if attr in ("redirect", "block_quic"):
                try:
                    values[attr] = cls._BOOLS[value.strip().lower()]
                except KeyError:
                    raise ValueError(f"invalid value for {key!r}: {value!r}")
            else:
                values[attr] = value.strip() or None
        return cls(**values).validated()

    def validated(self) -> HotspotConfig:
        """Return self after checking that all values make sense. Raises `ValueError`."""
        if not self.ssid or len(self.ssid.encode()) > 32:
            raise ValueError("ssid must be between 1 and 32 bytes")
        if self.password and not 8 <= len(self.password) <= 63:
            raise ValueError(
                "password must be between 8 and 63 characters (or empty for an open network)"
            )
        if self.band is not None and self.band not in ("bg", "a"):
            raise ValueError("band must be either 'bg' (2.4 GHz) or 'a' (5 GHz)")
        if self.backend is not None and self.backend not in BACKEND_NAMES:
            raise ValueError(
                f"unknown backend {self.backend!r}, expected one of {', '.join(BACKEND_NAMES)}"
            )
        if self.backend == "manual" and not self.interface:
            raise ValueError(
                "the manual backend requires an interface, e.g. iface=wlan0"
            )
        return self


def _split_pairs(data: str, aliases: dict[str, str]) -> list[str]:
    """
    Split `data` on commas, but keep commas that are part of a value.

    `ssid=my,network,band=a` splits into `["ssid=my,network", "band=a"]` because
    `network` is not a known option name.
    """
    parts: list[str] = []
    for chunk in data.split(","):
        key = chunk.partition("=")[0].strip().lower()
        if parts and ("=" not in chunk or key not in aliases):
            parts[-1] += f",{chunk}"
        else:
            parts.append(chunk)
    return parts


@dataclass
class HotspotStatus:
    """A description of the hotspot that is currently running."""

    backend: str
    """The name of the backend that created the access point."""
    ssid: str
    password: str | None
    interface: str
    """The interface the access point runs on."""
    address: str | None = None
    """The gateway address that clients use, if known."""
    redirector: str | None = None
    """The name of the active redirector, or `None` if traffic is not redirected."""

    def to_json(self) -> dict:
        return {
            "backend": self.backend,
            "ssid": self.ssid,
            "password": self.password,
            "interface": self.interface,
            "address": self.address,
            "redirector": self.redirector,
        }


class _Registry(metaclass=ABCMeta):
    """Shared machinery for the backend and redirector registries."""

    name: ClassVar[str] = ""
    """The name used in `backend=` / log output. Subclasses without one are abstract."""
    platforms: ClassVar[tuple[str, ...]] = ()
    """`sys.platform` prefixes this implementation supports. Empty means "any"."""

    _registry: ClassVar[dict[str, Any]]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if cls.name:
            cls._registry[cls.name] = cls

    @classmethod
    def supported(cls) -> bool:
        """Whether this implementation can run on the current platform."""
        return not cls.platforms or sys.platform.startswith(cls.platforms)

    @classmethod
    def available(cls) -> bool:
        """Whether this implementation can run *right now*, tooling included."""
        return cls.supported()


class HotspotBackend(_Registry, metaclass=ABCMeta):
    """Creates and tears down an access point."""

    _registry: ClassVar[dict[str, Any]] = {}

    def __init__(
        self,
        config: HotspotConfig,
        redirect_port: int,
        runner: CommandRunner = run,
    ) -> None:
        self.config = config
        self.redirect_port = redirect_port
        self.run = runner
        self.redirector: TrafficRedirector | None = None

    @abstractmethod
    async def start(self) -> HotspotStatus:
        """
        Bring up the access point and, unless disabled, the traffic redirection.

        Implementations must clean up after themselves if they fail halfway
        through, so that a failed `start()` leaves the system unchanged.
        """

    @abstractmethod
    async def stop(self) -> None:
        """
        Tear the access point and the traffic redirection down again.

        Implementations must be forgiving: `stop()` runs during shutdown and
        should undo as much as it can rather than bail out on the first error.
        """

    async def start_redirector(self, status: HotspotStatus) -> None:
        """Start the platform's redirector for `status` and record it on `status`."""
        if not self.config.redirect:
            logger.warning(
                f"Hotspot {status.ssid!r} is running without traffic redirection. "
                f"Configure clients to use {status.address or 'this machine'}:{self.redirect_port} as an HTTP proxy."
            )
            return
        self.redirector = create_redirector(
            interface=status.interface,
            gateway=status.address,
            port=self.redirect_port,
            block_quic=self.config.block_quic,
            runner=self.run,
        )
        try:
            await self.redirector.start()
        except HotspotError as e:
            # by far the most common cause is a missing sudo, so say so.
            raise HotspotError(
                f"Failed to redirect hotspot traffic: {e}\n"
                f"Installing the redirection rules requires root (administrator on "
                f"Windows) privileges. Pass `--mode hotspot:redirect=off` to run the "
                f"access point without intercepting its traffic."
            ) from e
        status.redirector = self.redirector.name

    async def stop_redirector(self) -> None:
        """Stop the redirector started by `start_redirector`, if any."""
        if self.redirector is not None:
            redirector, self.redirector = self.redirector, None
            await redirector.stop()


class TrafficRedirector(_Registry, metaclass=ABCMeta):
    """Forces the traffic of hotspot clients into mitmproxy's transparent listener."""

    _registry: ClassVar[dict[str, Any]] = {}

    def __init__(
        self,
        interface: str,
        gateway: str | None,
        port: int,
        block_quic: bool = True,
        runner: CommandRunner = run,
    ) -> None:
        self.interface = interface
        self.gateway = gateway
        self.port = port
        self.block_quic = block_quic
        self.run = runner

    @abstractmethod
    async def start(self) -> None:
        """Install the redirection rules."""

    @abstractmethod
    async def stop(self) -> None:
        """Remove the redirection rules again. Must not raise."""


def create_backend(
    config: HotspotConfig,
    redirect_port: int,
    runner: CommandRunner = run,
) -> HotspotBackend:
    """
    Pick the best available backend for `config` and instantiate it.

    Raises `HotspotError` if the requested backend is unusable or if no backend
    works on this machine.
    """
    candidates: list[type[HotspotBackend]] = list(HotspotBackend._registry.values())
    if config.backend:
        for cls in candidates:
            if cls.name == config.backend:
                if not cls.available():
                    raise HotspotError(
                        f"The {cls.name} hotspot backend is not available on this machine."
                    )
                return cls(config, redirect_port, runner)
        raise HotspotError(f"Unknown hotspot backend: {config.backend}")

    for cls in candidates:
        # the manual backend never wins by default, it needs an existing access point.
        if cls.name != "manual" and cls.available():
            return cls(config, redirect_port, runner)

    supported = sorted(c.name for c in candidates if c.supported())
    raise HotspotError(
        f"No usable hotspot backend found on this platform ({sys.platform}). "
        f"Backends for this platform: {', '.join(supported) or 'none'}. "
        f"If you already have an access point, use `--mode hotspot:backend=manual,iface=<interface>`."
    )


def create_redirector(
    interface: str,
    gateway: str | None,
    port: int,
    block_quic: bool = True,
    runner: CommandRunner = run,
) -> TrafficRedirector:
    """
    Pick the best available redirector for the current platform.

    Raises `HotspotError` if traffic cannot be redirected here.
    """
    candidates: list[type[TrafficRedirector]] = list(
        TrafficRedirector._registry.values()
    )
    for cls in candidates:
        if cls.available():
            return cls(interface, gateway, port, block_quic, runner)
    raise HotspotError(
        f"Cannot redirect hotspot traffic on this platform ({sys.platform}). "
        f"Use `--mode hotspot:redirect=off` to run the access point without interception."
    )
