# Wi-Fi hotspot support for mitmproxy's `hotspot` proxy mode.
#
# Importing this package registers every backend and redirector -- that is what
# the otherwise unused platform imports below are for. `create_backend` and
# `create_redirector` then pick the first implementation that reports itself as
# available on the current machine, in the order the classes are defined in
# their module, so `nmcli` wins over `hostapd` and nftables wins over iptables.
#
# See `mitmproxy.hotspot.base` for the interfaces the platform modules implement.
#
# (This file deliberately has no docstring and no logic: that keeps it out of
# the per-file coverage check, see test/individual_coverage.py.)

from mitmproxy.hotspot import linux as linux  # noqa: F401
from mitmproxy.hotspot import macos as macos  # noqa: F401
from mitmproxy.hotspot import manual as manual  # noqa: F401
from mitmproxy.hotspot import windows as windows  # noqa: F401
from mitmproxy.hotspot.base import BACKEND_NAMES
from mitmproxy.hotspot.base import create_backend
from mitmproxy.hotspot.base import create_redirector
from mitmproxy.hotspot.base import HotspotBackend
from mitmproxy.hotspot.base import HotspotConfig
from mitmproxy.hotspot.base import HotspotError
from mitmproxy.hotspot.base import HotspotStatus
from mitmproxy.hotspot.base import TrafficRedirector

__all__ = [
    "BACKEND_NAMES",
    "HotspotBackend",
    "HotspotConfig",
    "HotspotError",
    "HotspotStatus",
    "TrafficRedirector",
    "create_backend",
    "create_redirector",
]
