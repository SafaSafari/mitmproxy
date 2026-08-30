"""Shared test doubles for the `mitmproxy.hotspot` tests."""

from mitmproxy.hotspot.base import CaptureTarget
from mitmproxy.hotspot.base import HotspotConfig
from mitmproxy.hotspot.base import HotspotError


class FakeRunner:
    """A `CommandRunner` that records invocations and replays canned output."""

    def __init__(self, outputs: dict[str, str] | None = None, fail: tuple = ()):
        self.calls: list[tuple[str, ...]] = []
        self.stdins: list[str | None] = []
        self.outputs = outputs or {}
        self.fail = fail

    async def __call__(self, *args, check=True, timeout=60, stdin=None, **kwargs):
        self.calls.append(args)
        self.stdins.append(stdin)
        cmd = " ".join(args)
        for prefix in self.fail:
            if cmd.startswith(prefix):
                if check:
                    raise HotspotError(f"{cmd} failed")
                return ""
        for prefix, out in self.outputs.items():
            if cmd.startswith(prefix):
                return out
        return ""

    def ran(self, *fragments: str) -> bool:
        """Whether some command contains all of `fragments`."""
        for call in self.calls:
            cmd = " ".join(call)
            if all(f in cmd for f in fragments):
                return True
        return False


def config(**kwargs) -> HotspotConfig:
    # tests assert on exact commands, so don't let the environment change them:
    # `sudo` on PATH would add a prefix, and `capture=auto` resolves per platform.
    kwargs.setdefault("sudo", "never")
    kwargs.setdefault("capture", "redirect")
    return HotspotConfig(**kwargs)


def target(port: int | None = 8080, tun: str | None = None) -> CaptureTarget:
    return CaptureTarget(port=None if tun else port, tun=tun)
