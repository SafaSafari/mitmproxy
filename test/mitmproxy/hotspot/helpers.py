"""Shared test doubles for the `mitmproxy.hotspot` tests."""

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
    # tests assert on exact commands, so don't let a `sudo` on PATH change them.
    kwargs.setdefault("sudo", "never")
    return HotspotConfig(**kwargs)
