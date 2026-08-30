import sys

import pytest

from .helpers import config
from .helpers import FakeRunner
from .helpers import target
from mitmproxy import hotspot
from mitmproxy.hotspot import base
from mitmproxy.hotspot import linux
from mitmproxy.hotspot.base import HotspotConfig
from mitmproxy.hotspot.base import HotspotError


class TestRun:
    async def test_stdout(self):
        out = await base.run(sys.executable, "-c", "print('hello')")
        assert out.strip() == "hello"

    async def test_stdin(self):
        out = await base.run(
            sys.executable,
            "-c",
            "import sys; sys.stdout.write(sys.stdin.read())",
            stdin="ping",
        )
        assert out == "ping"

    async def test_capture_stderr(self):
        out = await base.run(
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('Token : 42')",
            capture_stderr=True,
        )
        assert "Token : 42" in out

    async def test_check(self):
        with pytest.raises(HotspotError, match="exit code 3"):
            await base.run(sys.executable, "-c", "raise SystemExit(3)")
        assert (
            await base.run(sys.executable, "-c", "raise SystemExit(3)", check=False)
            == ""
        )

    async def test_not_found(self):
        with pytest.raises(HotspotError, match="Failed to run"):
            await base.run("./mitmproxy-does-not-exist")

    async def test_timeout(self):
        with pytest.raises(HotspotError, match="Timed out"):
            await base.run(
                sys.executable, "-c", "import time; time.sleep(10)", timeout=0.2
            )


def test_which():
    assert not base.which("mitmproxy-does-not-exist")


class TestConfig:
    def test_defaults(self):
        assert HotspotConfig.parse("") == HotspotConfig()
        assert HotspotConfig.parse("   ") == HotspotConfig()

    def test_ssid_shorthand(self):
        assert HotspotConfig.parse("my-network").ssid == "my-network"

    def test_pairs(self):
        c = HotspotConfig.parse(
            "ssid=net,pass=hunter22,iface=wlan0,uplink=eth0,gw=10.0.0.1,band=a"
        )
        assert c.ssid == "net"
        assert c.password == "hunter22"
        assert c.interface == "wlan0"
        assert c.share == "eth0"
        assert c.gateway == "10.0.0.1"
        assert c.band == "a"
        assert HotspotConfig.parse("sudo=always").sudo == "always"

    def test_comma_in_value(self):
        # `network` is not an option name, so it stays part of the SSID.
        assert HotspotConfig.parse("ssid=my,network,band=bg").ssid == "my,network"

    def test_booleans(self):
        assert HotspotConfig.parse("quic=allow").block_quic is False
        assert HotspotConfig.parse("quic=block").block_quic is True
        assert HotspotConfig.parse("redirect=off").redirect is False
        assert HotspotConfig.parse("redirect=1").redirect is True

    def test_empty_value(self):
        assert HotspotConfig.parse("password=").password is None

    @pytest.mark.parametrize(
        "spec,error",
        [
            ("nope=1", "invalid hotspot option"),
            ("quic=maybe", "invalid value"),
            ("password=short", "8 and 63"),
            ("ssid=" + "x" * 33, "1 and 32 bytes"),
            ("band=ac", "bg"),
            ("capture=magic", "capture must be one of"),
            ("sudo=maybe", "sudo must be one of"),
            ("backend=carrier-pigeon", "unknown backend"),
            ("backend=manual", "requires an interface"),
        ],
    )
    def test_invalid(self, spec, error):
        with pytest.raises(ValueError, match=error):
            HotspotConfig.parse(spec)

    def test_open_network(self):
        assert HotspotConfig.parse("ssid=open,password=").validated().password is None


class TestRegistry:
    def test_backend_names(self):
        assert set(base.HotspotBackend._registry) == set(base.BACKEND_NAMES)

    def test_explicit_backend(self, monkeypatch):
        monkeypatch.setattr(linux, "which", lambda *a: True)
        monkeypatch.setattr(sys, "platform", "linux")
        b = hotspot.create_backend(config(backend="nmcli"), target())
        assert isinstance(b, linux.NetworkManagerBackend)

    def test_explicit_backend_unavailable(self, monkeypatch):
        monkeypatch.setattr(linux, "which", lambda *a: False)
        with pytest.raises(HotspotError, match="not available"):
            hotspot.create_backend(config(backend="nmcli"), target())

    def test_unknown_backend(self):
        # HotspotConfig rejects these, but the registry guards against it as well.
        with pytest.raises(HotspotError, match="Unknown hotspot backend"):
            hotspot.create_backend(HotspotConfig(backend="nope"), target())

    def test_autodetect_prefers_nmcli(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        assert isinstance(
            hotspot.create_backend(config(), target()), linux.NetworkManagerBackend
        )

    def test_autodetect_falls_back_to_hostapd(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: "nmcli" not in a)
        assert isinstance(
            hotspot.create_backend(config(), target()), linux.HostapdBackend
        )

    def test_autodetect_nothing_available(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: False)
        with pytest.raises(HotspotError, match="No usable hotspot backend"):
            hotspot.create_backend(config(), target())

    def test_redirector_autodetect(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: "nft" not in a)
        assert isinstance(
            hotspot.create_redirector("wlan0", None, target()), linux.IptablesRedirector
        )

    def test_no_redirector(self, monkeypatch):
        monkeypatch.setattr(base.TrafficRedirector, "_registry", {})
        with pytest.raises(HotspotError, match="Cannot send hotspot traffic"):
            hotspot.create_redirector("wlan0", None, target())


@pytest.fixture
def fake_stack(monkeypatch):
    """
    A backend and redirector that only record what they were asked to do.

    The registries are swapped out before the classes are defined, so the fakes
    register into a throwaway dict that monkeypatch discards afterwards.
    """
    monkeypatch.setattr(base.HotspotBackend, "_registry", {})
    monkeypatch.setattr(base.TrafficRedirector, "_registry", {})
    log: list[str] = []

    class FakeRedirector(base.TrafficRedirector):
        name = "fake-redirector"

        async def start(self) -> None:
            log.append(f"start {self.interface} {self.gateway} {self.port}")

        async def stop(self) -> None:
            log.append("stop")

    class FakeBackend(base.HotspotBackend):
        name = "fake-backend"

        async def start(self) -> base.HotspotStatus:
            status = base.HotspotStatus(
                backend=self.name,
                ssid=self.config.ssid,
                password=self.config.password,
                interface="wlan0",
                address="10.0.0.1",
            )
            await self.start_redirector(status)
            return status

        async def stop(self) -> None:
            await self.stop_redirector()

    return FakeBackend, FakeRedirector, log


class TestBackendLifecycle:
    def test_default_availability(self, fake_stack):
        backend_cls, _, _ = fake_stack
        # neither declares a platform, so both are available anywhere.
        assert backend_cls.available()

    async def test_redirector_is_wired_up(self, fake_stack):
        backend_cls, redirector_cls, log = fake_stack
        b = backend_cls(config(ssid="net"), target(), FakeRunner())

        status = await b.start()
        assert status.redirector == "fake-redirector"
        assert log == ["start wlan0 10.0.0.1 8080"]
        assert status.to_json() == {
            "backend": "fake-backend",
            "ssid": "net",
            "password": "mitmproxy",
            "interface": "wlan0",
            "address": "10.0.0.1",
            "capture": "redirect",
            "redirector": "fake-redirector",
        }

        await b.stop()
        assert log[-1] == "stop"
        # stopping twice must not stop the redirector twice.
        await b.stop()
        assert log.count("stop") == 1

    async def test_redirect_disabled(self, fake_stack, caplog):
        backend_cls, redirector_cls, log = fake_stack
        b = backend_cls(config(redirect=False), target(), FakeRunner())
        status = await b.start()
        assert status.redirector is None
        assert log == []
        assert "10.0.0.1:8080 as an HTTP proxy" in caplog.text

    async def test_redirector_failure_is_explained(self, fake_stack, monkeypatch):
        backend_cls, redirector_cls, log = fake_stack

        async def boom(self):
            raise HotspotError("nft: Operation not permitted")

        monkeypatch.setattr(redirector_cls, "start", boom)
        b = backend_cls(config(), target(), FakeRunner())
        with pytest.raises(HotspotError, match="requires root") as e:
            await b.start()
        assert "Operation not permitted" in str(e.value)


class TestElevate:
    def test_is_root(self, monkeypatch):
        monkeypatch.setattr(base.os, "geteuid", lambda: 0)
        assert base.is_root()
        monkeypatch.setattr(base.os, "geteuid", lambda: 1000)
        assert not base.is_root()

    def test_is_root_without_geteuid(self, monkeypatch):
        # Windows has no geteuid; nothing to elevate there.
        monkeypatch.delattr(base.os, "geteuid", raising=False)
        assert not base.is_root()

    @pytest.mark.parametrize(
        "root,sudo_installed,mode,expected",
        [
            (False, True, "auto", True),
            (False, False, "auto", False),  # no sudo binary: nothing we can do
            (True, True, "auto", False),  # already root
            (True, True, "never", False),
            (True, True, "always", True),
            (False, False, "always", True),
        ],
    )
    def test_will_elevate(self, monkeypatch, root, sudo_installed, mode, expected):
        monkeypatch.setattr(base, "is_root", lambda: root)
        monkeypatch.setattr(base, "which", lambda *a: sudo_installed)
        assert base.will_elevate(mode) is expected

    def test_runner_is_untouched_when_not_needed(self):
        runner = FakeRunner()
        assert base.elevate(runner, "never") is runner

    async def test_prefixes_sudo(self):
        runner = FakeRunner()
        elevated = base.elevate(runner, "always")
        await elevated("nft", "-f", "-", stdin="ruleset")
        assert runner.calls == [("sudo", "-n", "nft", "-f", "-")]
        assert runner.stdins == ["ruleset"]

    async def test_explains_missing_nopasswd(self):
        async def needs_password(*args, **kwargs):
            raise HotspotError("sudo: a password is required")

        with pytest.raises(HotspotError, match="NOPASSWD") as e:
            await base.elevate(needs_password, "always")("nft", "-f", "-")
        assert "hotspot:sudo=never" in str(e.value)

    async def test_other_errors_pass_through(self):
        async def boom(*args, **kwargs):
            raise HotspotError("nft: no such table")

        with pytest.raises(HotspotError, match="no such table"):
            await base.elevate(boom, "always")("nft", "delete", "table")

    async def test_redirector_gets_the_elevated_runner(self, fake_stack):
        backend_cls, _, log = fake_stack
        b = backend_cls(config(sudo="always"), target(), FakeRunner())
        assert b.run_elevated is not b.run
        await b.start()
        assert log  # redirector ran, and it ran through the elevated runner

    async def test_privilege_hint_is_not_duplicated(self, fake_stack, monkeypatch):
        backend_cls, redirector_cls, log = fake_stack

        async def boom(self):
            raise HotspotError("`nft` needs root privileges, add a NOPASSWD rule")

        monkeypatch.setattr(redirector_cls, "start", boom)
        b = backend_cls(config(), target(), FakeRunner())
        with pytest.raises(HotspotError) as e:
            await b.start()
        assert str(e.value).count("root privileges") == 1


class TestCaptureMethod:
    def test_target_kind(self):
        assert base.CaptureTarget(port=8080).kind == "redirect"
        assert base.CaptureTarget(tun="tun0").kind == "tun"

    def test_resolve_explicit(self):
        assert base.resolve_capture("tun") == "tun"
        assert base.resolve_capture("redirect") == "redirect"

    def test_resolve_auto_prefers_tun(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        assert base.resolve_capture("auto") == "tun"

    def test_resolve_auto_falls_back(self, monkeypatch):
        # no tun router registered, e.g. on macOS and Windows.
        monkeypatch.setattr(
            base.TrafficRedirector,
            "_registry",
            {
                k: v
                for k, v in base.TrafficRedirector._registry.items()
                if k != "iproute2"
            },
        )
        assert base.resolve_capture("auto") == "redirect"

    def test_config_capture_method(self, monkeypatch):
        monkeypatch.setattr(base, "resolve_capture", lambda m: "tun")
        assert HotspotConfig().capture_method == "tun"
        # an explicit proxy is the only thing left to point clients at.
        assert HotspotConfig(redirect=False).capture_method == "redirect"

    @pytest.mark.parametrize(
        "capture,block_quic,expected",
        [
            ("redirect", None, True),  # TCP-only capture: QUIC would slip past
            ("tun", None, False),  # tun sees UDP, no need to block anything
            ("tun", True, True),  # explicit wins
            ("redirect", False, False),
        ],
    )
    def test_drop_quic(self, capture, block_quic, expected):
        c = HotspotConfig(capture=capture, block_quic=block_quic)
        assert c.drop_quic is expected

    def test_tun_name(self):
        assert HotspotConfig.parse("tun=mitm0").tun_name == "mitm0"

    async def test_redirector_matches_target_kind(self, monkeypatch):
        """A tun target must not be handed to a packet filter redirector."""
        monkeypatch.setattr(
            base.TrafficRedirector,
            "_registry",
            {
                k: v
                for k, v in base.TrafficRedirector._registry.items()
                if k != "iproute2"
            },
        )
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        with pytest.raises(HotspotError, match="capture=redirect"):
            hotspot.create_redirector("wlan0", None, base.CaptureTarget(tun="tun0"))
