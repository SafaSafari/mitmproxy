import sys
from pathlib import Path

import pytest

from .helpers import config
from .helpers import FakeRunner
from .helpers import target
from mitmproxy import hotspot
from mitmproxy.hotspot import linux
from mitmproxy.hotspot.base import HotspotError


class TestNetworkManager:
    def backend(self, runner, **kwargs):
        return linux.NetworkManagerBackend(config(**kwargs), target(), runner)

    async def test_start_stop(self, monkeypatch):
        monkeypatch.setattr(linux, "which", lambda *a: True)
        runner = FakeRunner(
            {
                "nmcli -t -f DEVICE,TYPE": "eth0:ethernet\nwlan0:wifi\n",
                "nmcli -t -f IP4.ADDRESS": "IP4.ADDRESS[1]:10.42.0.1/24\n",
            }
        )
        b = self.backend(runner, ssid="net", password="hunter22")
        status = await b.start()

        assert status.interface == "wlan0"
        assert status.address == "10.42.0.1"
        assert status.backend == "nmcli"
        assert status.redirector == "nftables"
        assert status.to_json()["ssid"] == "net"
        assert runner.ran("nmcli connection add", "wlan0", "net")
        assert runner.ran("802-11-wireless.mode ap")
        assert runner.ran("wifi-sec.psk hunter22")
        assert runner.ran("nmcli connection up")
        # the redirection rules point at our listener
        assert any(s and "redirect to :8080" in s for s in runner.stdins)

        await b.stop()
        assert runner.ran("nmcli connection down")
        assert runner.ran("nmcli connection delete")

    async def test_explicit_interface_and_band(self, monkeypatch):
        monkeypatch.setattr(linux, "which", lambda *a: True)
        runner = FakeRunner()
        b = self.backend(runner, interface="wlp2s0", band="a", password="")
        status = await b.start()
        assert status.interface == "wlp2s0"
        assert status.address is None
        assert runner.ran("802-11-wireless.band a")
        assert not runner.ran("wifi-sec.key-mgmt")

    async def test_no_wifi_device(self):
        runner = FakeRunner({"nmcli -t -f DEVICE,TYPE": "eth0:ethernet\n"})
        with pytest.raises(HotspotError, match="does not report any Wi-Fi device"):
            await self.backend(runner).start()

    async def test_rollback_on_failure(self):
        runner = FakeRunner(
            {"nmcli -t -f DEVICE,TYPE": "wlan0:wifi\n"},
            fail=("nmcli connection up",),
        )
        with pytest.raises(HotspotError):
            await self.backend(runner).start()
        assert runner.ran("nmcli connection delete")

    async def test_redirect_disabled(self, caplog):
        runner = FakeRunner({"nmcli -t -f DEVICE,TYPE": "wlan0:wifi\n"})
        b = self.backend(runner, redirect=False)
        status = await b.start()
        assert status.redirector is None
        assert "without traffic redirection" in caplog.text
        await b.stop()

    async def test_rollback_on_redirector_failure(self, monkeypatch):
        monkeypatch.setattr(linux, "which", lambda *a: True)
        runner = FakeRunner(
            {"nmcli -t -f DEVICE,TYPE": "wlan0:wifi\n"}, fail=("nft -f",)
        )
        with pytest.raises(HotspotError):
            await self.backend(runner).start()
        assert runner.ran("nmcli connection delete")


class TestNmcliAvailability:
    def test_available(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        assert linux.NetworkManagerBackend.available()
        monkeypatch.setattr(linux, "which", lambda *a: False)
        assert not linux.NetworkManagerBackend.available()


class TestHostapd:
    def backend(self, runner, monkeypatch, **kwargs):
        monkeypatch.setattr(linux.os, "geteuid", lambda: 0)
        monkeypatch.setattr(linux, "which", lambda *a: True)
        return linux.HostapdBackend(config(**kwargs), target(), runner)

    def test_available(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        assert linux.HostapdBackend.available()

    def test_wireless_interfaces(self, monkeypatch, tmp_path):
        (tmp_path / "wlan0" / "wireless").mkdir(parents=True)
        (tmp_path / "eth0").mkdir()
        monkeypatch.setattr(linux, "Path", lambda _: tmp_path)
        assert linux.wireless_interfaces() == ["wlan0"]

    def test_hostapd_conf(self, monkeypatch):
        b = self.backend(FakeRunner(), monkeypatch, ssid="net", password="hunter22")
        conf = b.hostapd_conf("wlan0", "bg")
        assert "ssid=net" in conf
        assert "wpa_passphrase=hunter22" in conf
        assert "hw_mode=g" in conf

        b = self.backend(FakeRunner(), monkeypatch, password="")
        conf = b.hostapd_conf("wlan0", "a")
        assert "hw_mode=a" in conf
        assert "channel=36" in conf
        assert "wpa" not in conf

    def test_dnsmasq_conf(self, monkeypatch):
        conf = self.backend(FakeRunner(), monkeypatch).dnsmasq_conf("wlan0")
        assert "dhcp-range=10.42.42.10,10.42.42.250,12h" in conf
        assert f"dhcp-option=3,{linux.HOSTAPD_GATEWAY}" in conf

    async def test_start_stop(self, monkeypatch):
        runner = FakeRunner(
            {"ip -4 route show default": "default via 1.2.3.4 dev eth0"}
        )
        b = self.backend(runner, monkeypatch, interface="wlan0", password="hunter22")
        status = await b.start()

        assert status.address == linux.HOSTAPD_GATEWAY
        assert status.interface == "wlan0"
        assert runner.ran("ip addr add 10.42.42.1/24 dev wlan0")
        assert runner.ran("hostapd -B")
        assert runner.ran("dnsmasq")
        assert runner.ran("sysctl -w net.ipv4.ip_forward=1")
        assert any(s and "masquerade" in s for s in runner.stdins)
        assert b.rundir is not None and b.rundir.exists()

        rundir = b.rundir
        await b.stop()
        assert not rundir.exists()
        assert runner.ran("ip addr del 10.42.42.1/24 dev wlan0")

    async def test_no_wireless_interface(self, monkeypatch):
        monkeypatch.setattr(linux, "wireless_interfaces", lambda: [])
        with pytest.raises(HotspotError, match="No wireless interface"):
            await self.backend(FakeRunner(), monkeypatch).start()

    async def test_autodetect_interface(self, monkeypatch):
        monkeypatch.setattr(linux, "wireless_interfaces", lambda: ["wlan1"])
        b = self.backend(FakeRunner(), monkeypatch)
        assert await b.wifi_interface() == "wlan1"

    async def test_explicit_uplink(self, monkeypatch):
        b = self.backend(FakeRunner(), monkeypatch, share="eth5")
        assert await b.default_route_interface() == "eth5"

    async def test_no_default_route(self, monkeypatch):
        b = self.backend(FakeRunner(), monkeypatch, interface="wlan0")
        await b.start()
        assert b.uplink is None
        assert not any(s and "masquerade" in s for s in b.run.stdins)
        await b.stop()

    async def test_cleanup_on_failure(self, monkeypatch):
        runner = FakeRunner(fail=("hostapd",))
        b = self.backend(runner, monkeypatch, interface="wlan0")
        with pytest.raises(HotspotError):
            await b.start()
        assert b.rundir is None

    async def test_cleanup_on_redirector_failure(self, monkeypatch):
        runner = FakeRunner(fail=("nft -f",))
        b = self.backend(runner, monkeypatch, interface="wlan0")
        with pytest.raises(HotspotError):
            await b.start()
        assert b.rundir is None

    async def test_nat_with_iptables(self, monkeypatch):
        runner = FakeRunner()
        b = self.backend(runner, monkeypatch, interface="wlan0")
        monkeypatch.setattr(linux, "which", lambda *a: "nft" not in a)
        await b.enable_nat("eth0")
        assert runner.ran("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
        await b.disable_nat("eth0")
        assert runner.ran("iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE")

    def test_terminate(self, monkeypatch, tmp_path):
        killed = []
        monkeypatch.setattr(linux.os, "kill", lambda pid, sig: killed.append(pid))

        b = linux.HostapdBackend(config(), target(), FakeRunner())
        b.terminate(tmp_path / "missing.pid")  # no pidfile: nothing to do
        (tmp_path / "bad.pid").write_text("not-a-pid")
        b.terminate(tmp_path / "bad.pid")
        assert killed == []

        (tmp_path / "good.pid").write_text("4242\n")
        b.terminate(tmp_path / "good.pid")
        assert killed == [4242]


class TestNftablesRedirector:
    def redirector(self, runner, **kwargs):
        kwargs.setdefault("gateway", "10.42.0.1")
        return linux.NftablesRedirector(
            "wlan0", kwargs.pop("gateway"), target(), runner=runner, **kwargs
        )

    def test_ruleset(self):
        rules = self.redirector(FakeRunner()).ruleset("ip")
        assert 'iifname "wlan0" ip daddr 10.42.0.1 return' in rules
        assert "redirect to :8080" in rules
        assert "udp dport 443 drop" in rules
        # the gateway exemption is IPv4-only
        assert "daddr" not in self.redirector(FakeRunner()).ruleset("ip6")

    def test_no_quic_block(self):
        rules = self.redirector(FakeRunner(), block_quic=False).ruleset("ip")
        assert "udp dport 443" not in rules

    def test_no_gateway(self):
        assert "return" not in self.redirector(FakeRunner(), gateway=None).ruleset("ip")

    async def test_start_stop(self):
        runner = FakeRunner()
        r = self.redirector(runner)
        await r.start()
        assert len([c for c in runner.calls if c[:2] == ("nft", "-f")]) == 2
        await r.stop()
        assert runner.ran("nft delete table ip mitmproxy_hotspot")
        assert runner.ran("nft delete table ip6 mitmproxy_hotspot")


class TestIptablesRedirector:
    def test_available(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        assert linux.IptablesRedirector.available()

    async def test_start_stop(self):
        runner = FakeRunner()
        r = linux.IptablesRedirector("wlan0", "10.42.0.1", target(), runner=runner)
        await r.start()
        assert runner.ran("-N mitmproxy_hotspot")
        assert runner.ran("-d 10.42.0.1 -j RETURN")
        assert runner.ran("REDIRECT --to-port 8080")
        assert runner.ran("-I PREROUTING 1 -i wlan0")
        assert runner.ran("-I FORWARD 1 -i wlan0 -p udp --dport 443 -j DROP")
        await r.stop()
        assert runner.ran("-X mitmproxy_hotspot")

    async def test_no_gateway_no_quic(self):
        runner = FakeRunner()
        r = linux.IptablesRedirector(
            "wlan0", None, target(), block_quic=False, runner=runner
        )
        await r.start()
        assert not runner.ran("-j RETURN")
        assert not runner.ran("-I FORWARD")


class TestTunRouter:
    def router(self, runner, interface="wlan0", tun="tun0"):
        return linux.TunRouter(interface, None, target(tun=tun), runner=runner)

    def test_available(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        assert linux.TunRouter.available()
        monkeypatch.setattr(linux, "which", lambda *a: False)
        assert not linux.TunRouter.available()

    def test_captures_tun(self):
        assert linux.TunRouter.capture == "tun"

    async def test_start(self):
        runner = FakeRunner()
        await self.router(runner).start()
        assert runner.ran("sysctl -w net.ipv4.ip_forward=1")
        assert runner.ran("ip link set dev tun0 up")
        assert runner.ran("ip route add default dev tun0 table 8420")
        assert runner.ran("ip rule add iif wlan0 lookup 8420 priority 8420")
        assert runner.ran("ip -6 route add default dev tun0 table 8420")

    async def test_start_is_idempotent(self):
        """`ip rule add` stacks, so a start must clear a stale rule first."""
        runner = FakeRunner()
        await self.router(runner).start()
        commands = [" ".join(c) for c in runner.calls]
        first_del = next(i for i, c in enumerate(commands) if "rule del" in c)
        first_add = next(i for i, c in enumerate(commands) if "rule add" in c)
        assert first_del < first_add

    async def test_stop(self):
        runner = FakeRunner()
        await self.router(runner).stop()
        assert runner.ran("ip rule del iif wlan0 lookup 8420 priority 8420")
        assert runner.ran("ip route flush table 8420")
        assert runner.ran("ip -6 rule del iif wlan0")
        assert runner.ran("ip -6 route flush table 8420")

    async def test_selected_for_tun_targets(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        r = hotspot.create_redirector("wlan0", None, target(tun="tun0"))
        assert isinstance(r, linux.TunRouter)


class TestTunProvisioning:
    """An unprivileged mitmproxy cannot create a tun device, but sudo can do it for us."""

    async def test_skipped_when_root(self, monkeypatch):
        monkeypatch.setattr(linux, "is_root", lambda: True)
        runner = FakeRunner()
        assert await linux.provision_tun_device(None, "auto", runner) == (None, False)
        assert runner.calls == []

    async def test_skipped_without_sudo(self, monkeypatch):
        monkeypatch.setattr(linux, "is_root", lambda: False)
        monkeypatch.setattr(linux, "will_elevate", lambda mode: False)
        runner = FakeRunner()
        assert await linux.provision_tun_device("tun9", "never", runner) == (
            "tun9",
            False,
        )
        assert runner.calls == []

    async def test_skipped_without_ip(self, monkeypatch):
        monkeypatch.setattr(linux, "is_root", lambda: False)
        monkeypatch.setattr(linux, "will_elevate", lambda mode: True)
        monkeypatch.setattr(linux, "which", lambda *a: False)
        runner = FakeRunner()
        assert await linux.provision_tun_device(None, "auto", runner) == (None, False)
        assert runner.calls == []

    async def test_creates_device_owned_by_us(self, monkeypatch):
        monkeypatch.setattr(linux, "is_root", lambda: False)
        monkeypatch.setattr(linux, "which", lambda *a: True)
        monkeypatch.setattr(linux.os, "geteuid", lambda: 1234)
        runner = FakeRunner()

        name, created = await linux.provision_tun_device(None, "always", runner)
        assert (name, created) == (linux.DEFAULT_TUN_NAME, True)
        assert runner.ran(
            f"sudo -n ip tuntap add dev {linux.DEFAULT_TUN_NAME} mode tun user 1234"
        )

    async def test_honours_an_explicit_name(self, monkeypatch):
        monkeypatch.setattr(linux, "is_root", lambda: False)
        monkeypatch.setattr(linux, "which", lambda *a: True)
        runner = FakeRunner()
        name, created = await linux.provision_tun_device("mitm7", "always", runner)
        assert (name, created) == ("mitm7", True)
        assert runner.ran("ip tuntap add dev mitm7")

    async def test_reuses_a_leftover_device(self, monkeypatch):
        """A device left behind by a crash is fine to attach to, but not ours to delete."""
        monkeypatch.setattr(linux, "is_root", lambda: False)
        monkeypatch.setattr(linux, "which", lambda *a: True)

        async def exists(*args, **kwargs):
            raise HotspotError("ioctl(TUNSETIFF): File exists")

        assert await linux.provision_tun_device(None, "always", exists) == (
            linux.DEFAULT_TUN_NAME,
            False,
        )

    async def test_other_errors_propagate(self, monkeypatch):
        monkeypatch.setattr(linux, "is_root", lambda: False)
        monkeypatch.setattr(linux, "which", lambda *a: True)

        async def boom(*args, **kwargs):
            raise HotspotError("sudo: a password is required")

        # `elevate` turns this into its own actionable message; either way it must
        # not be swallowed the way a pre-existing device is.
        with pytest.raises(HotspotError, match="NOPASSWD"):
            await linux.provision_tun_device(None, "always", boom)

    async def test_release(self):
        runner = FakeRunner()
        await linux.release_tun_device("mitm7", "always", runner)
        assert runner.ran("sudo -n ip tuntap del dev mitm7 mode tun")


class TestBandFallback:
    """5 GHz is worth trying first, but not every adapter can host an AP there."""

    async def test_nmcli_prefers_5ghz(self, monkeypatch):
        monkeypatch.setattr(linux, "which", lambda *a: True)
        runner = FakeRunner({"nmcli -t -f DEVICE,TYPE": "wlan0:wifi\n"})
        b = linux.NetworkManagerBackend(config(), target(), runner)
        status = await b.start()
        assert status.band == "a"
        assert runner.ran("802-11-wireless.band a")
        assert not runner.ran("802-11-wireless.band bg")

    async def test_nmcli_falls_back_to_24ghz(self, monkeypatch, caplog):
        caplog.set_level("INFO")
        monkeypatch.setattr(linux, "which", lambda *a: True)
        calls = {"n": 0}
        base = FakeRunner({"nmcli -t -f DEVICE,TYPE": "wlan0:wifi\n"})

        async def runner(*args, **kwargs):
            if " ".join(args).startswith("nmcli connection up"):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise HotspotError("802-11-wireless.band: band a is not supported")
            return await base(*args, **kwargs)

        b = linux.NetworkManagerBackend(config(), target(), runner)
        status = await b.start()
        assert status.band == "bg"
        assert base.ran("802-11-wireless.band a")
        assert base.ran("802-11-wireless.band bg")
        assert "falling back to 2.4 GHz" in caplog.text

    async def test_nmcli_pinned_band_does_not_fall_back(self, monkeypatch):
        monkeypatch.setattr(linux, "which", lambda *a: True)
        runner = FakeRunner(
            {"nmcli -t -f DEVICE,TYPE": "wlan0:wifi\n"}, fail=("nmcli connection up",)
        )
        b = linux.NetworkManagerBackend(config(band="a"), target(), runner)
        with pytest.raises(HotspotError):
            await b.start()
        assert not runner.ran("802-11-wireless.band bg")

    async def test_hostapd_prefers_5ghz(self, monkeypatch):
        monkeypatch.setattr(linux.os, "geteuid", lambda: 0)
        monkeypatch.setattr(linux, "which", lambda *a: True)
        runner = FakeRunner()
        b = linux.HostapdBackend(config(interface="wlan0"), target(), runner)
        status = await b.start()
        assert status.band == "a"

    async def test_hostapd_falls_back_to_24ghz(self, monkeypatch, caplog):
        caplog.set_level("INFO")
        monkeypatch.setattr(linux.os, "geteuid", lambda: 0)
        monkeypatch.setattr(linux, "which", lambda *a: True)
        configs = []
        calls = {"n": 0}
        base = FakeRunner()

        async def runner(*args, **kwargs):
            if args[0] == "hostapd":
                configs.append(Path(args[-1]).read_text())
                calls["n"] += 1
                if calls["n"] == 1:
                    raise HotspotError("Could not set channel for kernel driver")
            return await base(*args, **kwargs)

        b = linux.HostapdBackend(config(interface="wlan0"), target(), runner)
        status = await b.start()
        assert status.band == "bg"
        assert "hw_mode=a" in configs[0]
        assert "hw_mode=g" in configs[1]
        assert "falling back to 2.4 GHz" in caplog.text
