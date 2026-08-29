import sys

import pytest

from .helpers import config
from .helpers import FakeRunner
from mitmproxy.hotspot import linux
from mitmproxy.hotspot.base import HotspotError


class TestNetworkManager:
    def backend(self, runner, **kwargs):
        return linux.NetworkManagerBackend(config(**kwargs), 8080, runner)

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
        return linux.HostapdBackend(config(**kwargs), 8080, runner)

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
        conf = b.hostapd_conf("wlan0")
        assert "ssid=net" in conf
        assert "wpa_passphrase=hunter22" in conf
        assert "hw_mode=g" in conf

        b = self.backend(FakeRunner(), monkeypatch, band="a", password="")
        conf = b.hostapd_conf("wlan0")
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

        b = linux.HostapdBackend(config(), 8080, FakeRunner())
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
            "wlan0", kwargs.pop("gateway"), 8080, runner=runner, **kwargs
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
        r = linux.IptablesRedirector("wlan0", "10.42.0.1", 8080, runner=runner)
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
            "wlan0", None, 8080, block_quic=False, runner=runner
        )
        await r.start()
        assert not runner.ran("-j RETURN")
        assert not runner.ran("-I FORWARD")
