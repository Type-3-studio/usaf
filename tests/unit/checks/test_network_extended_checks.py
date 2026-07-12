from __future__ import annotations

from usaf.checks.network.network_extended_checks import (
    AdminPortsExposedCheck,
    EphemeralPortListeningCheck,
    LoopbackCheck,
    NoDNSConfiguredCheck,
    NonStandardSSHPortCheck,
    SingleDNSServerCheck,
    UnusedInterfacesCheck,
    WirelessInterfaceCheck,
)


class TestAdminPortsExposedCheck:
    def test_passes_no_sockets(self):
        check = AdminPortsExposedCheck()
        result = check.evaluate({"sockets": {"tcp": [], "tcp6": []}})
        assert result.passed

    def test_passes_localhost(self):
        check = AdminPortsExposedCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_port": 6443, "local_address": "127.0.0.1", "state": "LISTEN", "protocol": "TCP"}], "tcp6": []}})
        assert result.passed

    def test_fails_exposed(self):
        check = AdminPortsExposedCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_port": 2375, "local_address": "0.0.0.0", "state": "LISTEN", "protocol": "TCP"}], "tcp6": []}})
        assert not result.passed


class TestLoopbackCheck:
    def test_passes_lo_up(self):
        check = LoopbackCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "lo", "state": "up"}]}})
        assert result.passed

    def test_fails_lo_down(self):
        check = LoopbackCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "lo", "state": "down"}]}})
        assert not result.passed

    def test_fails_no_lo(self):
        check = LoopbackCheck()
        result = check.evaluate({"interfaces": {"interfaces": []}})
        assert not result.passed


class TestWirelessInterfaceCheck:
    def test_passes_no_wifi(self):
        check = WirelessInterfaceCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "eth0", "flags": ["UP"]}]}})
        assert result.passed

    def test_fails_wifi(self):
        check = WirelessInterfaceCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "wlan0", "flags": ["UP"]}]}})
        assert not result.passed


class TestEphemeralPortListeningCheck:
    def test_passes_standard_port(self):
        check = EphemeralPortListeningCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_port": 8080, "local_address": "127.0.0.1", "state": "LISTEN", "protocol": "TCP"}], "tcp6": []}})
        assert result.passed

    def test_fails_ephemeral(self):
        check = EphemeralPortListeningCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_port": 60000, "local_address": "0.0.0.0", "state": "LISTEN", "protocol": "TCP"}], "tcp6": []}})
        assert not result.passed


class TestSingleDNSServerCheck:
    def test_passes_multi(self):
        check = SingleDNSServerCheck()
        result = check.evaluate({"dns": {"resolv_conf": {"nameservers": ["8.8.8.8", "8.8.4.4"]}}})
        assert result.passed

    def test_fails_single(self):
        check = SingleDNSServerCheck()
        result = check.evaluate({"dns": {"resolv_conf": {"nameservers": ["8.8.8.8"]}}})
        assert not result.passed


class TestNoDNSConfiguredCheck:
    def test_passes_with_dns(self):
        check = NoDNSConfiguredCheck()
        result = check.evaluate({"dns": {"resolv_conf": {"nameservers": ["8.8.8.8"]}, "resolved_status": {"dns_servers": []}}})
        assert result.passed

    def test_fails_no_dns(self):
        check = NoDNSConfiguredCheck()
        result = check.evaluate({"dns": {"resolv_conf": {"nameservers": []}, "resolved_status": {"dns_servers": []}}})
        assert not result.passed


class TestNonStandardSSHPortCheck:
    def test_passes_no_ssh_exposed(self):
        check = NonStandardSSHPortCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_port": 2222, "local_address": "0.0.0.0", "state": "LISTEN", "protocol": "TCP"}], "tcp6": []}})
        assert result.passed

    def test_fails_ssh_22_exposed(self):
        check = NonStandardSSHPortCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_port": 22, "local_address": "0.0.0.0", "state": "LISTEN", "protocol": "TCP"}], "tcp6": []}})
        assert not result.passed


class TestUnusedInterfacesCheck:
    def test_passes_all_up(self):
        check = UnusedInterfacesCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "eth0", "state": "up"}]}})
        assert result.passed

    def test_fails_down(self):
        check = UnusedInterfacesCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "eth1", "state": "down"}]}})
        assert not result.passed

    def test_skips_lo(self):
        check = UnusedInterfacesCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "lo", "state": "down"}]}})
        assert result.passed
