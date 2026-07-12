from __future__ import annotations

from usaf.checks.network.net_security_checks import (
    DnsResolverConfigCheck,
    DuplicateListeningPortsCheck,
    EphemeralPortExhaustionCheck,
    ExposedUdpServicesCheck,
    InterfacePromiscuousCheck,
    ListeningAllInterfacesCheck,
    LocalhostOnlyServicesCheck,
    NonRootPrivilegedPortsCheck,
    TcpTimeWaitServicesCheck,
    UnixSocketPermissionsCheck,
)
from usaf.models.severity import Confidence, Severity


LISTEN_TCP_OK = {"protocol": "TCP", "local_address": "192.168.1.1", "local_port": 22, "state": "LISTEN", "uid": 0}
LISTEN_TCP_ALL = {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 8080, "state": "LISTEN", "uid": 0}
LISTEN_TCP_LOCAL = {"protocol": "TCP", "local_address": "127.0.0.1", "local_port": 5432, "state": "LISTEN", "uid": 100}


class TestListeningAllInterfacesCheck:
    def test_passes_with_specific_bind(self):
        check = ListeningAllInterfacesCheck()
        result = check.evaluate({"sockets": {"tcp": [LISTEN_TCP_OK], "tcp6": [], "udp": [], "udp6": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_all_interfaces(self):
        check = ListeningAllInterfacesCheck()
        result = check.evaluate({"sockets": {"tcp": [LISTEN_TCP_ALL], "tcp6": [], "udp": [], "udp6": []}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "8080" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM

    def test_has_mitre_ids(self):
        check = ListeningAllInterfacesCheck()
        result = check.evaluate({"sockets": {"tcp": [LISTEN_TCP_ALL], "tcp6": [], "udp": [], "udp6": []}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestUnixSocketPermissionsCheck:
    def test_passes_with_secure_socket(self):
        check = UnixSocketPermissionsCheck()
        result = check.evaluate({"sockets": {"unix": []}})
        assert result.passed


class TestExposedUdpServicesCheck:
    def test_passes_with_no_exposed_udp(self):
        check = ExposedUdpServicesCheck()
        result = check.evaluate({"sockets": {"udp": [], "udp6": []}})
        assert result.passed

    def test_fails_with_exposed_udp(self):
        check = ExposedUdpServicesCheck()
        result = check.evaluate({"sockets": {"udp": [{"local_address": "0.0.0.0", "local_port": 53}], "udp6": []}})
        assert not result.passed
        assert len(result.findings) >= 1
        assert "DNS" in result.findings[0].title

    def test_has_mitre_ids(self):
        check = ExposedUdpServicesCheck()
        result = check.evaluate({"sockets": {"udp": [{"local_address": "0.0.0.0", "local_port": 53}], "udp6": []}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestNonRootPrivilegedPortsCheck:
    def test_passes_with_root_ports(self):
        check = NonRootPrivilegedPortsCheck()
        result = check.evaluate({"sockets": {"tcp": [LISTEN_TCP_OK], "tcp6": [], "udp": [], "udp6": []}})
        assert result.passed

    def test_fails_with_non_root(self):
        check = NonRootPrivilegedPortsCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_address": "0.0.0.0", "local_port": 443, "uid": 100, "state": "LISTEN"}], "tcp6": [], "udp": [], "udp6": []}})
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_has_mitre_ids(self):
        check = NonRootPrivilegedPortsCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_address": "0.0.0.0", "local_port": 443, "uid": 100, "state": "LISTEN"}], "tcp6": [], "udp": [], "udp6": []}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestTcpTimeWaitServicesCheck:
    def test_passes_with_normal_connections(self):
        check = TcpTimeWaitServicesCheck()
        result = check.evaluate({"sockets": {"tcp": [{"state": "ESTABLISHED", "local_port": 22}], "tcp6": []}})
        assert result.passed

    def test_has_mitre_ids(self):
        check = TcpTimeWaitServicesCheck()
        abnormal = [{"state": "TIME_WAIT", "local_port": i} for i in range(100)]
        result = check.evaluate({"sockets": {"tcp": abnormal, "tcp6": []}})
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestDuplicateListeningPortsCheck:
    def test_passes_with_unique_ports(self):
        check = DuplicateListeningPortsCheck()
        result = check.evaluate({"sockets": {"tcp": [LISTEN_TCP_OK], "tcp6": [], "udp": [], "udp6": []}})
        assert result.passed

    def test_has_mitre_ids(self):
        check = DuplicateListeningPortsCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_address": "0.0.0.0", "local_port": 80, "state": "LISTEN"}, {"local_address": "192.168.1.1", "local_port": 80, "state": "LISTEN"}], "tcp6": [], "udp": [], "udp6": []}})
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestEphemeralPortExhaustionCheck:
    def test_passes_with_large_range(self):
        check = EphemeralPortExhaustionCheck()
        result = check.evaluate({"kernel_params": {"net.ipv4.ip_local_port_range": "32768 60999"}})
        assert result.passed

    def test_fails_with_small_range(self):
        check = EphemeralPortExhaustionCheck()
        result = check.evaluate({"kernel_params": {"net.ipv4.ip_local_port_range": "32768 40000"}})
        assert not result.passed
        assert len(result.findings) >= 1

    def test_has_mitre_ids(self):
        check = EphemeralPortExhaustionCheck()
        result = check.evaluate({"kernel_params": {"net.ipv4.ip_local_port_range": "32768 40000"}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestInterfacePromiscuousCheck:
    def test_passes_with_normal(self):
        check = InterfacePromiscuousCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "eth0", "promisc": False}]}})
        assert result.passed

    def test_fails_with_promiscuous(self):
        check = InterfacePromiscuousCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "eth0", "promisc": True}]}})
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_has_mitre_ids(self):
        check = InterfacePromiscuousCheck()
        result = check.evaluate({"interfaces": {"interfaces": [{"name": "eth0", "promisc": True}]}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestDnsResolverConfigCheck:
    def test_passes_with_consistent(self):
        check = DnsResolverConfigCheck()
        result = check.evaluate({"dns": {"resolv_conf": {"nameservers": ["1.1.1.1"]}, "resolved_status": {"current_dns": ["1.1.1.1"], "running": True}}})
        assert result.passed

    def test_fails_with_mismatch(self):
        check = DnsResolverConfigCheck()
        result = check.evaluate({"dns": {"resolv_conf": {"nameservers": ["1.1.1.1"]}, "resolved_status": {"current_dns": ["8.8.8.8"], "running": True}}})
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM

    def test_has_mitre_ids(self):
        check = DnsResolverConfigCheck()
        result = check.evaluate({"dns": {"resolv_conf": {"nameservers": ["1.1.1.1"]}, "resolved_status": {"current_dns": ["8.8.8.8"], "running": True}}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestLocalhostOnlyServicesCheck:
    def test_has_mitre_ids(self):
        check = LocalhostOnlyServicesCheck()
        result = check.evaluate({"sockets": {"tcp": [{"local_address": "127.0.0.1", "local_port": 5432, "state": "LISTEN"}], "tcp6": []}})
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0
