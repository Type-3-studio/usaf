from __future__ import annotations

from usaf.checks.network.port_checks import PromiscuousModeCheck, UnexpectedListeningPortsCheck
from usaf.models.severity import Severity


class TestUnexpectedListeningPortsCheck:
    def test_passes_when_no_sockets(self):
        check = UnexpectedListeningPortsCheck()
        result = check.evaluate({"sockets": {"tcp": [], "tcp6": [], "udp": [], "udp6": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_known_safe_port(self):
        check = UnexpectedListeningPortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 443, "state": "LISTEN"}],
                "tcp6": [], "udp": [], "udp6": [],
            }
        })
        assert result.passed

    def test_passes_with_localhost_only(self):
        check = UnexpectedListeningPortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "127.0.0.1", "local_port": 9999, "state": "LISTEN"}],
                "tcp6": [], "udp": [], "udp6": [],
            }
        })
        assert result.passed

    def test_passes_with_port_below_1024(self):
        check = UnexpectedListeningPortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 631, "state": "LISTEN"}],
                "tcp6": [], "udp": [], "udp6": [],
            }
        })
        assert result.passed

    def test_fails_with_unexpected_port(self):
        check = UnexpectedListeningPortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 31337, "state": "LISTEN"}],
                "tcp6": [], "udp": [], "udp6": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.MEDIUM
        assert "31337" in f.title

    def test_finds_all_unexpected_ports(self):
        check = UnexpectedListeningPortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [
                    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 2222, "state": "LISTEN"},
                    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 3333, "state": "LISTEN"},
                    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 443, "state": "LISTEN"},
                ],
                "tcp6": [], "udp": [], "udp6": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_handles_missing_fields(self):
        check = UnexpectedListeningPortsCheck()
        result = check.evaluate({
            "sockets": {
                "tcp": [{}],
                "tcp6": [], "udp": [], "udp6": [],
            }
        })
        assert result.passed


class TestPromiscuousModeCheck:
    def test_passes_when_no_interfaces(self):
        check = PromiscuousModeCheck()
        result = check.evaluate({"interfaces": {"interfaces": []}})
        assert result.passed

    def test_passes_when_not_promiscuous(self):
        check = PromiscuousModeCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "promisc": False}]}
        })
        assert result.passed

    def test_fails_when_promiscuous(self):
        check = PromiscuousModeCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "promisc": True, "mac": "00:11:22:33:44:55"}]}
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.MEDIUM
        assert "eth0" in f.title

    def test_has_mitre_mapping(self):
        check = PromiscuousModeCheck()
        result = check.evaluate({
            "interfaces": {"interfaces": [{"name": "eth0", "promisc": True, "mac": "00:11:22:33:44:55"}]}
        })
        assert len(result.findings[0].mitre_attack_ids) > 0
