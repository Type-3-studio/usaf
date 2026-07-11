from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

from usaf.checks.services.service_checks import (
    FailedServicesCheck,
    ModifiedSystemdUnitCheck,
    RecentlyInstalledServicesCheck,
    ServicesFromUnknownBinariesCheck,
    ServicesRunningAsRootCheck,
    UnexpectedEnabledServicesCheck,
    UnexpectedListeningServicesCheck,
)
from usaf.models.severity import Confidence, Severity


class TestUnexpectedEnabledServicesCheck:
    """Tests for SVC-102: Unexpected Enabled Services."""

    def test_passes_with_no_services(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({"systemd": {"services": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_known_safe_service(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "ssh.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                }]
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_known_safe_exited(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "cron.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "exited",
                }]
            }
        })
        assert result.passed

    def test_fails_with_unexpected_service(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "myservice.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                }]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "myservice" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM
        assert f.false_positive_probability == 0.3
        assert "T1543.002" in f.mitre_attack_ids

    def test_skips_not_loaded(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "unknown.service",
                    "load": "not-loaded",
                    "active": "active",
                    "sub": "running",
                }]
            }
        })
        assert result.passed

    def test_skips_inactive(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "unknown.service",
                    "load": "loaded",
                    "active": "inactive",
                    "sub": "dead",
                }]
            }
        })
        assert result.passed

    def test_skips_unexpected_substate(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "unknown.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "dead",
                }]
            }
        })
        assert result.passed

    def test_detects_multiple_unexpected(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running"},
                    {"name": "unknown1.service", "load": "loaded", "active": "active", "sub": "running"},
                    {"name": "unknown2.service", "load": "loaded", "active": "active", "sub": "running"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_handles_missing_fields(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({"systemd": {"services": [{"name": "test.service"}]}})
        assert result.passed

    def test_strips_service_suffix(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "cron.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                }]
            }
        })
        assert result.passed

    def test_has_mitre_mapping(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "unknown.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                }]
            }
        })
        assert len(result.findings[0].mitre_attack_ids) > 0

    def test_finding_has_proper_evidence(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "unknown.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                }]
            }
        })
        f = result.findings[0]
        assert f.evidence is not None
        assert "unknown" in str(f.evidence.key)
        assert str(f.evidence.value) == "active/running"

    def test_handles_socket_suffix(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "unknown.socket",
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                }]
            }
        })
        assert not result.passed
        assert "unknown" in result.findings[0].title

    def test_strips_path_suffix(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "unknown.path",
                    "load": "loaded",
                    "active": "active",
                    "sub": "running",
                }]
            }
        })
        assert not result.passed
        assert "unknown" in result.findings[0].title


    def test_exited_known_safe_passes(self):
        check = UnexpectedEnabledServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{
                    "name": "apport.service",
                    "load": "loaded",
                    "active": "active",
                    "sub": "exited",
                }]
            }
        })
        assert result.passed


class TestServicesRunningAsRootCheck:
    """Tests for SVC-201: Services Running as Root."""

    def test_passes_with_no_services(self):
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({"systemd": {"services": []}, "processes": {"processes": []}})
        assert result.passed

    def test_passes_with_expected_root_service(self):
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "sshd.service", "active": "active"}]},
            "processes": {"processes": []},
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_fails_with_unexpected_root_service(self, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/myservice.service", "[Service]\nExecStart=/usr/bin/myservice")
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "active"}]},
            "processes": {
                "processes": [{
                    "pid": 1234, "name": "myservice", "binary": "/usr/bin/myservice",
                    "cmdline": "/usr/bin/myservice --config x", "uid": 0, "state": "S",
                }]
            },
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "myservice" in f.title
        assert f.severity == Severity.MEDIUM
        assert "T1068" in f.mitre_attack_ids
        assert f.evidence is not None

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_passes_with_non_root_service(self, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/myservice.service", "[Service]\nExecStart=/usr/bin/myservice")
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "active"}]},
            "processes": {
                "processes": [{
                    "pid": 1234, "name": "myservice", "binary": "/usr/bin/myservice",
                    "cmdline": "/usr/bin/myservice", "uid": 1000, "state": "S",
                }]
            },
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_skips_inactive_services(self, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/myservice.service", "[Service]\nExecStart=/usr/bin/myservice")
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "inactive"}]},
            "processes": {
                "processes": [{
                    "pid": 1234, "name": "myservice", "binary": "/usr/bin/myservice",
                    "cmdline": "/usr/bin/myservice", "uid": 0, "state": "S",
                }]
            },
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_skips_when_no_unit_file_content(self, mock_read_unit):
        mock_read_unit.return_value = (None, None)
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "active"}]},
            "processes": {
                "processes": [{
                    "pid": 1234, "name": "myservice", "binary": "/usr/bin/myservice",
                    "cmdline": "/usr/bin/myservice", "uid": 0, "state": "S",
                }]
            },
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_skips_when_no_execstart(self, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/myservice.service", "[Service]\nType=simple")
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "active"}]},
            "processes": {
                "processes": [{
                    "pid": 1234, "name": "myservice", "binary": "/usr/bin/myservice",
                    "cmdline": "/usr/bin/myservice", "uid": 0, "state": "S",
                }]
            },
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_skips_when_no_matching_processes(self, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/myservice.service", "[Service]\nExecStart=/usr/bin/myservice")
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "active"}]},
            "processes": {
                "processes": [{
                    "pid": 1234, "name": "other", "binary": "/usr/bin/other",
                    "cmdline": "/usr/bin/other", "uid": 0, "state": "S",
                }]
            },
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_handles_empty_process_list(self, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/myservice.service", "[Service]\nExecStart=/usr/bin/myservice")
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "active"}]},
            "processes": {"processes": []},
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_has_mitre_mapping(self, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/myservice.service", "[Service]\nExecStart=/usr/bin/myservice")
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "active"}]},
            "processes": {
                "processes": [{
                    "pid": 1234, "name": "myservice", "binary": "/usr/bin/myservice",
                    "cmdline": "/usr/bin/myservice", "uid": 0, "state": "S",
                }]
            },
        })
        assert len(result.findings[0].mitre_attack_ids) > 0

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_matches_via_binary_field(self, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/myservice.service", "[Service]\nExecStart=/usr/bin/myservice")
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "active"}]},
            "processes": {
                "processes": [{
                    "pid": 5678, "name": "myservice", "binary": "/usr/bin/myservice",
                    "cmdline": "", "uid": 0, "state": "S",
                }]
            },
        })
        assert not result.passed
        assert len(result.findings) == 1

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_handles_execstart_with_prefix(self, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/myservice.service", "[Service]\nExecStart=-/usr/bin/myservice")
        check = ServicesRunningAsRootCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "myservice.service", "active": "active"}]},
            "processes": {
                "processes": [{
                    "pid": 1234, "name": "myservice", "binary": "/usr/bin/myservice",
                    "cmdline": "/usr/bin/myservice", "uid": 0, "state": "S",
                }]
            },
        })
        assert not result.passed
        assert len(result.findings) == 1


class TestServicesFromUnknownBinariesCheck:
    """Tests for SVC-202: Services From Unknown Binaries."""

    def test_passes_with_no_services(self):
        check = ServicesFromUnknownBinariesCheck()
        result = check.evaluate({"systemd": {"services": []}})
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    @patch("usaf.checks.services.service_checks.get_package_for_file")
    def test_passes_with_package_owned_binary(self, mock_get_pkg, mock_read_unit):
        mock_read_unit.return_value = ("/lib/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd")
        mock_get_pkg.return_value = "openssh-server"
        check = ServicesFromUnknownBinariesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "ssh.service", "active": "active"}]}
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    @patch("usaf.checks.services.service_checks.get_package_for_file")
    def test_fails_with_unowned_binary(self, mock_get_pkg, mock_read_unit):
        mock_read_unit.return_value = ("/etc/systemd/system/custom.service", "[Service]\nExecStart=/usr/local/bin/custom")
        mock_get_pkg.return_value = None
        check = ServicesFromUnknownBinariesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "custom" in f.title or "/usr/local/bin/custom" in f.title
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert f.false_positive_probability == 0.05
        assert "T1543.002" in f.mitre_attack_ids
        assert "T1505" in f.mitre_attack_ids

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_skips_inactive(self, mock_read_unit):
        mock_read_unit.return_value = ("/etc/systemd/system/custom.service", "[Service]\nExecStart=/usr/local/bin/custom")
        check = ServicesFromUnknownBinariesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom.service", "active": "inactive"}]}
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_skips_when_no_unit_file(self, mock_read_unit):
        mock_read_unit.return_value = (None, None)
        check = ServicesFromUnknownBinariesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    def test_skips_when_no_execstart(self, mock_read_unit):
        mock_read_unit.return_value = ("/etc/systemd/system/custom.service", "[Service]\nType=simple")
        check = ServicesFromUnknownBinariesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._read_unit_file")
    @patch("usaf.checks.services.service_checks.get_package_for_file")
    def test_has_mitre_mapping(self, mock_get_pkg, mock_read_unit):
        mock_read_unit.return_value = ("/etc/systemd/system/custom.service", "[Service]\nExecStart=/usr/local/bin/custom")
        mock_get_pkg.return_value = None
        check = ServicesFromUnknownBinariesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
        })
        assert len(result.findings[0].mitre_attack_ids) > 0

    @patch("usaf.checks.services.service_checks._read_unit_file")
    @patch("usaf.checks.services.service_checks.get_package_for_file")
    def test_detects_multiple_unowned(self, mock_get_pkg, mock_read_unit):
        mock_read_unit.return_value = ("/etc/systemd/system/svc.service", "[Service]\nExecStart=/opt/custom/bin")
        mock_get_pkg.return_value = None
        check = ServicesFromUnknownBinariesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "svc1.service", "active": "active"},
                    {"name": "svc2.service", "active": "active"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    @patch("usaf.checks.services.service_checks._read_unit_file")
    @patch("usaf.checks.services.service_checks.get_package_for_file")
    def test_finding_has_file_evidence(self, mock_get_pkg, mock_read_unit):
        mock_read_unit.return_value = ("/etc/systemd/system/custom.service", "[Service]\nExecStart=/usr/local/bin/custom")
        mock_get_pkg.return_value = None
        check = ServicesFromUnknownBinariesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
        })
        f = result.findings[0]
        assert f.evidence is not None
        assert "/usr/local/bin/custom" in str(f.evidence.path)


class TestFailedServicesCheck:
    """Tests for SVC-301: Failed Services."""

    def test_passes_with_no_services(self):
        check = FailedServicesCheck()
        result = check.evaluate({"systemd": {"services": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_healthy(self):
        check = FailedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "ssh.service", "active": "active", "sub": "running", "description": ""},
                ]
            }
        })
        assert result.passed

    def test_fails_with_failed_active(self):
        check = FailedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "fail2ban.service", "active": "failed", "sub": "failed", "description": "Fail2ban"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "fail2ban" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH
        assert f.false_positive_probability == 0.1
        assert "T1489" in f.mitre_attack_ids

    def test_fails_with_failed_sub(self):
        check = FailedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "mysql.service", "active": "active", "sub": "failed", "description": "MySQL"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_detects_multiple_failed(self):
        check = FailedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "svc1.service", "active": "failed", "sub": "failed", "description": ""},
                    {"name": "svc2.service", "active": "failed", "sub": "failed", "description": ""},
                    {"name": "ssh.service", "active": "active", "sub": "running", "description": ""},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_handles_missing_fields(self):
        check = FailedServicesCheck()
        result = check.evaluate({"systemd": {"services": [{"name": "test.service"}]}})
        assert result.passed

    def test_has_mitre_mapping(self):
        check = FailedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "fail.service", "active": "failed", "sub": "failed", "description": ""},
                ]
            }
        })
        assert len(result.findings[0].mitre_attack_ids) > 0

    def test_strips_suffix_in_finding(self):
        check = FailedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "myapp.service", "active": "failed", "sub": "failed", "description": ""},
                ]
            }
        })
        f = result.findings[0]
        assert "myapp" in f.title
        assert ".service" not in f.title.split(":")[1] if ":" in f.title else True


class TestUnexpectedListeningServicesCheck:
    """Tests for SVC-302: Unexpected Listening Services."""

    def test_passes_with_no_sockets(self):
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {"tcp": [], "tcp6": [], "udp": [], "udp6": []},
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_known_safe_port(self):
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 22, "state": "LISTEN"}],
                "tcp6": [], "udp": [], "udp6": [],
            },
        })
        assert result.passed

    def test_passes_with_https(self):
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 443, "state": "LISTEN"}],
                "tcp6": [], "udp": [], "udp6": [],
            },
        })
        assert result.passed

    def test_passes_with_multiple_known_safe(self):
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [
                    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 22, "state": "LISTEN"},
                    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 443, "state": "LISTEN"},
                    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 3306, "state": "LISTEN"},
                ],
                "tcp6": [], "udp": [], "udp6": [],
            },
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._find_pid_by_inode")
    def test_fails_with_unexpected_port(self, mock_find_pid):
        mock_find_pid.return_value = None
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 31337, "state": "LISTEN", "inode": 12345}],
                "tcp6": [], "udp": [], "udp6": [],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "31337" in f.title
        assert f.severity == Severity.MEDIUM
        assert "T1043" in f.mitre_attack_ids

    def test_skips_udp_ports(self):
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [], "tcp6": [],
                "udp": [{"protocol": "UDP", "local_address": "0.0.0.0", "local_port": 31337, "state": "UNCONN"}],
                "udp6": [],
            },
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._find_pid_by_inode")
    def test_detects_multiple_unexpected(self, mock_find_pid):
        mock_find_pid.return_value = None
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [
                    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 2222, "state": "LISTEN", "inode": 111},
                    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 3333, "state": "LISTEN", "inode": 222},
                    {"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 443, "state": "LISTEN", "inode": 333},
                ],
                "tcp6": [], "udp": [], "udp6": [],
            },
        })
        assert not result.passed
        assert len(result.findings) == 2

    @patch("usaf.checks.services.service_checks._find_pid_by_inode")
    def test_detects_unexpected_on_tcp6(self, mock_find_pid):
        mock_find_pid.return_value = None
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [], "tcp6": [
                    {"protocol": "TCP6", "local_address": "::", "local_port": 9999, "state": "LISTEN", "inode": 444},
                ], "udp": [], "udp6": [],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_handles_missing_port_field(self):
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [{"protocol": "TCP"}],
                "tcp6": [], "udp": [], "udp6": [],
            },
        })
        assert result.passed

    def test_handles_no_inode_field(self):
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 4444, "state": "LISTEN"}],
                "tcp6": [], "udp": [], "udp6": [],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1

    @patch.object(UnexpectedListeningServicesCheck, "_match_pid_to_service")
    @patch("usaf.checks.services.service_checks._find_pid_by_inode")
    def test_includes_service_name_when_matched(self, mock_find_pid, mock_match):
        mock_find_pid.return_value = 1234
        mock_match.return_value = "custom-svc"
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom-svc.service", "active": "active"}]},
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 9999, "state": "LISTEN", "inode": 12345}],
                "tcp6": [], "udp": [], "udp6": [],
            },
        })
        assert not result.passed
        f = result.findings[0]
        assert "custom-svc" in f.description
        assert "9999" in f.title

    @patch("usaf.checks.services.service_checks._find_pid_by_inode")
    def test_has_mitre_mapping(self, mock_find_pid):
        mock_find_pid.return_value = None
        check = UnexpectedListeningServicesCheck()
        result = check.evaluate({
            "systemd": {"services": []},
            "sockets": {
                "tcp": [{"protocol": "TCP", "local_address": "0.0.0.0", "local_port": 31338, "state": "LISTEN", "inode": 555}],
                "tcp6": [], "udp": [], "udp6": [],
            },
        })
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestRecentlyInstalledServicesCheck:
    """Tests for SVC-401: Recently Installed Services."""

    def test_passes_with_no_services(self):
        check = RecentlyInstalledServicesCheck()
        result = check.evaluate({"systemd": {"services": []}})
        assert result.passed

    @patch("usaf.checks.services.service_checks._find_unit_file_path")
    def test_passes_with_old_unit_file(self, mock_find_path):
        mock_find_path.return_value = "/lib/systemd/system/ssh.service"
        old_mtime = (datetime.now(UTC) - timedelta(days=30)).timestamp()
        check = RecentlyInstalledServicesCheck()
        with patch.object(Path, "stat", return_value=MagicMock(st_mtime=old_mtime)):
            result = check.evaluate({
                "systemd": {"services": [{"name": "ssh.service", "active": "active"}]}
            })
        assert result.passed

    @patch("usaf.checks.services.service_checks._find_unit_file_path")
    def test_fails_with_recently_modified(self, mock_find_path):
        mock_find_path.return_value = "/etc/systemd/system/custom.service"
        recent_mtime = (datetime.now(UTC) - timedelta(hours=1)).timestamp()
        check = RecentlyInstalledServicesCheck()
        with patch.object(Path, "stat", return_value=MagicMock(st_mtime=recent_mtime)):
            result = check.evaluate({
                "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
            })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "custom" in f.title
        assert f.severity == Severity.MEDIUM
        assert "T1543.002" in f.mitre_attack_ids

    @patch("usaf.checks.services.service_checks._find_unit_file_path")
    def test_skips_inactive(self, mock_find_path):
        mock_find_path.return_value = "/etc/systemd/system/custom.service"
        check = RecentlyInstalledServicesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom.service", "active": "inactive"}]}
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._find_unit_file_path")
    def test_skips_when_no_unit_file(self, mock_find_path):
        mock_find_path.return_value = None
        check = RecentlyInstalledServicesCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
        })
        assert result.passed

    @patch("usaf.checks.services.service_checks._find_unit_file_path")
    def test_handles_stat_oserror(self, mock_find_path):
        mock_find_path.return_value = "/etc/systemd/system/custom.service"
        check = RecentlyInstalledServicesCheck()
        with patch.object(Path, "stat", side_effect=OSError("Permission denied")):
            result = check.evaluate({
                "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
            })
        assert result.passed

    @patch("usaf.checks.services.service_checks._find_unit_file_path")
    def test_has_mitre_mapping(self, mock_find_path):
        mock_find_path.return_value = "/etc/systemd/system/custom.service"
        recent_mtime = (datetime.now(UTC) - timedelta(hours=1)).timestamp()
        check = RecentlyInstalledServicesCheck()
        with patch.object(Path, "stat", return_value=MagicMock(st_mtime=recent_mtime)):
            result = check.evaluate({
                "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
            })
        assert len(result.findings[0].mitre_attack_ids) > 0

    @patch("usaf.checks.services.service_checks._find_unit_file_path")
    def test_finding_has_file_evidence(self, mock_find_path):
        mock_find_path.return_value = "/etc/systemd/system/custom.service"
        recent_mtime = (datetime.now(UTC) - timedelta(hours=1)).timestamp()
        check = RecentlyInstalledServicesCheck()
        with patch.object(Path, "stat", return_value=MagicMock(st_mtime=recent_mtime)):
            result = check.evaluate({
                "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
            })
        f = result.findings[0]
        assert f.evidence is not None
        assert f.evidence.path == "/etc/systemd/system/custom.service"


class TestModifiedSystemdUnitCheck:
    """Tests for SVC-402: Modified Systemd Unit Files."""

    def test_passes_with_no_services(self):
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({"systemd": {"services": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_only_lib_unit(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "ssh.service", "active": "active"}]}
        })
        assert result.passed

    def test_passes_with_no_unit_at_all(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "ghost.service", "active": "active"}]}
        })
        assert result.passed

    def test_fails_with_etc_override(self, monkeypatch):
        def mock_exists(path):
            p = str(path)
            return p in ("/etc/systemd/system/ssh.service", "/lib/systemd/system/ssh.service")
        monkeypatch.setattr(Path, "exists", mock_exists)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "ssh.service", "active": "active"}]}
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "ssh" in f.title
        assert f.severity == Severity.HIGH
        assert "T1543.002" in f.mitre_attack_ids
        assert "T1574" in f.mitre_attack_ids
        assert f.confidence == Confidence.HIGH

    def test_fails_with_custom_unit_in_etc_only(self, monkeypatch):
        def mock_exists(path):
            p = str(path)
            return p == "/etc/systemd/system/custom.service"
        monkeypatch.setattr(Path, "exists", mock_exists)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "custom.service", "active": "active"}]}
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "custom unit" in f.description.lower()

    def test_fails_with_dropin_override(self, monkeypatch):
        def mock_exists(path):
            p = str(path)
            if p == "/etc/systemd/system/ssh.service":
                return False
            if p == "/lib/systemd/system/ssh.service":
                return True
            if p == "/etc/systemd/system/ssh.service.d":
                return True
            return False
        monkeypatch.setattr(Path, "exists", mock_exists)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "ssh.service", "active": "active"}]}
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_run_dropin_override(self, monkeypatch):
        def mock_exists(path):
            p = str(path)
            if p == "/etc/systemd/system/ssh.service":
                return False
            if p == "/lib/systemd/system/ssh.service":
                return True
            if p == "/etc/systemd/system/ssh.service.d":
                return False
            if p == "/run/systemd/system/ssh.service.d":
                return True
            return False
        monkeypatch.setattr(Path, "exists", mock_exists)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "ssh.service", "active": "active"}]}
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_both_override_and_dropin(self, monkeypatch):
        def mock_exists(path):
            p = str(path)
            return p in ("/etc/systemd/system/ssh.service", "/lib/systemd/system/ssh.service", "/etc/systemd/system/ssh.service.d")
        monkeypatch.setattr(Path, "exists", mock_exists)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "ssh.service", "active": "active"}]}
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "modified unit" in f.description.lower()

    def test_skips_duplicate_unit_names(self, monkeypatch):
        def mock_exists(path):
            p = str(path)
            return p in ("/etc/systemd/system/ssh.service", "/lib/systemd/system/ssh.service")
        monkeypatch.setattr(Path, "exists", mock_exists)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "ssh.service", "active": "active"},
                    {"name": "ssh.service", "active": "active"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_handles_missing_active_field(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "test.service"}]}
        })
        assert result.passed

    def test_has_mitre_mapping(self, monkeypatch):
        def mock_exists(path):
            p = str(path)
            return p in ("/etc/systemd/system/ssh.service", "/lib/systemd/system/ssh.service")
        monkeypatch.setattr(Path, "exists", mock_exists)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "ssh.service", "active": "active"}]}
        })
        assert len(result.findings[0].mitre_attack_ids) > 0

    def test_detects_multiple_modified_units(self, monkeypatch):
        def mock_exists(path):
            p = str(path)
            return p in (
                "/etc/systemd/system/svc1.service",
                "/lib/systemd/system/svc1.service",
                "/etc/systemd/system/svc2.service",
                "/lib/systemd/system/svc2.service",
            )
        monkeypatch.setattr(Path, "exists", mock_exists)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "svc1.service", "active": "active"},
                    {"name": "svc2.service", "active": "active"},
                    {"name": "ssh.service", "active": "active"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_override_in_description(self, monkeypatch):
        def mock_exists(path):
            p = str(path)
            if p == "/etc/systemd/system/ssh.service":
                return True
            if p == "/lib/systemd/system/ssh.service":
                return True
            return False
        monkeypatch.setattr(Path, "exists", mock_exists)
        check = ModifiedSystemdUnitCheck()
        result = check.evaluate({
            "systemd": {"services": [{"name": "ssh.service", "active": "active"}]}
        })
        f = result.findings[0]
        assert "modified unit" in f.description
        assert "override in /etc" in f.description
