from __future__ import annotations

"""Integration tests for individual checks with realistic mock data."""

from usaf.checks.authentication.password_policy import PasswordPolicyCheck
from usaf.checks.compromise.known_bad_processes import KnownBadProcessCheck
from usaf.checks.containers.docker_socket_check import DockerSocketCheck
from usaf.checks.kernel.module_loading_check import KernelModuleLoadingCheck
from usaf.checks.packages.unnecessary_packages import UnnecessaryPackagesCheck
from usaf.checks.security.firewall_check import FirewallActiveCheck
from usaf.checks.services.insecure_services import InsecureServicesCheck


class TestCheckIntegration:
    """Verify checks produce consistent results with realistic data."""

    def test_known_bad_process_no_false_positive(self):
        check = KnownBadProcessCheck()
        result = check.evaluate({
            "processes": {
                "processes": [
                    {"name": "sshd", "pid": 1, "uid": 0, "state": "S", "binary": "/usr/sbin/sshd"},
                    {"name": "systemd", "pid": 1, "uid": 0, "state": "S", "binary": "/lib/systemd/systemd"},
                    {"name": "bash", "pid": 1000, "uid": 1000, "state": "S", "binary": "/usr/bin/bash"},
                ]
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_risky_packages_list(self):
        from usaf.checks.packages.unnecessary_packages import UnnecessaryPackagesCheck

        check = UnnecessaryPackagesCheck()
        assert "telnetd" in check.RISKY_PACKAGES
        assert "rsh-server" in check.RISKY_PACKAGES
        assert "samba" in check.RISKY_PACKAGES
        assert len(check.RISKY_PACKAGES) >= 14

    def test_firewall_check_known_states(self):
        check = FirewallActiveCheck()

        pass_result = check.evaluate({
            "firewall": {
                "ufw": {"active": True, "installed": True, "raw": ""},
                "nftables": {"active": False, "installed": False},
                "iptables": {"active": False, "installed": False},
            }
        })
        assert pass_result.passed

        fail_result = check.evaluate({
            "firewall": {
                "ufw": {"active": False, "installed": False},
                "nftables": {"active": False, "installed": False},
                "iptables": {"active": False, "installed": False},
            }
        })
        assert not fail_result.passed

    def test_insecure_services_empty_no_findings(self, monkeypatch):
        from pathlib import Path

        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = InsecureServicesCheck()
        result = check.evaluate({})
        assert result.passed

    def test_kernel_module_loading_check(self, monkeypatch):
        from pathlib import Path

        monkeypatch.setattr(Path, "read_text", lambda _: "0")
        monkeypatch.setattr(Path, "exists", lambda _: True)
        check = KernelModuleLoadingCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
