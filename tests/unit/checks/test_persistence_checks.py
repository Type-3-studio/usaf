from __future__ import annotations

from usaf.checks.persistence.unauthorized_services import UnauthorizedServicesCheck
from usaf.models.severity import Severity


class TestUnauthorizedServicesCheck:
    def test_passes_when_no_services(self):
        check = UnauthorizedServicesCheck()
        result = check.evaluate({"systemd": {"services": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_benign_services(self):
        check = UnauthorizedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "ssh.service", "description": "OpenSSH server", "active": "active"},
                    {"name": "ufw.service", "description": "Uncomplicated firewall", "active": "active"},
                ]
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_skips_inactive_services(self):
        check = UnauthorizedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "backdoor.service", "description": "suspicious", "active": "inactive"},
                ]
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_detects_suspicious_service_by_name(self):
        check = UnauthorizedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "backdoor.service", "description": "A system service", "active": "active"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "backdoor" in f.title
        assert f.severity == Severity.HIGH

    def test_detects_suspicious_service_by_description(self):
        check = UnauthorizedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "systemd-helper.service", "description": "reverse shell daemon", "active": "active"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_detects_multiple_suspicious_services(self):
        check = UnauthorizedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "backdoor.service", "description": "bad", "active": "active"},
                    {"name": "miner.service", "description": "crypto", "active": "active"},
                    {"name": "ssh.service", "description": "SSH server", "active": "active"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_has_mitre_mapping(self):
        check = UnauthorizedServicesCheck()
        result = check.evaluate({
            "systemd": {
                "services": [
                    {"name": "backdoor.service", "description": "suspicious", "active": "active"},
                ]
            }
        })
        assert len(result.findings[0].mitre_attack_ids) > 0
