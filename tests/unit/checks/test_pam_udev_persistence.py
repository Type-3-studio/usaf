from __future__ import annotations

from usaf.checks.persistence.pam_udev_persistence import (
    PamModuleModificationsCheck,
    UdevRulesPersistenceCheck,
    UnexpectedPamModulesCheck,
)


class TestUnexpectedPamModulesCheck:
    def test_passes_with_empty_modules(self):
        check = UnexpectedPamModulesCheck()
        result = check.evaluate({"pam": {"modules": []}})
        assert result.passed

    def test_passes_with_no_pam_data(self):
        check = UnexpectedPamModulesCheck()
        result = check.evaluate({"pam": {}})
        assert result.passed

    def test_passes_with_known_modules(self):
        check = UnexpectedPamModulesCheck()
        result = check.evaluate({
            "pam": {
                "modules": [
                    {"name": "pam_unix.so", "path": "/lib/x86_64-linux-gnu/security/pam_unix.so"},
                    {"name": "pam_limits.so", "path": "/lib/x86_64-linux-gnu/security/pam_limits.so"},
                ]
            }
        })
        assert result.passed

    def test_fails_with_unknown_module(self):
        check = UnexpectedPamModulesCheck()
        result = check.evaluate({
            "pam": {
                "modules": [{"name": "pwnkit.so", "path": "/lib/security/pwnkit.so"}]
            }
        })
        assert not result.passed
        assert len(result.findings) >= 1

    def test_detects_suspicious_module_name_in_config(self):
        check = UnexpectedPamModulesCheck()
        result = check.evaluate({
            "pam": {
                "modules": [{"name": "pam_unix.so", "path": "/lib/security/pam_unix.so"}],
                "config_files": [
                    {"file": "/etc/pam.d/common-auth", "content": "auth required pam_backdoor.so"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) >= 1

    def test_has_mitre_mapping(self):
        check = UnexpectedPamModulesCheck()
        result = check.evaluate({
            "pam": {
                "modules": [{"name": "pwnkit.so", "path": "/lib/security/pwnkit.so"}]
            }
        })
        assert len(result.findings) > 0
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestPamModuleModificationsCheck:
    def test_does_not_error_with_no_data(self):
        check = PamModuleModificationsCheck()
        result = check.evaluate({"pam": {}})
        assert result.error is None

    def test_has_mitre_mapping(self):
        check = PamModuleModificationsCheck()
        result = check.evaluate({"pam": {}})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestUdevRulesPersistenceCheck:
    def test_does_not_error_with_no_data(self):
        check = UdevRulesPersistenceCheck()
        result = check.evaluate({})
        assert result.error is None

    def test_has_mitre_mapping(self):
        check = UdevRulesPersistenceCheck()
        result = check.evaluate({})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)
