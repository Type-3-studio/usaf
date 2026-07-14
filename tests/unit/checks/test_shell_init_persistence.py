from __future__ import annotations

from usaf.checks.persistence.shell_init_persistence import (
    ModifiedBashInitCheck,
    ModifiedZshInitCheck,
    UnexpectedProfileScriptsCheck,
)


class TestUnexpectedProfileScriptsCheck:
    def test_does_not_error_with_no_data(self):
        check = UnexpectedProfileScriptsCheck()
        result = check.evaluate({})
        assert result.error is None

    def test_has_mitre_mapping(self):
        check = UnexpectedProfileScriptsCheck()
        result = check.evaluate({})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestModifiedBashInitCheck:
    def test_passes_with_no_users(self):
        check = ModifiedBashInitCheck()
        result = check.evaluate({"users": {"users": []}})
        assert result.passed

    def test_passes_with_benign_users(self):
        check = ModifiedBashInitCheck()
        result = check.evaluate({
            "users": {
                "users": [
                    {"username": "testuser", "home": "/nonexistent"},
                ]
            }
        })
        assert result.passed

    def test_has_mitre_mapping(self):
        check = ModifiedBashInitCheck()
        result = check.evaluate({"users": {"users": []}})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestModifiedZshInitCheck:
    def test_passes_with_no_users(self):
        check = ModifiedZshInitCheck()
        result = check.evaluate({"users": {"users": []}})
        assert result.passed

    def test_passes_with_benign_users(self):
        check = ModifiedZshInitCheck()
        result = check.evaluate({
            "users": {
                "users": [
                    {"username": "testuser", "home": "/nonexistent"},
                ]
            }
        })
        assert result.passed

    def test_has_mitre_mapping(self):
        check = ModifiedZshInitCheck()
        result = check.evaluate({"users": {"users": []}})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)
