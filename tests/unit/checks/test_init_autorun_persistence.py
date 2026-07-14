from __future__ import annotations

from usaf.checks.persistence.init_autorun_persistence import (
    InitScriptPersistenceCheck,
    LoginLogoutHooksCheck,
    RcLocalScriptCheck,
    SystemdUserUnitsCheck,
    XdgAutostartCheck,
)


class TestRcLocalScriptCheck:
    def test_passes_with_no_data(self):
        check = RcLocalScriptCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_mitre_mapping(self):
        check = RcLocalScriptCheck()
        result = check.evaluate({})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestInitScriptPersistenceCheck:
    def test_does_not_error_with_no_data(self):
        check = InitScriptPersistenceCheck()
        result = check.evaluate({})
        assert result.error is None

    def test_has_mitre_mapping(self):
        check = InitScriptPersistenceCheck()
        result = check.evaluate({})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestLoginLogoutHooksCheck:
    def test_passes_with_no_data(self):
        check = LoginLogoutHooksCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_mitre_mapping(self):
        check = LoginLogoutHooksCheck()
        result = check.evaluate({})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestSystemdUserUnitsCheck:
    def test_passes_with_no_users(self):
        check = SystemdUserUnitsCheck()
        result = check.evaluate({"users": {"users": []}})
        assert result.passed

    def test_passes_with_nonexistent_users(self):
        check = SystemdUserUnitsCheck()
        result = check.evaluate({
            "users": {
                "users": [
                    {"username": "testuser", "home": "/nonexistent"},
                ]
            }
        })
        assert result.passed

    def test_has_mitre_mapping(self):
        check = SystemdUserUnitsCheck()
        result = check.evaluate({"users": {"users": []}})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestXdgAutostartCheck:
    def test_does_not_error_with_no_data(self):
        check = XdgAutostartCheck()
        result = check.evaluate({})
        assert result.error is None

    def test_has_mitre_mapping(self):
        check = XdgAutostartCheck()
        result = check.evaluate({})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)
