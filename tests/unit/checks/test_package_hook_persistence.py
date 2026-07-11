from __future__ import annotations

from usaf.checks.persistence.package_hook_persistence import (
    AptHookPersistenceCheck,
    DpkgHookPersistenceCheck,
)
from usaf.models.severity import Severity


class TestAptHookPersistenceCheck:
    def test_does_not_error_with_no_data(self):
        check = AptHookPersistenceCheck()
        result = check.evaluate({"apt": {}})
        assert result.error is None

    def test_does_not_error_with_empty_apt_data(self):
        check = AptHookPersistenceCheck()
        result = check.evaluate({})
        assert result.error is None

    def test_has_mitre_mapping(self):
        check = AptHookPersistenceCheck()
        result = check.evaluate({"apt": {}})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestDpkgHookPersistenceCheck:
    def test_passes_with_no_data(self):
        check = DpkgHookPersistenceCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_mitre_mapping(self):
        check = DpkgHookPersistenceCheck()
        result = check.evaluate({})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)
