from __future__ import annotations

import pytest

from usaf.core.exceptions import PluginDependencyError, PluginNotFoundError, PluginRegistrationError
from usaf.core.plugin import AuditCheck
from usaf.core.registry import PluginRegistry
from usaf.models.severity import CheckCategory, Severity


class TestPluginRegistry:
    def test_register_and_retrieve(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class TestCheck(AuditCheck):
            id = "TEST-001"
            name = "Test Check"
            category = CheckCategory.SYSTEM
            severity = Severity.MEDIUM
            description = "A test check"
            depends = ["kernel_params"]
            tags = ["test"]

            def _run_check(self, collectors):
                return []

        cls = empty_registry.get_class("TEST-001")
        assert cls.id == "TEST-001"
        assert cls.name == "Test Check"

    def test_register_duplicate_id(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class Check1(AuditCheck):
            id = "DUP-001"
            name = "Check 1"
            category = CheckCategory.SYSTEM
            severity = Severity.MEDIUM
            description = "First"

            def _run_check(self, collectors):
                return []

        with pytest.raises(PluginRegistrationError):

            @empty_registry.register
            class Check2(AuditCheck):
                id = "DUP-001"
                name = "Check 2"
                category = CheckCategory.SYSTEM
                severity = Severity.MEDIUM
                description = "Second"

                def _run_check(self, collectors):
                    return []

    def test_get_nonexistent_check(self, empty_registry: PluginRegistry):
        with pytest.raises(PluginNotFoundError):
            empty_registry.get_class("NONEXISTENT")

    def test_get_instance(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class TestInstanceCheck(AuditCheck):
            id = "INST-001"
            name = "Instance Check"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "Test getting instance"

            def _run_check(self, collectors):
                return []

        instance = empty_registry.get_instance("INST-001")
        assert instance.id == "INST-001"
        assert instance.name == "Instance Check"

    def test_instance_caching(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class CacheTestCheck(AuditCheck):
            id = "CACHE-001"
            name = "Cache Test"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "Test instance caching"

            def _run_check(self, collectors):
                return []

        i1 = empty_registry.get_instance("CACHE-001")
        i2 = empty_registry.get_instance("CACHE-001")
        assert i1 is i2

    def test_get_all_ids(self, empty_registry: PluginRegistry):
        assert empty_registry.get_all_ids() == []

        @empty_registry.register
        class A(AuditCheck):
            id = "A-001"
            name = "A"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "A"

            def _run_check(self, collectors):
                return []

        @empty_registry.register
        class B(AuditCheck):
            id = "B-001"
            name = "B"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "B"

            def _run_check(self, collectors):
                return []

        ids = empty_registry.get_all_ids()
        assert "A-001" in ids
        assert "B-001" in ids
        assert len(ids) == 2

    def test_by_category(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class SysCheck(AuditCheck):
            id = "CAT-SYS"
            name = "Sys"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "System check"

            def _run_check(self, collectors):
                return []

        @empty_registry.register
        class NetCheck(AuditCheck):
            id = "CAT-NET"
            name = "Net"
            category = CheckCategory.NETWORK
            severity = Severity.LOW
            description = "Network check"

            def _run_check(self, collectors):
                return []

        sys_checks = empty_registry.get_by_category("SYSTEM")
        assert "CAT-SYS" in sys_checks
        assert "CAT-NET" not in sys_checks

    def test_resolve_dependencies(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class DepA(AuditCheck):
            id = "DEP-A"
            name = "Dep A"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "A"
            depends = ["kernel_params"]

            def _run_check(self, collectors):
                return []

        @empty_registry.register
        class DepB(AuditCheck):
            id = "DEP-B"
            name = "Dep B"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "B"
            depends = ["kernel_params"]

            def _run_check(self, collectors):
                return []

        order = empty_registry.resolve_dependencies(["DEP-A", "DEP-B"])
        assert "DEP-A" in order
        assert "DEP-B" in order
        assert len(order) == 2

    def test_circular_dependency(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class CircA(AuditCheck):
            id = "CIRC-A"
            name = "Circ A"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "A"
            depends = ["CIRC-B"]

            def _run_check(self, collectors):
                return []

        @empty_registry.register
        class CircB(AuditCheck):
            id = "CIRC-B"
            name = "Circ B"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "B"
            depends = ["CIRC-A"]

            def _run_check(self, collectors):
                return []

        with pytest.raises(PluginDependencyError):
            empty_registry.resolve_dependencies(["CIRC-A", "CIRC-B"])

    def test_validate_dependencies(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class MissingDepCheck(AuditCheck):
            id = "MISSING-DEP"
            name = "Missing"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "Has missing dependency"
            depends = ["NONEXISTENT_COLLECTOR"]

            def _run_check(self, collectors):
                return []

        errors = empty_registry.validate_dependencies()
        assert len(errors) > 0
        assert "MISSING-DEP" in errors[0]

    def test_class_missing_required_attributes(self):
        with pytest.raises(PluginRegistrationError):

            class BadCheck(AuditCheck):
                id = ""
                name = ""
                description = ""

                def _run_check(self, collectors):
                    return []

    def test_count(self, empty_registry: PluginRegistry):
        assert empty_registry.count() == 0

        @empty_registry.register
        class CountCheck(AuditCheck):
            id = "COUNT-001"
            name = "Count"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "Count test"

            def _run_check(self, collectors):
                return []

        assert empty_registry.count() == 1

    def test_clear(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class ClearCheck(AuditCheck):
            id = "CLEAR-001"
            name = "Clear"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "Clear test"

            def _run_check(self, collectors):
                return []

        assert empty_registry.count() == 1
        empty_registry.clear()
        assert empty_registry.count() == 0
        assert empty_registry.get_all_ids() == []

    def test_unregister(self, empty_registry: PluginRegistry):
        @empty_registry.register
        class UnregCheck(AuditCheck):
            id = "UNREG-001"
            name = "Unreg"
            category = CheckCategory.SYSTEM
            severity = Severity.LOW
            description = "Unregister test"

            def _run_check(self, collectors):
                return []

        assert empty_registry.count() == 1
        empty_registry.unregister("UNREG-001")
        assert empty_registry.count() == 0


def test_discover_checks_does_not_crash_on_missing_package():
    from usaf.core.registry import discover_checks

    discover_checks("usaf.does_not_exist")  # Should not raise


def test_discover_checks_discovers_existing_checks():
    from usaf.core.registry import discover_checks, registry

    before = registry.count()
    # Re-discover (safe — existing checks are already registered)
    discover_checks("usaf.checks")
    after = registry.count()
    # Should not lose any checks
    assert after >= before
    # Known checks should be present
    assert "KERN-101" in registry.get_all_ids()
    assert "SSH-101" in registry.get_all_ids()
    assert "USR-101" in registry.get_all_ids()
    assert "NET-101" in registry.get_all_ids()
    assert "PRM-101" in registry.get_all_ids()
