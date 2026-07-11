from __future__ import annotations

from typing import Any

from usaf.core.exceptions import (
    PluginDependencyError,
    PluginNotFoundError,
    PluginRegistrationError,
)
from usaf.core.plugin import AuditCheck


class PluginRegistry:
    """Registry for audit check plugins.

    Manages plugin discovery, registration, dependency resolution,
    and lifecycle.
    """

    def __init__(self) -> None:
        self._checks: dict[str, type[AuditCheck]] = {}
        self._instances: dict[str, AuditCheck] = {}
        self._dependency_graph: dict[str, set[str]] = {}

    def register(self, check_cls: type[AuditCheck]) -> type[AuditCheck]:
        """Register a check plugin class."""
        check_id = check_cls.id
        if not check_id:
            raise PluginRegistrationError(
                f"Cannot register {check_cls.__name__}: id is empty"
            )
        if check_id in self._checks:
            raise PluginRegistrationError(
                f"Check '{check_id}' is already registered"
            )
        self._checks[check_id] = check_cls
        self._dependency_graph[check_id] = set(check_cls.depends)
        return check_cls

    def unregister(self, check_id: str) -> None:
        """Unregister a check plugin."""
        self._checks.pop(check_id, None)
        self._instances.pop(check_id, None)
        self._dependency_graph.pop(check_id, None)

    def get_class(self, check_id: str) -> type[AuditCheck]:
        """Get a check plugin class by ID."""
        cls = self._checks.get(check_id)
        if cls is None:
            raise PluginNotFoundError(f"Check '{check_id}' not found")
        return cls

    def get_instance(self, check_id: str) -> AuditCheck:
        """Get or create a check plugin instance by ID."""
        if check_id in self._instances:
            return self._instances[check_id]
        cls = self.get_class(check_id)
        instance = cls()
        self._instances[check_id] = instance
        return instance

    def get_all_ids(self) -> list[str]:
        """Get all registered check IDs."""
        return list(self._checks.keys())

    def get_all_classes(self) -> dict[str, type[AuditCheck]]:
        """Get all registered check classes."""
        return dict(self._checks)

    def get_all_instances(self) -> dict[str, AuditCheck]:
        """Get or create instances of all registered checks."""
        for check_id in self._checks:
            if check_id not in self._instances:
                self._instances[check_id] = self._checks[check_id]()
        return dict(self._instances)

    def get_by_category(self, category: str) -> dict[str, type[AuditCheck]]:
        """Get all checks in a category."""
        return {
            cid: cls
            for cid, cls in self._checks.items()
            if cls.category.value == category or cls.category == category
        }

    def resolve_dependencies(
        self, check_ids: list[str] | None = None
    ) -> list[str]:
        """Topological sort of checks based on collector dependencies."""
        targets = check_ids or list(self._checks.keys())
        graph: dict[str, set[str]] = {}
        all_ids = set(self._checks.keys())
        for cid in targets:
            if cid not in self._checks:
                raise PluginNotFoundError(f"Check '{cid}' not found")
            deps = set(self._checks[cid].depends)
            graph[cid] = deps & all_ids  # Only check-to-check deps

        visited: set[str] = set()
        temp: set[str] = set()
        order: list[str] = []

        def visit(cid: str) -> None:
            if cid in temp:
                raise PluginDependencyError(
                    f"Circular dependency detected involving '{cid}'"
                )
            if cid in visited:
                return
            temp.add(cid)
            for dep in graph.get(cid, set()):
                visit(dep)
            temp.remove(cid)
            visited.add(cid)
            order.append(cid)

        for cid in targets:
            if cid not in visited:
                visit(cid)

        return order

    def validate_dependencies(self) -> list[str]:
        """Validate that all dependencies can be satisfied."""
        errors: list[str] = []
        for check_id, cls in self._checks.items():
            for dep in cls.depends:
                if dep not in self._checks:
                    errors.append(
                        f"Check '{check_id}' depends on unknown check '{dep}'"
                    )
        return errors

    def count(self) -> int:
        return len(self._checks)

    def clear(self) -> None:
        self._checks.clear()
        self._instances.clear()
        self._dependency_graph.clear()


registry: PluginRegistry = PluginRegistry()


def register_check(cls: type[AuditCheck]) -> type[AuditCheck]:
    """Decorator to register a check plugin."""
    return registry.register(cls)


__all__ = ["PluginRegistry", "registry", "register_check"]
