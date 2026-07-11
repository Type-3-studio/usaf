from __future__ import annotations

import importlib
import pkgutil

from usaf.collectors.base import BaseCollector
from usaf.core.exceptions import CollectorError


class CollectorRegistry:
    """Registry for data collector plugins.

    Manages collector class registration, discovery, instantiation, and
    lifecycle. Mirrors the pattern used by PluginRegistry for checks.
    """

    def __init__(self) -> None:
        self._classes: dict[str, type[BaseCollector]] = {}

    def register(self, cls: type[BaseCollector]) -> type[BaseCollector]:
        name = getattr(cls, "name", None)
        if not name:
            raise CollectorError(f"Cannot register {cls.__name__}: name is empty")
        if name in self._classes:
            raise CollectorError(f"Collector '{name}' is already registered")
        self._classes[name] = cls
        return cls

    def unregister(self, name: str) -> None:
        self._classes.pop(name, None)

    def get_class(self, name: str) -> type[BaseCollector]:
        cls = self._classes.get(name)
        if cls is None:
            raise CollectorError(f"Collector '{name}' not found")
        return cls

    def create_instance(self, name: str) -> BaseCollector:
        cls = self.get_class(name)
        return cls()

    def create_all_instances(self) -> list[BaseCollector]:
        return [cls() for cls in self._classes.values()]

    def get_all_names(self) -> list[str]:
        return list(self._classes.keys())

    def count(self) -> int:
        return len(self._classes)

    def clear(self) -> None:
        self._classes.clear()

    @staticmethod
    def discover(package: str = "usaf.collectors") -> None:
        """Walk a package namespace and import every submodule.

        Importing triggers @register_collector decorators, which populate
        the registry. Safe to call multiple times (duplicate registrations
        raise, so discovery is idempotent via guard clauses if needed).
        """
        try:
            pkg = importlib.import_module(package)
        except ImportError:
            return

        for _info in pkgutil.walk_packages(
            pkg.__path__, prefix=package + ".", onerror=lambda _: None
        ):
            try:
                importlib.import_module(_info.name)
            except Exception:
                pass


collector_registry: CollectorRegistry = CollectorRegistry()


def register_collector(cls: type[BaseCollector]) -> type[BaseCollector]:
    """Decorator to register a collector plugin."""
    return collector_registry.register(cls)
