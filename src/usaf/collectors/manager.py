from __future__ import annotations

from typing import Any

from usaf.collectors.base import BaseCollector
from usaf.core.exceptions import CollectorError


class CollectorManager:
    """Manages collector lifecycle, caching, and dependency resolution."""

    def __init__(self, collectors: list[BaseCollector] | None = None) -> None:
        self._collectors: dict[str, BaseCollector] = {}
        self._data: dict[str, dict[str, Any]] = {}
        if collectors:
            for c in collectors:
                self.add(c)

    def add(self, collector: BaseCollector) -> None:
        """Register a collector."""
        if collector.name in self._collectors:
            raise CollectorError(
                f"Collector '{collector.name}' is already registered"
            )
        self._collectors[collector.name] = collector

    def get(self, name: str) -> dict[str, Any] | None:
        """Get collector data by name."""
        return self._data.get(name)

    def get_collector(self, name: str) -> BaseCollector:
        """Get collector instance by name."""
        c = self._collectors.get(name)
        if c is None:
            raise CollectorError(f"Collector '{name}' not found")
        return c

    def collect_all(self, names: list[str] | None = None) -> dict[str, dict[str, Any]]:
        """Collect data from all or specified collectors."""
        target_names = names or list(self._collectors.keys())
        order = self._resolve_dependencies(target_names)

        for name in order:
            collector = self._collectors[name]
            self._data[name] = collector.collect()

        return dict(self._data)

    def collect_single(self, name: str) -> dict[str, Any]:
        collector = self.get_collector(name)
        data = collector.collect()
        self._data[name] = data
        return data

    def _resolve_dependencies(self, names: list[str]) -> list[str]:
        """Topological sort of collector names."""
        graph: dict[str, set[str]] = {}
        all_names = set(self._collectors.keys())
        for name in names:
            deps = set(self._collectors[name].depends) & all_names
            graph[name] = deps

        visited: set[str] = set()
        temp: set[str] = set()
        order: list[str] = []

        def visit(name: str) -> None:
            if name not in all_names:
                return
            if name in temp:
                raise CollectorError(
                    f"Circular dependency in collectors involving '{name}'"
                )
            if name in visited:
                return
            temp.add(name)
            for dep in graph.get(name, set()):
                visit(dep)
            temp.remove(name)
            visited.add(name)
            order.append(name)

        for name in names:
            visit(name)

        return order

    def clear_cache(self) -> None:
        for collector in self._collectors.values():
            collector.clear_cache()
        self._data.clear()

    @property
    def names(self) -> list[str]:
        return list(self._collectors.keys())

    @property
    def count(self) -> int:
        return len(self._collectors)
