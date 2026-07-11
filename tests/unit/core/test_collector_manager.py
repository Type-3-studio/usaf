from __future__ import annotations

import pytest

from usaf.collectors.base import BaseCollector
from usaf.collectors.manager import CollectorManager
from usaf.core.exceptions import CollectorError


class TestCollectorManager:
    def test_add_and_get(self, collector_manager: CollectorManager):
        c = _make_collector("test_collector", {})
        collector_manager.add(c)
        fetched = collector_manager.get_collector("test_collector")
        assert fetched is not None
        assert fetched.name == "test_collector"

    def test_add_duplicate_raises(self, collector_manager: CollectorManager):
        c = _make_collector("dup", {})
        collector_manager.add(c)
        with pytest.raises(CollectorError):
            collector_manager.add(_make_collector("dup", {}))

    def test_get_nonexistent_collector(self, collector_manager: CollectorManager):
        with pytest.raises(CollectorError):
            collector_manager.get_collector("does_not_exist")

    def test_collect_all(self, collector_manager: CollectorManager):
        c = _make_collector("data", {"key": "value"})
        collector_manager.add(c)
        result = collector_manager.collect_all(["data"])
        assert result["data"]["key"] == "value"

    def test_collect_single(self, collector_manager: CollectorManager):
        c = _make_collector("single", {"result": 42})
        collector_manager.add(c)
        data = collector_manager.collect_single("single")
        assert data["result"] == 42

    def test_clear_cache(self, collector_manager: CollectorManager):
        c = _make_collector("cache_test", {"data": 1})
        collector_manager.add(c)
        collector_manager.collect_all(["cache_test"])
        assert c._data is not None
        collector_manager.clear_cache()
        assert c._data is None

    def test_names_property(self, collector_manager: CollectorManager):
        collector_manager.add(_make_collector("c1", {}))
        collector_manager.add(_make_collector("c2", {}))
        assert set(collector_manager.names) == {"c1", "c2"}

    def test_count(self, collector_manager: CollectorManager):
        assert collector_manager.count == 0
        collector_manager.add(_make_collector("x", {}))
        assert collector_manager.count == 1

    def test_dependency_resolution(self, collector_manager: CollectorManager):
        class DepA(BaseCollector):
            name = "dep_a"

            def _do_collect(self):
                return {"a": 1}

        class DepB(BaseCollector):
            name = "dep_b"
            depends = ["dep_a"]

            def _do_collect(self):
                return {"b": 2}

        collector_manager.add(DepA())
        collector_manager.add(DepB())
        result = collector_manager.collect_all(["dep_b", "dep_a"])
        assert "dep_a" in result
        assert "dep_b" in result

    def test_collector_caching(self, collector_manager: CollectorManager):
        call_count = 0

        class CountCollector(BaseCollector):
            name = "counter"

            def _do_collect(self):
                nonlocal call_count
                call_count += 1
                return {"count": call_count}

        collector_manager.add(CountCollector())
        r1 = collector_manager.collect_all(["counter"])
        r2 = collector_manager.collect_all(["counter"])
        assert call_count == 1  # Only collected once


    def test_init_with_collectors(self):
        c = _make_collector("preloaded", {"x": 1})
        mgr = CollectorManager(collectors=[c])
        assert mgr.count == 1
        assert mgr.get_collector("preloaded").name == "preloaded"

    def test_collect_all_none_defaults(self, collector_manager: CollectorManager):
        c = _make_collector("auto", {"val": 1})
        collector_manager.add(c)
        result = collector_manager.collect_all()
        assert "auto" in result

    def test_collect_single_updates_data(self, collector_manager: CollectorManager):
        c = _make_collector("s", {"key": "value"})
        collector_manager.add(c)
        data = collector_manager.collect_single("s")
        assert data["key"] == "value"
        assert collector_manager.get("s") == data

    def test_get_returns_none_for_unknown(self, collector_manager: CollectorManager):
        assert collector_manager.get("nope") is None

    def test_circular_dependency_raises(self, collector_manager: CollectorManager):
        class CircA(BaseCollector):
            name = "circ_a"
            depends = ["circ_b"]
            def _do_collect(self):
                return {}

        class CircB(BaseCollector):
            name = "circ_b"
            depends = ["circ_a"]
            def _do_collect(self):
                return {}

        collector_manager.add(CircA())
        collector_manager.add(CircB())
        with pytest.raises(CollectorError, match="Circular dependency"):
            collector_manager.collect_all(["circ_a", "circ_b"])

    def test_dependency_on_nonexistent_collector(self, collector_manager: CollectorManager):
        class BadDep(BaseCollector):
            name = "bad_dep"
            depends = ["nonexistent"]
            def _do_collect(self):
                return {}

        collector_manager.add(BadDep())
        # Should just skip the missing dependency
        result = collector_manager.collect_all(["bad_dep"])
        assert "bad_dep" in result


def _make_collector(col_name: str, data: dict) -> BaseCollector:
    def _create(name_value: str):
        class DynamicCollector(BaseCollector):
            name = name_value
            description = "Dynamic test collector"

            def _do_collect(self):
                return dict(data)

        return DynamicCollector()

    return _create(col_name)
