from __future__ import annotations

from typing import Any

import pytest

from usaf.collectors.base import BaseCollector
from usaf.core.exceptions import CollectorError, CollectorTimeoutError


class TestBaseCollector:
    def test_requires_name(self):
        class BadCollector(BaseCollector):
            def _do_collect(self) -> dict[str, Any]:
                return {}

        with pytest.raises(CollectorError, match="must define a 'name'"):
            BadCollector()

    def test_collect_caches_result(self):
        call_count = 0

        class CountingCollector(BaseCollector):
            name = "counter"

            def _do_collect(self) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                return {"count": call_count}

        c = CountingCollector()
        r1 = c.collect()
        r2 = c.collect()
        assert r1["count"] == 1
        assert r2["count"] == 1
        assert call_count == 1

    def test_clear_cache(self):
        call_count = 0

        class CountingCollector(BaseCollector):
            name = "counter"

            def _do_collect(self) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                return {"count": call_count}

        c = CountingCollector()
        c.collect()
        c.clear_cache()
        r2 = c.collect()
        assert r2["count"] == 2

    def test_get_data_calls_collect_if_no_cache(self):
        class SimpleCollector(BaseCollector):
            name = "simple"

            def _do_collect(self) -> dict[str, Any]:
                return {"key": "value"}

        c = SimpleCollector()
        assert c._data is None
        data = c.get_data()
        assert data["key"] == "value"
        assert c._data is not None

    def test_get_data_uses_cache(self):
        class SimpleCollector(BaseCollector):
            name = "simple"

            def _do_collect(self) -> dict[str, Any]:
                return {"key": "value"}

        c = SimpleCollector()
        c._data = {"cached": True}
        data = c.get_data()
        assert data["cached"] is True

    def test_collect_adds_metadata(self):
        class MetaCollector(BaseCollector):
            name = "meta"

            def _do_collect(self) -> dict[str, Any]:
                return {"result": 42}

        c = MetaCollector()
        data = c.collect()
        assert "_collector_meta" in data
        assert data["_collector_meta"]["name"] == "meta"
        assert "duration_ms" in data["_collector_meta"]
        assert "timestamp" in data["_collector_meta"]

    def test_collect_wraps_collector_error(self):
        class FailingCollector(BaseCollector):
            name = "failer"

            def _do_collect(self) -> dict[str, Any]:
                raise CollectorError("custom error")

        c = FailingCollector()
        with pytest.raises(CollectorError, match="custom error"):
            c.collect()

    def test_collect_wraps_unknown_error(self):
        class FailingCollector(BaseCollector):
            name = "failer"

            def _do_collect(self) -> dict[str, Any]:
                raise ValueError("something broke")

        c = FailingCollector()
        with pytest.raises(CollectorError, match="failer.*failed.*something broke"):
            c.collect()

    def test_collect_returns_empty_dict_on_none(self):
        class NoneCollector(BaseCollector):
            name = "return_none"

            def _do_collect(self) -> dict[str, Any] | None:
                return None

        c = NoneCollector()
        data = c.collect()
        assert data == {"_collector_meta": data["_collector_meta"]}

    def test_depends_default_empty(self):
        class NoDepCollector(BaseCollector):
            name = "no_dep"

            def _do_collect(self) -> dict[str, Any]:
                return {}

        c = NoDepCollector()
        assert c.depends == []
