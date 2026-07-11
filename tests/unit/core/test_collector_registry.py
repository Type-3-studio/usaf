from __future__ import annotations

import pytest

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import CollectorRegistry, collector_registry, register_collector
from usaf.core.exceptions import CollectorError


class TestCollectorRegistry:
    def test_register_and_retrieve(self):
        reg = CollectorRegistry()

        @reg.register
        class TestColl(BaseCollector):
            name = "test_coll"

            def _do_collect(self):
                return {"key": "value"}

        cls = reg.get_class("test_coll")
        assert cls.name == "test_coll"

    def test_register_duplicate_name(self):
        reg = CollectorRegistry()

        @reg.register
        class Coll1(BaseCollector):
            name = "dup"

            def _do_collect(self):
                return {}

        with pytest.raises(CollectorError):

            @reg.register
            class Coll2(BaseCollector):
                name = "dup"

                def _do_collect(self):
                    return {}

    def test_get_nonexistent(self):
        reg = CollectorRegistry()
        with pytest.raises(CollectorError):
            reg.get_class("nope")

    def test_unregister(self):
        reg = CollectorRegistry()

        @reg.register
        class C(BaseCollector):
            name = "remove_me"

            def _do_collect(self):
                return {}

        assert reg.count() == 1
        reg.unregister("remove_me")
        assert reg.count() == 0

    def test_create_instance(self):
        reg = CollectorRegistry()

        @reg.register
        class MyColl(BaseCollector):
            name = "my_coll"

            def _do_collect(self):
                return {"result": 42}

        instance = reg.create_instance("my_coll")
        assert instance.name == "my_coll"
        assert instance.collect()["result"] == 42

    def test_create_all_instances(self):
        reg = CollectorRegistry()

        @reg.register
        class A(BaseCollector):
            name = "a"

            def _do_collect(self):
                return {}

        @reg.register
        class B(BaseCollector):
            name = "b"

            def _do_collect(self):
                return {}

        instances = reg.create_all_instances()
        names = {i.name for i in instances}
        assert names == {"a", "b"}

    def test_get_all_names(self):
        reg = CollectorRegistry()

        @reg.register
        class A(BaseCollector):
            name = "alpha"

            def _do_collect(self):
                return {}

        @reg.register
        class B(BaseCollector):
            name = "beta"

            def _do_collect(self):
                return {}

        assert set(reg.get_all_names()) == {"alpha", "beta"}

    def test_register_with_empty_name_raises(self):
        reg = CollectorRegistry()

        with pytest.raises(CollectorError):

            @reg.register
            class NoName(BaseCollector):
                name = ""

                def _do_collect(self):
                    return {}

    def test_register_decorator_function(self):
        reg = CollectorRegistry()
        reg.clear()

        @register_collector
        class DecoratedColl(BaseCollector):
            name = "decorated"
            description = "Uses decorator"

            def _do_collect(self):
                return {"decorated": True}

        try:
            cls = collector_registry.get_class("decorated")
            assert cls.name == "decorated"
        finally:
            collector_registry.unregister("decorated")

    def test_clear(self):
        reg = CollectorRegistry()

        @reg.register
        class C(BaseCollector):
            name = "temp"

            def _do_collect(self):
                return {}

        assert reg.count() == 1
        reg.clear()
        assert reg.count() == 0
