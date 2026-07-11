from __future__ import annotations

import time

from usaf.cache.engine import CacheEngine


class TestCacheEngine:
    def test_get_and_set(self):
        cache = CacheEngine()
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_missing(self):
        cache = CacheEngine()
        assert cache.get("nonexistent") is None

    def test_get_expired(self):
        cache = CacheEngine()
        cache.set("key", "value", ttl=0)
        time.sleep(0.001)
        assert cache.get("key") is None

    def test_invalidate(self):
        cache = CacheEngine()
        cache.set("key", "value")
        cache.invalidate("key")
        assert cache.get("key") is None

    def test_invalidate_missing(self):
        cache = CacheEngine()
        cache.invalidate("nonexistent")

    def test_clear(self):
        cache = CacheEngine()
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None

    def test_size(self):
        cache = CacheEngine()
        assert cache.size == 0
        cache.set("a", 1)
        assert cache.size == 1
        cache.set("b", 2)
        assert cache.size == 2

    def test_size_after_expiry(self):
        cache = CacheEngine()
        cache.set("a", 1, ttl=0)
        cache.set("b", 2, ttl=300)
        time.sleep(0.001)
        assert cache.size == 1
        assert cache.get("a") is None
        assert cache.get("b") == 2

    def test_set_overwrites(self):
        cache = CacheEngine()
        cache.set("key", "old")
        cache.set("key", "new")
        assert cache.get("key") == "new"
