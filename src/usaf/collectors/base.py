from __future__ import annotations

import abc
import time
from typing import Any

from usaf.core.exceptions import CollectorError, CollectorTimeoutError
from usaf.core.interfaces import CollectorInterface


class BaseCollector(CollectorInterface):
    """Base class for all data collectors."""

    name: str = ""
    description: str = ""
    depends: list[str] = []
    timeout: int = 30
    _data: dict[str, Any] | None = None

    def __init__(self) -> None:
        if not self.name:
            raise CollectorError(f"{type(self).__name__} must define a 'name' class variable")

    def collect(self) -> dict[str, Any]:
        """Collect data with timeout support."""
        if self._data is not None:
            return self._data
        start = time.perf_counter()
        try:
            self._data = self._do_collect()
        except CollectorError:
            raise
        except TimeoutError:
            raise CollectorTimeoutError(f"Collector '{self.name}' timed out after {self.timeout}s")
        except Exception as e:
            raise CollectorError(f"Collector '{self.name}' failed: {e}") from e
        elapsed = time.perf_counter() - start
        self._data = self._data or {}
        self._data["_collector_meta"] = {
            "name": self.name,
            "duration_ms": round(elapsed * 1000, 2),
            "timestamp": time.time(),
        }
        return self._data

    @abc.abstractmethod
    def _do_collect(self) -> dict[str, Any]: ...

    def get_data(self) -> dict[str, Any]:
        if self._data is None:
            return self.collect()
        return self._data

    def clear_cache(self) -> None:
        self._data = None
