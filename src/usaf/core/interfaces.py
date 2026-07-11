from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from usaf.models.result import CheckResult, ScanResult
from usaf.models.score import ScanScore


class AuditCheckInterface(ABC):
    """Interface every audit check plugin must implement."""

    id: str
    name: str
    category: str
    severity: str
    description: str
    depends: list[str]
    tags: list[str]
    timeout: int = 60

    @abstractmethod
    def evaluate(self, collectors: dict[str, dict[str, Any]]) -> CheckResult: ...


class CollectorInterface(ABC):
    """Interface every data collector must implement."""

    name: str
    description: str = ""
    depends: list[str] = []
    timeout: int = 30

    @abstractmethod
    def collect(self) -> dict[str, Any]: ...


class ReporterInterface(ABC):
    """Interface every reporter must implement."""

    name: str
    description: str = ""

    @abstractmethod
    def generate(
        self, result: ScanResult, score: ScanScore | None = None, **kwargs: Any
    ) -> str: ...

    @abstractmethod
    def write(self, content: str, path: str) -> None: ...


class ParserInterface(ABC):
    """Interface every parser must implement."""

    name: str
    description: str = ""

    @abstractmethod
    def parse(self, content: str) -> Any: ...

    @abstractmethod
    def parse_file(self, path: str) -> Any: ...


class ScoringEngineInterface(ABC):
    """Interface for the scoring engine."""

    @abstractmethod
    def calculate(self, result: ScanResult) -> ScanScore: ...


class CacheEngineInterface(ABC):
    """Interface for caching."""

    @abstractmethod
    def get(self, key: str) -> Any | None: ...

    @abstractmethod
    def set(self, key: str, value: Any, ttl: int = 300) -> None: ...

    @abstractmethod
    def invalidate(self, key: str) -> None: ...

    @abstractmethod
    def clear(self) -> None: ...
