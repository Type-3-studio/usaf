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


class CorrelationRuleInterface(ABC):
    """Interface for correlation rules."""

    id: str
    name: str
    description: str
    severity: str
    requires: list[str]

    @abstractmethod
    def evaluate(self, findings: list[Any]) -> list[Any]: ...


class BaselineManagerInterface(ABC):
    """Interface for baseline management."""

    @abstractmethod
    def store(self, name: str, snapshot: Any) -> str: ...

    @abstractmethod
    def load(self, name: str) -> Any: ...

    @abstractmethod
    def diff(self, baseline: Any, current: Any) -> Any: ...

    @abstractmethod
    def list_baselines(self) -> list[str]: ...


class ProfileManagerInterface(ABC):
    """Interface for profile management."""

    @abstractmethod
    def match(self, collector_data: dict[str, Any], profile_name: str | None = None) -> Any: ...

    @abstractmethod
    def get_profile(self, name: str) -> Any: ...


class ComplianceFrameworkInterface(ABC):
    """Interface for compliance framework queries."""

    @abstractmethod
    def get_findings_for(self, framework_id: str, findings: list[Any]) -> list[Any]: ...

    @abstractmethod
    def get_coverage(self, framework_id: str, result: Any) -> Any: ...
