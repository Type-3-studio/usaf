from __future__ import annotations

import abc
import time
from typing import Any, ClassVar

from usaf.core.exceptions import PluginError, PluginRegistrationError
from usaf.core.interfaces import AuditCheckInterface
from usaf.models.evidence import Evidence
from usaf.models.finding import Finding
from usaf.models.result import CheckResult
from usaf.models.severity import CheckCategory, Confidence, Severity


class AuditCheck(AuditCheckInterface):
    """Base class for all audit check plugins."""

    id: ClassVar[str] = ""
    name: ClassVar[str] = ""
    category: ClassVar[CheckCategory] = CheckCategory.GENERAL
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = ""
    depends: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = []
    timeout: int = 60

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        required = ["id", "name", "description"]
        missing = [r for r in required if not getattr(cls, r, None)]
        if missing:
            raise PluginRegistrationError(
                f"Check {cls.__name__} missing required attributes: {', '.join(missing)}"
            )

    def evaluate(self, collectors: dict[str, dict[str, Any]]) -> CheckResult:
        start = time.perf_counter()
        result = CheckResult(
            check_id=self.id,
            name=self.name,
            category=self.category,
            passed=True,
        )
        try:
            findings = self._run_check(collectors)
            result.findings = findings
            result.passed = len(findings) == 0
        except Exception as e:
            result.passed = False
            result.error = f"{type(e).__name__}: {e}"
        result.execution_time_ms = (time.perf_counter() - start) * 1000
        return result

    @abc.abstractmethod
    def _run_check(self, collectors: dict[str, dict[str, Any]]) -> list[Finding]:
        ...

    def finding(
        self,
        finding_id: str,
        title: str,
        description: str,
        rationale: str,
        remediation: str,
        severity: Severity | None = None,
        evidence: Evidence | None = None,
        detected_value: str | None = None,
        expected_value: str | None = None,
        affected_component: str | None = None,
        reference: str | None = None,
        confidence: Confidence = Confidence.HIGH,
        false_positive_probability: float = 0.0,
        cve_ids: list[str] | None = None,
        cis_benchmarks: list[str] | None = None,
        mitre_attack_ids: list[str] | None = None,
        owasp_ids: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> Finding:
        return Finding(
            id=f"{self.id}-{finding_id}",
            check_id=self.id,
            category=self.category,
            severity=severity or self.severity,
            risk_score=(severity or self.severity).score,
            title=title,
            description=description,
            rationale=rationale,
            evidence=evidence,
            detected_value=detected_value,
            expected_value=expected_value,
            affected_component=affected_component,
            remediation=remediation,
            reference=reference,
            confidence=confidence,
            false_positive_probability=false_positive_probability,
            source=type(self).__name__,
            cve_ids=cve_ids or [],
            cis_benchmarks=cis_benchmarks or [],
            mitre_attack_ids=mitre_attack_ids or [],
            owasp_ids=owasp_ids or [],
            tags=tags or [],
        )

    def _get_data(
        self, collectors: dict[str, dict[str, Any]], name: str
    ) -> dict[str, Any]:
        data = collectors.get(name)
        if data is None:
            raise PluginError(
                f"Check '{self.id}' requires collector '{name}' which was not found"
            )
        return data

    def _get_optional_data(
        self, collectors: dict[str, dict[str, Any]], name: str
    ) -> dict[str, Any] | None:
        return collectors.get(name)


__all__ = ["AuditCheck"]
