from __future__ import annotations

from typing import Any

from usaf.core.interfaces import ReporterInterface
from usaf.knowledge.base import KnowledgeBase
from usaf.models.finding import Finding
from usaf.models.result import ScanResult
from usaf.models.score import ScanScore


class BaseReporter(ReporterInterface):
    """Base class for all reporters."""

    name: str = ""
    description: str = ""

    def __init__(self) -> None:
        self._kb: KnowledgeBase | None = None

    @property
    def knowledge_base(self) -> KnowledgeBase:
        if self._kb is None:
            self._kb = KnowledgeBase()
            self._kb.load_all()
        return self._kb

    def enrich_finding(self, finding: Finding) -> dict[str, Any]:
        """Enrich a finding with knowledge base data for richer output."""
        entry = self.knowledge_base.lookup_finding(finding)
        if entry is None:
            return {}
        return {
            "kb_id": entry.id,
            "kb_threat": entry.threat,
            "kb_exploit": entry.exploit,
            "kb_impact": entry.impact,
            "kb_cvss": entry.cvss,
            "kb_breakage": entry.breakage,
            "kb_known_exceptions": entry.known_exceptions,
            "kb_false_positive_rate": entry.false_positive_rate,
            "kb_summary": entry.summary,
        }

    def enrich_findings(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Enrich all findings with knowledge base data."""
        return [
            {
                "finding": finding.model_dump(),
                "knowledge": self.enrich_finding(finding),
            }
            for finding in findings
        ]

    def generate(self, result: ScanResult, score: ScanScore | None = None, **kwargs: Any) -> str:
        raise NotImplementedError

    def write(self, content: str, path: str) -> None:
        with open(path, "w") as f:
            f.write(content)
