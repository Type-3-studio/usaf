from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from usaf.core.exceptions import PolicyError
from usaf.models.finding import Finding
from usaf.models.severity import Confidence


class KnowledgeEntry:
    """Rich metadata for a security check, loaded from YAML knowledge files.

    Provides threat context, exploit scenarios, CVSS scoring,
    false-positive analysis, and remediation guidance for every check.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self.id: str = data.get("id", "")
        self.title: str = data.get("title", "")
        self.threat: str = data.get("threat", "")
        self.exploit: str = data.get("exploit", "")
        self.impact: str = data.get("impact", "")
        self.fix: str = data.get("fix", "")
        self.breakage: str = data.get("breakage", "")
        self.cvss: str = data.get("cvss", "")
        self.affected_versions: list[str] = data.get("affected_versions", [])
        self.false_positive_rate: float = data.get("false_positive_rate", 0.0)
        self.known_exceptions: list[str] = data.get("known_exceptions", [])
        self.related_findings: list[str] = data.get("related_findings", [])
        self.severity_override: str | None = data.get("severity_override")
        self.tags: list[str] = data.get("tags", [])
        self.mitre_mappings: list[str] = data.get("mitre_mappings", [])
        self._data = data

    def __getattr__(self, name: str) -> Any:
        return self._data.get(name, "")

    @classmethod
    def from_file(cls, path: str | Path) -> KnowledgeEntry:
        path = Path(path)
        if not path.exists():
            raise PolicyError(f"Knowledge file not found: {path}")
        try:
            data = yaml.safe_load(path.read_text())
            if not data:
                raise PolicyError(f"Empty knowledge file: {path}")
            return cls(data)
        except yaml.YAMLError as e:
            raise PolicyError(f"Invalid YAML in {path}: {e}") from e

    def evaluate_confidence_from_kb(
        self, finding: Finding
    ) -> tuple[Confidence, float]:
        """Compute evidence-adjusted confidence using KB false_positive_rate."""
        base_multiplier = finding.confidence.multiplier
        fp_adjusted = base_multiplier * (1.0 - self.false_positive_rate)
        evidence_bonus = self._compute_evidence_quality(finding)
        effective = min(1.0, fp_adjusted + evidence_bonus)
        confidence = (
            Confidence.HIGH if effective >= 0.8
            else Confidence.MEDIUM if effective >= 0.5
            else Confidence.LOW
        )
        return confidence, round(effective, 2)

    @staticmethod
    def _compute_evidence_quality(finding: Finding) -> float:
        ev = finding.evidence
        if ev is None:
            return 0.0

        bonus = 0.0
        ev_type = type(ev).__name__

        file_evidence_types = {"FileEvidence"}
        command_evidence_types = {"CommandEvidence"}
        high_quality_types = {"FileEvidence", "ProcessEvidence", "UserEvidence"}
        medium_quality_types = {"NetworkEvidence", "PackageEvidence", "RegistryEvidence"}

        if ev_type in high_quality_types:
            bonus += 0.15
        elif ev_type in medium_quality_types:
            bonus += 0.10
        elif ev_type in command_evidence_types:
            bonus += 0.05

        return bonus

    @property
    def has_exceptions(self) -> bool:
        return len(self.known_exceptions) > 0

    @property
    def summary(self) -> str:
        parts = []
        if self.threat:
            parts.append(f"Threat: {self.threat}")
        if self.impact:
            parts.append(f"Impact: {self.impact}")
        if self.cvss:
            parts.append(f"CVSS: {self.cvss}")
        if self.known_exceptions:
            parts.append(f"Exceptions ({len(self.known_exceptions)}): {self.known_exceptions[0]}")
        return " | ".join(parts)


class KnowledgeBase:
    """Repository of knowledge entries for all security checks.

    Loads YAML files from the knowledge/ directory and provides
    lookup by check ID. Integrates with findings via the reference field.
    """

    def __init__(self, knowledge_dir: str | Path | None = None) -> None:
        self._entries: dict[str, KnowledgeEntry] = {}
        self.knowledge_dir = Path(knowledge_dir or self._default_dir())
        self._loaded = False

    @staticmethod
    def _default_dir() -> str:
        return str(Path(__file__).parent)

    def load_all(self) -> None:
        """Load all YAML knowledge files from the knowledge directory."""
        for yaml_file in sorted(self.knowledge_dir.glob("*.yaml")):
            try:
                entry = KnowledgeEntry.from_file(yaml_file)
                if entry.id:
                    self._entries[entry.id] = entry
            except (PolicyError, yaml.YAMLError):
                pass
        self._loaded = True

    def get(self, check_id: str) -> KnowledgeEntry | None:
        if not self._loaded:
            self.load_all()
        return self._entries.get(check_id)

    def lookup_finding(self, finding: Finding) -> KnowledgeEntry | None:
        """Look up a knowledge entry for the check that produced this finding."""
        return self.get(finding.check_id)

    @property
    def entries(self) -> dict[str, KnowledgeEntry]:
        if not self._loaded:
            self.load_all()
        return dict(self._entries)

    @property
    def count(self) -> int:
        return len(self.entries)

    def evaluate_finding_confidence(
        self, finding: Finding
    ) -> tuple[Confidence, float]:
        """Evaluate a finding's confidence using KB data + evidence quality."""
        entry = self.lookup_finding(finding)
        if entry:
            return entry.evaluate_confidence_from_kb(finding)
        base = finding.confidence.multiplier
        evidence_bonus = KnowledgeEntry._compute_evidence_quality(finding)
        effective = min(1.0, base + evidence_bonus)
        confidence = (
            Confidence.HIGH if effective >= 0.8
            else Confidence.MEDIUM if effective >= 0.5
            else Confidence.LOW
        )
        return confidence, round(effective, 2)
