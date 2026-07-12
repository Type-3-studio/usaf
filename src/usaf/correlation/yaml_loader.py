from __future__ import annotations

import fnmatch
import logging
import os
from datetime import UTC, datetime
from typing import Any

import yaml

from usaf.correlation.engine import CorrelatedFinding, CorrelationRule
from usaf.models.finding import Finding
from usaf.models.severity import Severity

logger = logging.getLogger("usaf.correlation.yaml")


class CorrelationRuleYAML(CorrelationRule):
    """A correlation rule loaded from a YAML definition file.

    Supports pattern-based matching against finding fields, reducing
    the need for Python-coded rules for common correlation patterns.
    """

    def __init__(self, rule_def: dict[str, Any]) -> None:
        self.id: str = rule_def["id"]
        self.name: str = rule_def.get("name", self.id)
        self.description: str = rule_def.get("description", "")
        self.severity: Severity = Severity.from_score(rule_def.get("severity_score", 7.5))
        self.requires: list[str] = rule_def.get("requires", [])
        self._conditions = rule_def.get("conditions", [])
        self._output = rule_def.get("output", {})
        self._min_signal_count = rule_def.get("min_signal_count", 2)
        self._tags = rule_def.get("tags", [])
        self._mitre_attack_ids = rule_def.get("mitre_attack_ids", [])
        self._cis_benchmarks = rule_def.get("cis_benchmarks", [])
        self._kill_chain_phases = rule_def.get("kill_chain_phases", [])
        self._temporal_weight: dict[str, Any] = rule_def.get("temporal_weight", {})
        self.kill_chain_phases = self._kill_chain_phases
        self.tags = self._tags

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        matched_signals: list[Finding] = []

        for condition in self._conditions:
            matched = self._match_condition(condition, findings)
            matched_signals.extend(matched)

        if not matched_signals:
            return []

        unique_signals = self._deduplicate(matched_signals)
        if len(unique_signals) < self._min_signal_count:
            return []

        temporal_boost = self._compute_temporal_boost(unique_signals)
        risk_accumulation = 1.0 - (0.5 ** len(unique_signals))

        details: list[str] = []
        seen_check_ids: set[str] = set()
        for f in unique_signals:
            if f.check_id not in seen_check_ids:
                seen_check_ids.add(f.check_id)
                count = sum(1 for sf in unique_signals if sf.check_id == f.check_id)
                details.append(f"{count} finding(s) from {f.check_id}")

        title = self._output.get("title", f"YAML Rule: {self.name}")
        description = self._output.get(
            "description",
            f"Matched {len(unique_signals)} signal(s): {'; '.join(details)}",
        )
        rationale = self._output.get(
            "rationale",
            f"YAML-defined correlation rule '{self.id}' identified a pattern consistent with "
            f"{self.name.lower()}. The presence of {len(unique_signals)} indicators across "
            f"{len(seen_check_ids)} check types increases confidence in this finding.",
        )
        remediation = self._output.get(
            "remediation",
            "1. Review the correlated findings for context\n"
            "2. Investigate each individual signal independently\n"
            "3. Take appropriate remedial action based on the specific findings",
        )

        return [
            self._make_finding(
                finding_id="001",
                title=title,
                description=description,
                rationale=rationale,
                remediation=remediation,
                source_findings=unique_signals,
                severity=self.severity,
                tags=self._tags,
                mitre_attack_ids=self._mitre_attack_ids,
                cis_benchmarks=self._cis_benchmarks,
            )
        ]

    def _match_condition(
        self, condition: dict[str, Any], findings: list[Finding]
    ) -> list[Finding]:
        check_ids = condition.get("check_ids", [])
        evidence_type = condition.get("evidence_type")
        field_matches = condition.get("field_matches", {})
        min_count = condition.get("min_count", 1)

        matched: list[Finding] = []
        for f in findings:
            if check_ids and f.check_id not in check_ids:
                continue
            if evidence_type and not self._evidence_matches_type(f, evidence_type):
                continue
            if field_matches and not self._check_field_matches(f, field_matches):
                continue
            matched.append(f)

        return matched[:max(min_count, len(matched))]

    @staticmethod
    def _evidence_matches_type(finding: Finding, evidence_type: str) -> bool:
        if finding.evidence is None:
            return False
        ev_type = type(finding.evidence).__name__
        return ev_type == evidence_type

    @staticmethod
    def _check_field_matches(
        finding: Finding, field_matches: dict[str, Any]
    ) -> bool:
        for field, pattern in field_matches.items():
            value = getattr(finding, field, None)
            if value is None:
                ev = finding.evidence
                if ev is not None:
                    value = getattr(ev, field, None)
            if value is None:
                return False
            if isinstance(value, str):
                if not fnmatch.fnmatch(value, str(pattern)):
                    return False
            elif isinstance(value, (int, float)):
                if str(value) != str(pattern):
                    return False
                if value != pattern:
                    return False
            elif isinstance(value, list):
                str_value = [str(v) for v in value]
                if isinstance(pattern, str):
                    if not any(fnmatch.fnmatch(v, pattern) for v in str_value):
                        return False
                elif isinstance(pattern, list):
                    if not any(fnmatch.fnmatch(v, p) for v in str_value for p in pattern):
                        return False
        return True

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        seen: set[str] = set()
        result: list[Finding] = []
        for f in findings:
            if f.id not in seen:
                seen.add(f.id)
                result.append(f)
        return result

    def _compute_temporal_boost(self, findings: list[Finding]) -> float:
        if not self._temporal_weight:
            return 0.0
        max_age_hours = float(self._temporal_weight.get("max_age_hours", 0))
        boost_max = float(self._temporal_weight.get("boost_max", 0.0))
        if max_age_hours <= 0 or boost_max <= 0:
            return 0.0
        now = datetime.now(UTC)
        recent_count = 0
        for f in findings:
            age = (now - f.timestamp).total_seconds() / 3600
            if age <= max_age_hours:
                recent_count += 1
        if not findings:
            return 0.0
        ratio = recent_count / len(findings)
        return float(ratio * boost_max)


class YamlRuleLoader:
    """Loads correlation rules from YAML definition files.

    Scans a directory for *.yaml files and converts each into a
    CorrelationRuleYAML instance. This allows security engineers
    to define correlation rules without writing Python code.
    """

    def __init__(self, rules_dir: str | None = None) -> None:
        self.rules_dir = rules_dir or self._default_rules_dir()

    @staticmethod
    def _default_rules_dir() -> str:
        base = os.environ.get(
            "USAF_POLICIES_DIR",
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "..", "..", "policies"),
        )
        return os.path.join(base, "correlation")

    def load_all(self) -> list[CorrelationRuleYAML]:
        rules_dir = self.rules_dir
        if not os.path.isdir(rules_dir):
            logger.debug("Correlation rules directory not found: %s", rules_dir)
            return []

        rules: list[CorrelationRuleYAML] = []
        for fname in sorted(os.listdir(rules_dir)):
            if not fname.endswith((".yaml", ".yml")):
                continue
            fpath = os.path.join(rules_dir, fname)
            try:
                with open(fpath) as f:
                    data = yaml.safe_load(f)
                if data is None:
                    continue
                rule_defs = data if isinstance(data, list) else [data]
                for rule_def in rule_defs:
                    if "id" not in rule_def:
                        logger.warning("Skipping YAML rule without 'id' in %s", fname)
                        continue
                    rules.append(CorrelationRuleYAML(rule_def))
                    logger.debug("Loaded YAML correlation rule: %s", rule_def["id"])
            except Exception as e:
                logger.warning("Failed to load correlation rule %s: %s", fname, e)
        return rules
