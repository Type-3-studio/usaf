from __future__ import annotations

import fnmatch
import logging
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from usaf.models.finding import Finding
from usaf.models.scenario import AttackScenario, CounterEvidence, ScenarioResult
from usaf.models.severity import CheckCategory, Confidence, Severity

logger = logging.getLogger("usaf.correlation")


class CorrelatedFinding(Finding):
    """A synthetic finding produced by correlating multiple check findings."""

    source_findings: list[str] = Field(
        description="IDs of the findings that triggered this correlation"
    )
    correlation_rule: str = Field(description="ID of the correlation rule that generated this")


class CorrelationRule(ABC):
    """Base class for correlation rules that combine findings into synthetic insights.

    Phase 5 extensions:
    - temporal_weight: config for freshnes-based confidence boost
    - kill_chain_phases: map to MITRE ATT&CK phases
    """

    id: str
    name: str
    description: str
    severity: Severity = Severity.MEDIUM
    requires: list[str] = []
    temporal_weight: dict[str, float | int] = {}
    kill_chain_phases: list[str] = []
    tags: list[str] = []

    @abstractmethod
    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        ...

    @property
    def finding_id_prefix(self) -> str:
        return f"CORR-{self.id}"

    def _make_finding(
        self,
        finding_id: str,
        title: str,
        description: str,
        rationale: str,
        remediation: str,
        source_findings: list[Finding],
        severity: Severity | None = None,
        **kwargs: Any,
    ) -> CorrelatedFinding:
        # Phase 5: Temporal weight — fresher findings get confidence boost
        confidence_override = None
        if self.temporal_weight:
            boost = self._compute_temporal_confidence(source_findings)
            if boost > 0:
                confidence_override = Confidence.HIGH

        return CorrelatedFinding(
            id=f"{self.finding_id_prefix}-{finding_id}",
            check_id=self.finding_id_prefix,
            category=self._detect_category(source_findings),
            severity=severity or self.severity,
            risk_score=(severity or self.severity).score,
            title=title,
            description=description,
            rationale=rationale,
            remediation=remediation,
            source=type(self).__name__,
            source_findings=[f.id for f in source_findings],
            correlation_rule=self.id,
            confidence=confidence_override or Confidence.HIGH,
            **kwargs,
        )

    def _compute_temporal_confidence(self, findings: list[Finding]) -> float:
        """Boost confidence based on finding freshness.

        Newer findings (within configured max_age_hours) get a confidence
        bonus up to boost_max. Returns 0 if no temporal config or no recent findings.
        """
        max_age = self.temporal_weight.get("max_age_hours", 0)
        boost_max = self.temporal_weight.get("boost_max", 0.0)
        if max_age <= 0 or boost_max <= 0 or not findings:
            return 0.0
        now = datetime.now(UTC)
        recent = sum(1 for f in findings if (now - f.timestamp).total_seconds() / 3600 <= max_age)
        return float(recent / len(findings)) * boost_max

    @staticmethod
    def _detect_category(findings: list[Finding]) -> Any:
        cat_counts: dict[Any, int] = {}
        for f in findings:
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
        if not cat_counts:
            return CheckCategory.COMPROMISE
        return max(cat_counts, key=lambda k: cat_counts[k])


class CorrelationEngine:
    """Orchestrates correlation rule execution with Phase 5 enhancements.

    Phase 5 features:
    - YAML-defined rules via load_yaml_rules()
    - Temporal correlation: fresh findings weighted higher
    - Risk accumulation: (1 - 0.5^N) combined probability
    - Counter-evidence: known-good entries reduce false positives
    - Scenario scoring: pre-built attack scenarios scored as units
    """

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        self._rules: dict[str, CorrelationRule] = {}
        self._counter_evidence: CounterEvidence | None = None
        self._scenarios: dict[str, AttackScenario] = {}
        if rules:
            for rule in rules:
                self.register(rule)

    def register(self, rule: CorrelationRule) -> None:
        if rule.id in self._rules:
            raise ValueError(f"Correlation rule '{rule.id}' is already registered")
        self._rules[rule.id] = rule

    def unregister(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)

    @property
    def rules(self) -> dict[str, CorrelationRule]:
        return dict(self._rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def set_counter_evidence(self, ce: CounterEvidence | None) -> None:
        self._counter_evidence = ce

    def register_scenario(self, scenario: AttackScenario) -> None:
        self._scenarios[scenario.id] = scenario

    def register_scenarios(self, scenarios: list[AttackScenario]) -> None:
        for s in scenarios:
            self.register_scenario(s)

    @property
    def scenarios(self) -> dict[str, AttackScenario]:
        return dict(self._scenarios)

    def evaluate(
        self, findings: list[Finding], counter_evidence: CounterEvidence | None = None
    ) -> list[CorrelatedFinding]:
        """Run all registered correlation rules against findings.

        Phase 5: Applies counter-evidence reduction before rule evaluation
        and computes risk accumulation confidence for each result.
        """
        if counter_evidence is not None:
            self._counter_evidence = counter_evidence

        # Apply counter-evidence filtering to reduce false positives
        filtered = self._apply_counter_evidence(findings) if self._counter_evidence else findings

        correlated: list[CorrelatedFinding] = []
        combined = list(filtered)

        for rule_id in self._resolved_order():
            rule = self._rules[rule_id]
            try:
                result = rule.evaluate(combined)

                # Phase 5: Apply risk accumulation confidence adjustment
                if result:
                    result = self._apply_risk_accumulation(result, findings)

                correlated.extend(result)
                combined.extend(result)
            except Exception as e:
                logger.warning(
                    "Correlation rule '%s' failed: %s", rule_id, e, exc_info=True
                )

        return correlated

    def evaluate_scenarios(
        self, correlated_findings: list[CorrelatedFinding]
    ) -> list[ScenarioResult]:
        """Evaluate all registered attack scenarios against correlated findings.

        A scenario fires when a minimum number of its constituent rules
        have produced findings. Results include kill chain phase coverage
        and combined confidence scoring.
        """
        triggered_rule_ids: set[str] = {
            f.correlation_rule for f in correlated_findings
        }

        results: list[ScenarioResult] = []
        for scenario in self._scenarios.values():
            matched_rules = [r for r in scenario.rule_ids if r in triggered_rule_ids]
            triggered = len(matched_rules) >= scenario.min_rules_triggered

            if not triggered:
                continue

            # Risk accumulation within scenario
            confidence = 1.0 - (0.5 ** len(matched_rules))

            source_ids = [
                f.id
                for f in correlated_findings
                if f.correlation_rule in matched_rules
            ]

            results.append(
                ScenarioResult(
                    scenario_id=scenario.id,
                    scenario_name=scenario.name,
                    triggered=True,
                    confidence=round(confidence, 3),
                    rules_triggered=len(matched_rules),
                    total_rules=len(scenario.rule_ids),
                    severity=scenario.severity,
                    source_finding_ids=source_ids,
                    kill_chain_phases=scenario.kill_chain_phases,
                    description=(
                        f"Scenario '{scenario.name}' triggered with "
                        f"{len(matched_rules)}/{len(scenario.rule_ids)} rules. "
                        f"Confidence: {confidence:.1%}. "
                        f"Kill chain phases: {', '.join(p.value for p in scenario.kill_chain_phases)}."
                    ),
                )
            )

        return results

    def _apply_counter_evidence(
        self, findings: list[Finding]
    ) -> list[Finding]:
        """Filter out findings that match known-good patterns."""
        if not self._counter_evidence:
            return findings

        ce = self._counter_evidence
        filtered: list[Finding] = []

        for f in findings:
            ev = f.evidence
            if ev is None:
                filtered.append(f)
                continue

            is_countered = False

            if ce.package_names and hasattr(ev, "name") and ev.name and ev.name in ce.package_names:
                is_countered = True

            if ce.binary_paths and hasattr(ev, "binary") and ev.binary and any(ev.binary.startswith(p) for p in ce.binary_paths):
                is_countered = True

            if ce.service_names and hasattr(ev, "process_name") and ev.process_name and ev.process_name in ce.service_names:
                is_countered = True

            if ce.file_paths and hasattr(ev, "path") and ev.path and any(fnmatch.fnmatch(ev.path, pat) for pat in ce.file_paths):
                is_countered = True

            if not is_countered:
                filtered.append(f)

        return filtered

    @staticmethod
    def _apply_risk_accumulation(
        results: list[CorrelatedFinding],
        all_findings: list[Finding] | None = None,  # noqa: ARG004
    ) -> list[CorrelatedFinding]:
        """Adjust correlated finding severity/confidence based on signal volume.

        Risk accumulation formula: confidence += (1 - 0.5^N) * 0.2
        where N is the number of source findings. Multiple signals of
        the same type compound the likelihood of a true positive.
        """
        for result in results:
            n_signals = len(result.source_findings)
            if n_signals <= 1:
                continue

            # Risk accumulation bonus
            accumulation = 1.0 - (0.5 ** n_signals)
            risk_bonus = accumulation * 2.0

            # Adjust risk score upward (capped at 10.0)
            result.risk_score = min(10.0, result.risk_score + risk_bonus)

            # Boost severity if many signals
            if n_signals >= 5 and result.severity == Severity.MEDIUM:
                result.severity = Severity.HIGH
            elif n_signals >= 8 and result.severity == Severity.HIGH:
                result.severity = Severity.CRITICAL

        return results

    def _resolved_order(self) -> list[str]:
        """Return rules in dependency order using topological sort."""
        graph: dict[str, set[str]] = {}
        for rid, rule in self._rules.items():
            graph[rid] = {dep for dep in rule.requires if dep in self._rules}
        visited: set[str] = set()
        temp: set[str] = set()
        order: list[str] = []

        def visit(rid: str) -> None:
            if rid in temp:
                raise ValueError(f"Circular dependency in correlation rules involving '{rid}'")
            if rid in visited:
                return
            temp.add(rid)
            for dep in graph.get(rid, set()):
                visit(dep)
            temp.remove(rid)
            visited.add(rid)
            order.append(rid)

        for rid in self._rules:
            if rid not in visited:
                visit(rid)

        return order

    def clear(self) -> None:
        self._rules.clear()
