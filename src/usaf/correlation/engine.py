from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import Field

from usaf.models.finding import Finding
from usaf.models.severity import Severity


class CorrelatedFinding(Finding):
    """A synthetic finding produced by correlating multiple check findings."""

    source_findings: list[str] = Field(
        description="IDs of the findings that triggered this correlation"
    )
    correlation_rule: str = Field(description="ID of the correlation rule that generated this")


class CorrelationRule(ABC):
    """Base class for correlation rules that combine findings into synthetic insights.

    Correlation rules receive all findings from a scan and return either
    an empty list (no correlation) or one or more CorrelatedFinding instances.
    """

    id: str
    name: str
    description: str
    severity: Severity = Severity.MEDIUM
    requires: list[str] = []

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
            **kwargs,
        )

    @staticmethod
    def _detect_category(findings: list[Finding]) -> Any:
        from usaf.models.severity import CheckCategory

        cat_counts: dict[Any, int] = {}
        for f in findings:
            cat_counts[f.category] = cat_counts.get(f.category, 0) + 1
        if not cat_counts:
            return CheckCategory.COMPROMISE
        return max(cat_counts, key=lambda k: cat_counts[k])


class CorrelationEngine:
    """Orchestrates correlation rule execution.

    Runs all registered rules against a set of findings and returns
    any synthetic findings produced. Operates deterministically —
    same findings in → same correlated findings out.
    """

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        self._rules: dict[str, CorrelationRule] = {}
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

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        """Run all registered correlation rules against findings.

        Rules are executed in registration order. Each rule receives the
        complete findings list (including outputs of prior rules) so rules
        can chain — though cross-rule chaining is opt-in via rule ordering.
        """
        correlated: list[CorrelatedFinding] = []
        combined = list(findings)

        for rule_id in self._resolved_order():
            rule = self._rules[rule_id]
            try:
                result = rule.evaluate(combined)
                correlated.extend(result)
                combined.extend(result)
            except Exception:
                pass

        return correlated

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
