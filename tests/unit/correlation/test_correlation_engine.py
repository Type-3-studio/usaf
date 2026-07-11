from __future__ import annotations

import pytest

from usaf.correlation.engine import CorrelatedFinding, CorrelationEngine, CorrelationRule
from usaf.models.evidence import FileEvidence, NetworkEvidence
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Severity


class TestCorrelationEngine:
    def test_empty_findings_returns_empty(self):
        engine = CorrelationEngine()
        result = engine.evaluate([])
        assert result == []

    def test_register_and_evaluate(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleAllMatch())
        findings = [
            _make_finding("TEST-001-001", "test", Severity.HIGH),
        ]
        result = engine.evaluate(findings)
        assert len(result) == 1
        assert result[0].correlation_rule == "TEST-ALL"
        assert "TEST-001-001" in result[0].source_findings

    def test_multiple_rules(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleAllMatch())
        engine.register(_TestRuleNeverMatch())
        findings = [_make_finding("TEST-001-001", "test", Severity.HIGH)]
        result = engine.evaluate(findings)
        assert len(result) == 1

    def test_rule_dependency_order(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleNeverMatch())
        engine.register(_TestRuleRequiresNonExistent())
        # Should not crash, just skip unmatched
        result = engine.evaluate([_make_finding("TEST-001-001", "test", Severity.LOW)])
        assert isinstance(result, list)

    def test_register_duplicate_raises(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleAllMatch())
        with pytest.raises(ValueError, match="already registered"):
            engine.register(_TestRuleAllMatch())

    def test_unregister_removes_rule(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleAllMatch())
        assert engine.rule_count == 1
        engine.unregister("TEST-ALL")
        assert engine.rule_count == 0

    def test_evaluate_produces_correlated_finding(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleAllMatch())
        findings = [_make_finding("TEST-001-001", "test", Severity.CRITICAL)]
        result = engine.evaluate(findings)
        cf = result[0]
        assert isinstance(cf, CorrelatedFinding)
        assert isinstance(cf.source_findings, list)
        assert len(cf.source_findings) == 1
        assert cf.correlation_rule == "TEST-ALL"

    def test_correlated_finding_extends_finding(self):
        cf = CorrelatedFinding(
            id="CORR-TEST-001",
            check_id="CORR-TEST",
            category=CheckCategory.COMPROMISE,
            severity=Severity.CRITICAL,
            risk_score=10.0,
            title="Test",
            description="Test",
            rationale="Test rationale",
            remediation="Test remediation",
            source="TestSource",
            source_findings=["SSH-001-001", "NET-001-001"],
            correlation_rule="SSH-BRUTE",
        )
        assert cf.source_findings == ["SSH-001-001", "NET-001-001"]
        assert cf.correlation_rule == "SSH-BRUTE"

    def test_rule_with_no_matches_returns_empty(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleNeverMatch())
        result = engine.evaluate([_make_finding("TEST-001-001", "test", Severity.LOW)])
        assert result == []

    def test_evaluate_with_network_evidence(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleNetworkMatch())
        findings = [
            _make_finding_with_network("NET-001-001", "SSH port", Severity.MEDIUM, 22),
            _make_finding("SSH-001-001", "root login", Severity.HIGH),
        ]
        result = engine.evaluate(findings)
        assert len(result) == 1

    def test_clear_removes_all_rules(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleAllMatch())
        engine.register(_TestRuleNeverMatch())
        assert engine.rule_count == 2
        engine.clear()
        assert engine.rule_count == 0

    def test_rules_property_returns_copy(self):
        engine = CorrelationEngine()
        engine.register(_TestRuleAllMatch())
        rules = engine.rules
        assert "TEST-ALL" in rules
        rules["NEW"] = _TestRuleNeverMatch()  # type: ignore[assignment]
        assert "NEW" not in engine.rules


class _TestRuleAllMatch(CorrelationRule):
    id = "TEST-ALL"
    name = "Test: All match"
    description = "Matches every finding"
    severity = Severity.HIGH

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        if not findings:
            return []
        return [
            self._make_finding(
                finding_id="001",
                title="All match result",
                description="All findings matched",
                rationale="Testing",
                remediation="None",
                source_findings=findings,
                severity=Severity.HIGH,
            )
        ]


class _TestRuleNeverMatch(CorrelationRule):
    id = "TEST-NEVER"
    name = "Test: Never match"
    description = "Never returns findings"
    severity = Severity.LOW

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        return []


class _TestRuleRequiresNonExistent(CorrelationRule):
    id = "TEST-REQUIRES"
    name = "Test: Requires"
    description = "Requires non-existent rule"
    severity = Severity.MEDIUM
    requires = ["NONEXISTENT"]

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        return []


class _TestRuleNetworkMatch(CorrelationRule):
    id = "TEST-NET"
    name = "Test: Network match"
    description = "Matches SSH + network findings"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        ssh = [f for f in findings if f.check_id.startswith("SSH-")]
        net = [f for f in findings if f.check_id.startswith("NET-")]
        if ssh and net:
            return [
                self._make_finding(
                    finding_id="001",
                    title="SSH + Network",
                    description="Combined SSH and network finding",
                    rationale="Test",
                    remediation="None",
                    source_findings=ssh + net,
                    severity=Severity.CRITICAL,
                )
            ]
        return []


def _make_finding(finding_id: str, title: str, severity: Severity) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.SECURITY,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test finding",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
    )


def _make_finding_with_network(
    finding_id: str, title: str, severity: Severity, port: int
) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.NETWORK,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test network finding",
        rationale="Test rationale",
        remediation="Test remediation",
        source="TestCheck",
        evidence=NetworkEvidence(
            protocol="tcp",
            local_address="0.0.0.0",
            local_port=port,
            state="LISTEN",
        ),
    )
