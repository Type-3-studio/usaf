from __future__ import annotations

from usaf.models.evidence import ProcessEvidence
from usaf.models.finding import Finding
from usaf.models.result import CheckResult, ScanMetadata, ScanResult
from usaf.models.severity import CheckCategory, Confidence, Severity
from usaf.scoring.engine import ScoringEngine
from usaf.scoring.trust import TrustScorer


class TestScoringPipeline:
    """Integration tests for the scoring pipeline."""

    def test_empty_scan_result(self):
        result = ScanResult()
        engine = ScoringEngine()
        score = engine.calculate(result)
        assert score.overall_score == 0.0
        assert score.overall_grade == "A+"

    def test_single_low_risk_finding(self):
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[
                CheckResult(
                    check_id="LOW-001",
                    name="Low Risk",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="LOW-001-001",
                            check_id="LOW-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.LOW,
                            risk_score=2.5,
                            title="Low finding",
                            description="Minor issue",
                            rationale="Not critical",
                            remediation="Fix later",
                            source="Test",
                        ),
                    ],
                ),
            ],
        )
        engine = ScoringEngine()
        score = engine.calculate(result)
        assert score.overall_score > 0.0
        assert score.low_count == 1

    def test_multiple_severities_accumulate(self):
        severity_risk = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
        }
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[
                CheckResult(
                    check_id="MIX-001",
                    name="Mixed findings",
                    category=CheckCategory.SECURITY,
                    passed=False,
                    findings=[
                        Finding(
                            id=f"MIX-001-{i:03d}",
                            check_id="MIX-001",
                            category=CheckCategory.SECURITY,
                            severity=sev,
                            risk_score=severity_risk[sev],
                            title=sev.value,
                            description="Test",
                            rationale="Test",
                            remediation="Test",
                            source="Test",
                        )
                        for i, sev in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO])
                    ],
                ),
            ],
        )
        engine = ScoringEngine()
        score = engine.calculate(result)
        assert score.total_findings == 5
        assert score.critical_count == 1
        assert score.high_count == 1
        assert score.medium_count == 1
        assert score.low_count == 1
        assert score.info_count == 1

    def test_confidence_reduces_score(self):
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[
                CheckResult(
                    check_id="CONF-001",
                    name="Confidence test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="CONF-001-001",
                            check_id="CONF-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.HIGH,
                            risk_score=7.5,
                            title="High confidence",
                            description="Test",
                            rationale="Test",
                            remediation="Test",
                            source="Test",
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.0,
                        ),
                    ],
                ),
            ],
        )
        engine = ScoringEngine()
        score = engine.calculate(result)
        high_conf_score = score.overall_score

        result_low_conf = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[
                CheckResult(
                    check_id="CONF-002",
                    name="Confidence test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="CONF-002-001",
                            check_id="CONF-002",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.HIGH,
                            risk_score=7.5,
                            title="Low confidence",
                            description="Test",
                            rationale="Test",
                            remediation="Test",
                            source="Test",
                            confidence=Confidence.LOW,
                            false_positive_probability=0.5,
                        ),
                    ],
                ),
            ],
        )
        low_conf_score = engine.calculate(result_low_conf)
        assert low_conf_score.overall_score < high_conf_score

    def test_trust_scoring(self):
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[
                CheckResult(
                    check_id="TRUST-001",
                    name="Trust test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="TRUST-001-001",
                            check_id="TRUST-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.HIGH,
                            risk_score=7.5,
                            title="With evidence",
                            description="Test",
                            rationale="Test",
                            remediation="Test",
                            source="Test",
                            evidence=ProcessEvidence(
                                pid=1234, name="test", binary="/usr/bin/test"
                            ),
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.2,
                        ),
                    ],
                ),
            ],
        )
        scorer = TrustScorer()
        trust_scores = scorer.score_many(result.findings)
        assert len(trust_scores) == 1
        assert "TRUST-001-001" in trust_scores
        confidence, effective_score = trust_scores["TRUST-001-001"]
        assert effective_score > 0.0

    def test_severity_counts_consistency(self):
        severity_risk = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
        }
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[
                CheckResult(
                    check_id=check_id,
                    name=name,
                    category=CheckCategory.SECURITY,
                    passed=False,
                    findings=[
                        Finding(
                            id=f"{check_id}-001",
                            check_id=check_id,
                            category=CheckCategory.SECURITY,
                            severity=sev,
                            risk_score=severity_risk[sev],
                            title=name,
                            description="Test",
                            rationale="Test",
                            remediation="Test",
                            source="Test",
                        ),
                    ],
                )
                for check_id, name, sev in [
                    ("CRIT-001", "Critical", Severity.CRITICAL),
                    ("HIGH-001", "High", Severity.HIGH),
                    ("MED-001", "Medium", Severity.MEDIUM),
                    ("LOW-001", "Low", Severity.LOW),
                ]
            ],
        )
        engine = ScoringEngine()
        score = engine.calculate(result)
        assert score.total_findings == 4
        assert score.critical_count + score.high_count + score.medium_count + score.low_count == score.total_findings
