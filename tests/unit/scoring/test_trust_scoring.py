from __future__ import annotations

from usaf.models.evidence import CommandEvidence, FileEvidence, NetworkEvidence, ProcessEvidence
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Confidence, Severity
from usaf.scoring.trust import TrustScorer, adjust_all_trust, adjust_finding_trust


class TestTrustScorer:
    def test_no_evidence_clamps_to_low(self):
        scorer = TrustScorer()
        finding = Finding(
            id="TEST-001",
            check_id="TEST",
            category=CheckCategory.GENERAL,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="Test",
            confidence=Confidence.HIGH,
            evidence=None,
        )
        confidence, effective = scorer.score(finding)
        assert confidence == Confidence.LOW
        assert effective <= 0.3

    def test_file_evidence_boosts_confidence(self):
        scorer = TrustScorer()
        finding = Finding(
            id="TEST-001",
            check_id="TEST",
            category=CheckCategory.GENERAL,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="Test",
            confidence=Confidence.HIGH,
            evidence=FileEvidence(path="/test/file", content="data", permission="0644", owner="root"),
        )
        confidence, effective = scorer.score(finding)
        assert confidence == Confidence.HIGH
        assert effective > 0.8

    def test_network_evidence_medium_boost(self):
        scorer = TrustScorer()
        finding = Finding(
            id="TEST-001",
            check_id="TEST",
            category=CheckCategory.NETWORK,
            severity=Severity.MEDIUM,
            risk_score=5.0,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="Test",
            confidence=Confidence.HIGH,
            evidence=NetworkEvidence(
                protocol="tcp",
                local_address="0.0.0.0",
                local_port=22,
                state="LISTEN",
            ),
        )
        confidence, effective = scorer.score(finding)
        assert effective > 0.5

    def test_command_evidence_small_boost(self):
        scorer = TrustScorer()
        finding = Finding(
            id="TEST-001",
            check_id="TEST",
            category=CheckCategory.GENERAL,
            severity=Severity.MEDIUM,
            risk_score=5.0,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="Test",
            confidence=Confidence.LOW,
            evidence=CommandEvidence(command="test", stdout="ok", exit_code=0),
        )
        confidence, effective = scorer.score(finding)
        # LOW (0.4) + 0.05 = 0.45 -> still LOW
        assert confidence in (Confidence.LOW, Confidence.MEDIUM)

    def test_process_evidence_high_boost(self):
        scorer = TrustScorer()
        finding = Finding(
            id="TEST-001",
            check_id="TEST",
            category=CheckCategory.PROCESSES,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="Test",
            confidence=Confidence.HIGH,
            evidence=ProcessEvidence(pid=1234, name="sshd", binary="/usr/sbin/sshd", user="root"),
        )
        confidence, effective = scorer.score(finding)
        assert confidence == Confidence.HIGH
        assert effective > 0.8

    def test_fp_factor_reduces_effective(self):
        scorer = TrustScorer()
        finding = Finding(
            id="TEST-001",
            check_id="TEST",
            category=CheckCategory.GENERAL,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="Test",
            confidence=Confidence.HIGH,
            false_positive_probability=0.8,
            evidence=FileEvidence(path="/test/file", content="data"),
        )
        confidence, effective = scorer.score(finding)
        # HIGH (1.0) + 0.15 = 1.15, * (1-0.8) = 0.23 -> should be LOW
        assert effective < 0.5

    def test_score_many_returns_dict(self):
        scorer = TrustScorer()
        findings = [
            Finding(
                id="T1",
                check_id="TEST",
                category=CheckCategory.GENERAL,
                severity=Severity.LOW,
                risk_score=2.5,
                title="Test1",
                description="Test",
                rationale="Test",
                remediation="Test",
                source="Test",
                evidence=FileEvidence(path="/a", content="b"),
            ),
            Finding(
                id="T2",
                check_id="TEST",
                category=CheckCategory.GENERAL,
                severity=Severity.LOW,
                risk_score=2.5,
                title="Test2",
                description="Test",
                rationale="Test",
                remediation="Test",
                source="Test",
                evidence=None,
            ),
        ]
        results = scorer.score_many(findings)
        assert len(results) == 2
        assert "T1" in results
        assert "T2" in results

    def test_apply_finding_modifies_in_place(self):
        scorer = TrustScorer()
        finding = Finding(
            id="TEST-001",
            check_id="TEST",
            category=CheckCategory.GENERAL,
            severity=Severity.HIGH,
            risk_score=7.5,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="Test",
            confidence=Confidence.HIGH,
            evidence=None,
        )
        scorer.apply_finding(finding)
        assert finding.confidence == Confidence.LOW

    def test_apply_all_modifies_all(self):
        scorer = TrustScorer()
        findings = [
            Finding(
                id="T1", check_id="TEST", category=CheckCategory.GENERAL,
                severity=Severity.LOW, risk_score=2.5,
                title="T1", description="T", rationale="T", remediation="T",
                source="T", evidence=None, confidence=Confidence.HIGH,
            ),
            Finding(
                id="T2", check_id="TEST", category=CheckCategory.GENERAL,
                severity=Severity.LOW, risk_score=2.5,
                title="T2", description="T", rationale="T", remediation="T",
                source="T", evidence=FileEvidence(path="/a", content="b"),
                confidence=Confidence.LOW,
            ),
        ]
        scorer.apply_all(findings)
        assert findings[0].confidence == Confidence.LOW
        assert findings[1].confidence != Confidence.LOW

    def test_convenience_adjust_finding_trust(self):
        finding = Finding(
            id="TEST-001", check_id="TEST", category=CheckCategory.GENERAL,
            severity=Severity.HIGH, risk_score=7.5,
            title="T", description="T", rationale="T", remediation="T",
            source="T", evidence=None, confidence=Confidence.HIGH,
        )
        result = adjust_finding_trust(finding)
        assert result.confidence == Confidence.LOW

    def test_convenience_adjust_all_trust(self):
        findings = [
            Finding(
                id="T1", check_id="TEST", category=CheckCategory.GENERAL,
                severity=Severity.LOW, risk_score=2.5,
                title="T1", description="T", rationale="T", remediation="T",
                source="T", evidence=None, confidence=Confidence.HIGH,
            ),
        ]
        results = adjust_all_trust(findings)
        assert len(results) == 1
        assert results[0].confidence == Confidence.LOW

    def test_multi_evidence_bonus(self):
        scorer = TrustScorer()
        finding = Finding(
            id="TEST-001", check_id="TEST", category=CheckCategory.GENERAL,
            severity=Severity.HIGH, risk_score=7.5,
            title="T", description="d", rationale="r", remediation="f",
            source="s", confidence=Confidence.HIGH,
            evidence=FileEvidence(
                path="/etc/test", permission="0644", owner="root", group="root",
                size=1024, content="data",
            ),
        )
        confidence, effective = scorer.score(finding)
        assert confidence == Confidence.HIGH
        assert effective > 0.8

    def test_effective_to_confidence_medium(self):
        assert TrustScorer._effective_to_confidence(0.6) == Confidence.MEDIUM

    def test_effective_to_confidence_low(self):
        assert TrustScorer._effective_to_confidence(0.3) == Confidence.LOW

    def test_compute_quality_unknown_type(self):
        from usaf.models.evidence import LogEvidence
        ev = LogEvidence(log_path="/var/log/syslog", lines=[], pattern="fail", match_count=0)
        bonus = TrustScorer._compute_evidence_quality(ev)
        assert bonus == 0.08  # LogEvidence

    def test_convenience_adjust_all_empty(self):
        results = adjust_all_trust([])
        assert results == []
