from usaf.correlation.rules import (
    CloudCompromiseRule,
    ComplianceGapRule,
    PriorityRemediationRule,
)
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Severity


def _make_finding(
    check_id: str = "CLD-301",
    finding_id: str = "001",
    severity: Severity = Severity.HIGH,
    tags: list[str] | None = None,
    cis_benchmarks: list[str] | None = None,
) -> Finding:
    return Finding(
        id=f"{check_id}-{finding_id}",
        check_id=check_id,
        category=CheckCategory.CLOUD,
        severity=severity,
        risk_score=severity.score,
        title=f"Test finding for {check_id}",
        description=f"A test finding from {check_id}",
        rationale="Testing rationale",
        remediation="Fix it",
        source="test",
        tags=tags or ["test"],
        cis_benchmarks=cis_benchmarks or [],
        mitre_attack_ids=[],
    )


class TestCloudCompromiseRule:
    def test_does_not_fire_without_creds(self):
        rule = CloudCompromiseRule()
        findings = [
            _make_finding("CLD-101"),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 0

    def test_does_not_fire_without_metadata(self):
        rule = CloudCompromiseRule()
        findings = [
            _make_finding("CLD-301"),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 0

    def test_fires_with_creds_and_metadata(self):
        rule = CloudCompromiseRule()
        findings = [
            _make_finding("CLD-301"),
            _make_finding("CLD-101"),
        ]
        result = rule.evaluate(findings)
        assert len(result) >= 1
        assert result[0].severity == Severity.CRITICAL

    def test_fires_with_creds_metadata_and_network(self):
        rule = CloudCompromiseRule()
        findings = [
            _make_finding("CLD-301"),
            _make_finding("CLD-101"),
            _make_finding("NET-101"),
        ]
        result = rule.evaluate(findings)
        assert len(result) >= 1
        assert "Cloud" in result[0].title

    def test_mitre_mappings_present(self):
        rule = CloudCompromiseRule()
        findings = [
            _make_finding("CLD-301"),
            _make_finding("CLD-101"),
        ]
        result = rule.evaluate(findings)
        assert "T1552.005" in result[0].mitre_attack_ids

    def test_correct_id(self):
        assert CloudCompromiseRule.id == "CORR-601"


class TestComplianceGapRule:
    def test_does_not_fire_without_findings(self):
        rule = ComplianceGapRule()
        result = rule.evaluate([])
        assert len(result) == 0

    def test_does_not_fire_with_few_cis_failures(self):
        rule = ComplianceGapRule()
        findings = [
            _make_finding("CMP-201", severity=Severity.HIGH),
            _make_finding("CMP-201", finding_id="002", severity=Severity.MEDIUM),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 0

    def test_fires_with_many_cis_failures(self):
        rule = ComplianceGapRule()
        findings = [
            _make_finding("CMP-201", finding_id=str(i), severity=Severity.HIGH)
            for i in range(12)
        ]
        result = rule.evaluate(findings)
        assert len(result) >= 1
        assert result[0].severity == Severity.CRITICAL

    def test_fires_with_cis_and_firewall(self):
        rule = ComplianceGapRule()
        findings = [
            _make_finding("CMP-201", finding_id=str(i), severity=Severity.HIGH)
            for i in range(6)
        ]
        findings.append(_make_finding("FW-101"))
        result = rule.evaluate(findings)
        assert len(result) >= 1

    def test_fires_with_cis_and_audit(self):
        rule = ComplianceGapRule()
        findings = [
            _make_finding("CMP-201", finding_id=str(i), severity=Severity.HIGH)
            for i in range(6)
        ]
        findings.append(_make_finding("FOR-101"))
        result = rule.evaluate(findings)
        assert len(result) >= 1

    def test_correct_id(self):
        assert ComplianceGapRule.id == "CORR-602"


class TestPriorityRemediationRule:
    def test_does_not_fire_without_compliance_findings(self):
        rule = PriorityRemediationRule()
        result = rule.evaluate([])
        assert len(result) == 0

    def test_does_not_fire_with_few_findings(self):
        rule = PriorityRemediationRule()
        findings = [
            _make_finding("CMP-201", tags=["compliance", "cis"]),
            _make_finding("CMP-301", tags=["compliance", "stig"]),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 0

    def test_fires_with_multi_framework_failures(self):
        rule = PriorityRemediationRule()
        finding_201 = _make_finding(
            "CMP-201",
            tags=["compliance", "cis-level-1"],
            cis_benchmarks=["CIS Ubuntu 22.04: 5.2.1"],
        )
        finding_301 = _make_finding(
            "CMP-301",
            tags=["compliance", "stig-ubtu"],
            cis_benchmarks=["CIS Ubuntu 22.04: 5.2.1"],
        )
        finding_401 = _make_finding(
            "CMP-401",
            tags=["compliance", "pci-dss"],
            cis_benchmarks=["CIS Ubuntu 22.04: 5.2.1"],
        )
        findings = [
            finding_201,
            finding_301,
            finding_401,
            _make_finding("KERN-101", tags=["kernel"]),
        ]
        result = rule.evaluate(findings)
        assert len(result) >= 1

    def test_correct_id(self):
        assert PriorityRemediationRule.id == "CORR-603"
