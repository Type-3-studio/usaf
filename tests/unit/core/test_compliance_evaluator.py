from usaf.core.compliance.evaluator import ComplianceEvaluator
from usaf.core.compliance.mappings import (
    CIS_LEVEL1_SERVER_CONTROLS,
    CIS_LEVEL2_SERVER_CONTROLS,
    HIPAA_CONTROLS,
    PCI_DSS_CONTROLS,
    SOC2_CONTROLS,
    STIG_CONTROLS,
)
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Severity


def _make_finding(check_id: str, finding_id: str = "001", severity: Severity = Severity.HIGH, cis: list[str] | None = None) -> Finding:
    return Finding(
        id=f"{check_id}-{finding_id}",
        check_id=check_id,
        category=CheckCategory.COMPLIANCE,
        severity=severity,
        risk_score=severity.score,
        title=f"Test finding for {check_id}",
        description="A test finding",
        rationale="Testing",
        remediation="Fix it",
        source="test",
        cis_benchmarks=cis or [],
        tags=[f"test-{check_id.lower()}"],
    )


class TestComplianceEvaluator:
    def test_evaluate_no_findings(self):
        evaluator = ComplianceEvaluator()
        results = evaluator.evaluate([])
        assert len(results) > 0
        # CMP-201 through CMP-403, CMP-501, CMP-502, CMP-503
        assert len(results) >= 7

    def test_cmp201_sees_findings(self):
        evaluator = ComplianceEvaluator()
        findings = [
            _make_finding("KERN-101", severity=Severity.HIGH, cis=["CIS Ubuntu 22.04: 1.5.1"]),
        ]
        results = evaluator.evaluate(findings)
        cmp201 = [r for r in results if r.check_id == "CMP-201"]
        assert len(cmp201) == 1
        # Should find at least the failed ASLR control
        assert len(cmp201[0].findings) >= 1

    def test_cmp202_has_more_controls_than_cmp201(self):
        assert len(CIS_LEVEL2_SERVER_CONTROLS) > len(CIS_LEVEL1_SERVER_CONTROLS)

    def test_stig_controls_defined(self):
        assert len(STIG_CONTROLS) >= 10

    def test_pci_dss_controls_defined(self):
        assert len(PCI_DSS_CONTROLS) >= 10

    def test_soc2_controls_defined(self):
        assert len(SOC2_CONTROLS) >= 10

    def test_hipaa_controls_defined(self):
        assert len(HIPAA_CONTROLS) >= 10

    def test_cmp502_baseline_not_available(self):
        evaluator = ComplianceEvaluator()
        results = evaluator.evaluate([])
        cmp502 = [r for r in results if r.check_id == "CMP-502"]
        assert len(cmp502) == 1
        assert cmp502[0].passed is True

    def test_cmp503_remediation_needed(self):
        evaluator = ComplianceEvaluator()
        findings = [
            _make_finding("KERN-101", severity=Severity.HIGH),
            _make_finding("SSH-101", severity=Severity.CRITICAL),
        ]
        results = evaluator.evaluate(findings)
        cmp503 = [r for r in results if r.check_id == "CMP-503"]
        assert len(cmp503) == 1
        assert cmp503[0].passed is False
        assert len(cmp503[0].findings) >= 1

    def test_cmp503_passes_when_no_high_critical(self):
        evaluator = ComplianceEvaluator()
        findings = [
            _make_finding("KERN-101", severity=Severity.INFO),
        ]
        results = evaluator.evaluate(findings)
        cmp503 = [r for r in results if r.check_id == "CMP-503"]
        assert cmp503[0].passed is True

    def test_evaluator_check_ids(self):
        evaluator = ComplianceEvaluator()
        assert evaluator._check_id_map["CIS Level 1 - Server"] == "CMP-201"
        assert evaluator._check_id_map["CIS Level 2 - Server"] == "CMP-202"
        assert evaluator._check_id_map["CIS Level 1 - Desktop"] == "CMP-203"
        assert evaluator._check_id_map["STIG Ubuntu 22.04"] == "CMP-301"
        assert evaluator._check_id_map["PCI DSS 4.0"] == "CMP-401"
        assert evaluator._check_id_map["SOC2"] == "CMP-402"
        assert evaluator._check_id_map["HIPAA"] == "CMP-403"

    def test_get_compliance_results(self):
        findings = [
            _make_finding("KERN-101", severity=Severity.HIGH, cis=["CIS Ubuntu 22.04: 1.5.1"]),
        ]
        results = ComplianceEvaluator.get_compliance_results(findings)
        assert "cis" in results
        assert results["cis"].total_controls > 0
