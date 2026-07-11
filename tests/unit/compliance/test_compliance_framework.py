from __future__ import annotations

from usaf.compliance.framework import ComplianceFramework, ComplianceResult
from usaf.models.finding import Finding
from usaf.models.result import ScanMetadata, ScanResult
from usaf.models.severity import CheckCategory, Severity


class TestComplianceFramework:
    def test_get_findings_for_cis(self):
        compliance = ComplianceFramework()
        findings = [
            _make_finding_with_cis("SSH-001-001", "protocol", Severity.HIGH, ["CIS Ubuntu 22.04: 5.2.2"]),
        ]
        results = compliance.get_findings_for("cis", findings)
        assert len(results) > 0
        matched = [r for r in results if r[0] == "CIS Ubuntu 22.04: 5.2.2"]
        assert len(matched) == 1
        ctrl = matched[0][1]
        assert ctrl.status == "failed"
        assert "SSH-001-001" in ctrl.finding_ids

    def test_get_findings_for_cis_no_match(self):
        compliance = ComplianceFramework()
        results = compliance.get_findings_for("cis", [])
        assert len(results) > 0  # All controls returned
        # Should all be "passed" since no findings match
        assert all(r[1].status == "passed" for r in results)

    def test_unsupported_framework_raises(self):
        compliance = ComplianceFramework()
        try:
            compliance.get_findings_for("pci", [])
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_get_coverage(self):
        compliance = ComplianceFramework()
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[],
        )
        coverage = compliance.get_coverage("cis", result)
        assert isinstance(coverage, ComplianceResult)
        assert coverage.total_controls > 0
        assert coverage.coverage_percent > 0

    def test_get_coverage_with_findings(self):
        compliance = ComplianceFramework()
        findings = [
            _make_finding_with_cis("SSH-001-001", "protocol", Severity.HIGH, ["CIS Ubuntu 22.04: 5.2.2"]),
            _make_finding_with_cis("KERN-001-001", "aslr", Severity.HIGH, ["CIS Ubuntu 22.04: 1.5.1"]),
        ]
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
            results=[],
            collectors_data={},
        )
        result.results.append(_make_check_result(findings))
        coverage = compliance.get_coverage("cis", result)
        assert coverage.failed >= 2  # At least 2 controls failed
        assert coverage.passed >= 0

    def test_report_gap_analysis(self):
        compliance = ComplianceFramework()
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
        )
        analysis = compliance.report_gap_analysis("cis", result)
        assert "covered" in analysis
        assert "gaps" in analysis
        # At least some CIS controls should have coverage
        assert len(analysis["covered"]) > 0

    def test_controls_have_remediation_when_failed(self):
        compliance = ComplianceFramework()
        findings = [
            _make_finding_with_cis("SSH-001-001", "protocol", Severity.HIGH, ["CIS Ubuntu 22.04: 5.2.2"]),
        ]
        results = compliance.get_findings_for("cis", findings)
        matched = [r for r in results if r[0] == "CIS Ubuntu 22.04: 5.2.2"]
        assert len(matched) == 1
        assert matched[0][1].remediation != ""

    def test_nist_mappings_exist(self):
        compliance = ComplianceFramework()
        controls = compliance._get_controls_for_framework("nist")
        assert len(controls) > 0
        assert "NIST 800-53: CM-6" in controls
        assert controls["NIST 800-53: AC-3"]["title"] != ""

    def test_cis_mappings_exist(self):
        compliance = ComplianceFramework()
        controls = compliance._get_controls_for_framework("cis")
        assert len(controls) > 20  # We have 25+ CIS mappings

    def test_not_checked_controls(self):
        compliance = ComplianceFramework()
        result = ScanResult(
            metadata=ScanMetadata(hostname="test"),
        )
        coverage = compliance.get_coverage("cis", result)
        # Some controls may not be checked by any existing check
        assert coverage.not_checked >= 0


def _make_finding_with_cis(
    finding_id: str, title: str, severity: Severity, cis_benchmarks: list[str]
) -> Finding:
    return Finding(
        id=finding_id,
        check_id=finding_id.rsplit("-", 1)[0],
        category=CheckCategory.SECURITY,
        severity=severity,
        risk_score=severity.score,
        title=title,
        description="Test",
        rationale="Test rationale",
        remediation="Fix the issue",
        source="TestCheck",
        cis_benchmarks=cis_benchmarks,
    )


def _make_check_result(findings: list[Finding]) -> ...:
    from usaf.models.result import CheckResult
    return CheckResult(
        check_id="TEST",
        name="Test check",
        category=CheckCategory.SECURITY,
        passed=len(findings) == 0,
        findings=findings,
    )
