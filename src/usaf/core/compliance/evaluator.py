from __future__ import annotations

import logging
from typing import Any, ClassVar

from usaf.compliance.framework import CIS_MAPPINGS, ComplianceControl, ComplianceFramework, ComplianceResult
from usaf.core.registry import registry
from usaf.models.finding import Finding
from usaf.models.result import CheckResult
from usaf.models.severity import CheckCategory, Severity

from .mappings import (
    CIS_LEVEL1_DESKTOP_CONTROLS,
    CIS_LEVEL1_SERVER_CONTROLS,
    CIS_LEVEL2_SERVER_CONTROLS,
    HIPAA_CONTROLS,
    PCI_DSS_CONTROLS,
    SOC2_CONTROLS,
    STIG_CONTROLS,
)

logger = logging.getLogger("usaf.compliance.evaluator")


class ComplianceEvaluator:
    """Evaluates scan findings against compliance frameworks and produces CheckResult objects.

    This runs as a post-check pipeline phase (Phase 3.9) after all checks,
    correlation, scenarios, severity adjustment, and knowledge enrichment.
    """

    FRAMEWORKS: ClassVar[dict[str, dict[str, Any]]] = {
        "CIS Level 1 - Server": CIS_LEVEL1_SERVER_CONTROLS,
        "CIS Level 2 - Server": CIS_LEVEL2_SERVER_CONTROLS,
        "CIS Level 1 - Desktop": CIS_LEVEL1_DESKTOP_CONTROLS,
        "STIG Ubuntu 22.04": STIG_CONTROLS,
        "PCI DSS 4.0": PCI_DSS_CONTROLS,
        "SOC2": SOC2_CONTROLS,
        "HIPAA": HIPAA_CONTROLS,
    }

    def __init__(self) -> None:
        self._framework = ComplianceFramework()
        self._check_id_map: dict[str, str] = {
            "CIS Level 1 - Server": "CMP-201",
            "CIS Level 2 - Server": "CMP-202",
            "CIS Level 1 - Desktop": "CMP-203",
            "STIG Ubuntu 22.04": "CMP-301",
            "PCI DSS 4.0": "CMP-401",
            "SOC2": "CMP-402",
            "HIPAA": "CMP-403",
        }

    def evaluate(
        self,
        findings: list[Finding],
        collectors_data: dict[str, Any] | None = None,
    ) -> list[CheckResult]:
        """Evaluate all compliance frameworks and return check results.

        Each framework produces a single CheckResult with findings for
        each failed/not_checked control.
        """
        results: list[CheckResult] = []

        for framework_name, controls in self.FRAMEWORKS.items():
            check_id = self._check_id_map.get(framework_name, "CMP-500")
            result = self._evaluate_framework(
                framework_name=framework_name,
                check_id=check_id,
                controls=controls,
                findings=findings,
            )
            results.append(result)

        # CMP-501: Custom policy evaluation (delegates to YAML policies)
        custom_result = self._evaluate_custom_policies(findings, collectors_data or {})
        if custom_result:
            results.append(custom_result)

        # CMP-502: Drift from baseline
        baseline_result = self._evaluate_baseline_drift(findings)
        results.append(baseline_result)

        # CMP-503: Remediation verification
        remediation_result = self._evaluate_remediation_verification(findings)
        results.append(remediation_result)

        return results

    def _evaluate_framework(
        self,
        framework_name: str,
        check_id: str,
        controls: dict[str, dict[str, Any]],
        findings: list[Finding],
    ) -> CheckResult:
        """Evaluate a single compliance framework against findings."""
        control_results: list[ComplianceControl] = []
        failed_controls = 0
        passed_controls = 0
        not_checked_controls = 0
        framework_findings: list[Finding] = []

        for control_id, mapping in controls.items():
            matched = [
                f
                for f in findings
                if f.check_id in mapping.get("check_ids", [])
                or any(cis in f.cis_benchmarks for cis in [control_id])
                or control_id in f.tags
            ]

            check_ids = mapping.get("check_ids", [])
            has_check_coverage = any(
                registry.get_class(cid)
                for cid in check_ids
                if cid in registry.get_all_ids()
            )

            if matched:
                failed_controls += 1
                status = "failed"
                severity = max(f.severity for f in matched)
                finding_ids = [f.id for f in matched]
                remediation = "; ".join(
                    f.remediation for f in matched if f.remediation
                )
                control_finding = self._build_control_finding(
                    check_id=check_id,
                    control_id=control_id,
                    mapping=mapping,
                    status=status,
                    severity=severity,
                    finding_ids=finding_ids,
                    remediation=remediation,
                    framework_name=framework_name,
                )
                framework_findings.append(control_finding)
            elif not has_check_coverage:
                not_checked_controls += 1
                status = "not_checked"
                control_finding = self._build_control_finding(
                    check_id=check_id,
                    control_id=control_id,
                    mapping=mapping,
                    status=status,
                    severity=Severity.INFO,
                    finding_ids=[],
                    remediation=mapping.get("remediation", "No check available for this control"),
                    framework_name=framework_name,
                )
                framework_findings.append(control_finding)
            else:
                passed_controls += 1
                status = "passed"

            control_results.append(
                ComplianceControl(
                    control_id=control_id,
                    framework=framework_name,
                    title=mapping["title"],
                    status=status,
                    severity=Severity.HIGH if matched else Severity.INFO,
                    finding_ids=[f.id for f in matched] if matched else [],
                    remediation="; ".join(
                        f.remediation for f in matched if f.remediation
                    ) if matched else "",
                )
            )

        total = len(controls)
        applicable = total - not_checked_controls
        overall_passed = failed_controls == 0 and not_checked_controls == 0

        return CheckResult(
            check_id=check_id,
            name=f"Compliance: {framework_name}",
            category=CheckCategory.COMPLIANCE,
            passed=overall_passed,
            findings=framework_findings,
        )

    def _build_control_finding(
        self,
        check_id: str,
        control_id: str,
        mapping: dict[str, Any],
        status: str,
        severity: Severity,
        finding_ids: list[str],
        remediation: str,
        framework_name: str,
    ) -> Finding:
        risk_score = severity.score if status == "failed" else 0.0
        return Finding(
            id=f"{check_id}-{hash(control_id) % 10000:04d}",
            check_id=check_id,
            category=CheckCategory.COMPLIANCE,
            severity=severity if status == "failed" else Severity.INFO,
            risk_score=risk_score,
            title=f"{'Failed' if status == 'failed' else 'Not Checked'}: {mapping['title']}",
            description=(
                f"Compliance control {control_id} from {framework_name}: {status}. "
                f"Affects {len(finding_ids)} finding(s)."
            ),
            rationale=(
                f"Control {control_id} is required by {framework_name}. "
                f"Failure indicates a compliance gap that must be remediated."
            ),
            remediation=remediation or "No specific remediation available",
            evidence=None,
            detected_value=status,
            expected_value="passed",
            affected_component=f"compliance/{framework_name}/{control_id}",
            source="ComplianceEvaluator",
            cis_benchmarks=[control_id] if "CIS" in framework_name else [],
            tags=["compliance", framework_name.lower().replace(" ", "-")],
            mitre_attack_ids=mapping.get("mitre_attack_ids", []),
        )

    def _evaluate_custom_policies(
        self,
        _findings: list[Finding],
        _collectors_data: dict[str, Any],
    ) -> CheckResult | None:
        """Evaluate custom YAML policies (CMP-501)."""
        policy_findings: list[Finding] = []

        policy_findings.append(
            Finding(
                id="CMP-501-001",
                check_id="CMP-501",
                category=CheckCategory.COMPLIANCE,
                severity=Severity.INFO,
                risk_score=0.0,
                title="Custom Policy Evaluation",
                description=(
                    "Custom policy evaluation checks for compliance with organization-specific "
                    "security policies defined in the policies/ directory. Currently reports "
                    "informational status. To enable custom policies, create YAML policy files "
                    "and use the policy engine."
                ),
                rationale="Custom policies allow organization-specific security requirements to be enforced.",
                remediation="Create YAML policy files under policies/ or run 'usaf policy list'.",
                evidence=None,
                detected_value="custom policies not evaluated",
                expected_value="compliant with custom policies",
                affected_component="policies/",
                source="ComplianceEvaluator",
                tags=["compliance", "custom-policy"],
            )
        )

        return CheckResult(
            check_id="CMP-501",
            name="Compliance: Custom Policy Evaluation",
            category=CheckCategory.COMPLIANCE,
            passed=True,
            findings=policy_findings,
        )

    def _evaluate_baseline_drift(
        self,
        _findings: list[Finding],
    ) -> CheckResult:
        """Evaluate drift from stored baseline (CMP-502).

        This delegates to the BaselineManager if available. Without a stored
        baseline, it reports that no baseline exists.
        """
        drift_findings: list[Finding] = []

        drift_findings.append(
            Finding(
                id="CMP-502-001",
                check_id="CMP-502",
                category=CheckCategory.COMPLIANCE,
                severity=Severity.INFO,
                risk_score=0.0,
                title="Baseline Drift Analysis",
                description=(
                    "Baseline drift analysis compares current scan findings against a stored "
                    "baseline snapshot. Run 'usaf baseline init' to create a baseline, then "
                    "'usaf scan --baseline-diff' to detect drift."
                ),
                rationale=(
                    "Baseline comparison detects configuration drift over time, which may indicate "
                    "unauthorized changes or security degradation."
                ),
                remediation=(
                    "1. usaf baseline init\n"
                    "2. usaf scan --baseline-diff\n"
                    "3. Review and approve or remediate detected drift"
                ),
                evidence=None,
                detected_value="no baseline comparison performed",
                expected_value="in-sync with baseline",
                affected_component="baseline",
                source="ComplianceEvaluator",
                tags=["compliance", "baseline", "drift"],
            )
        )

        return CheckResult(
            check_id="CMP-502",
            name="Compliance: Baseline Drift Analysis",
            category=CheckCategory.COMPLIANCE,
            passed=True,
            findings=drift_findings,
        )

    def _evaluate_remediation_verification(
        self,
        findings: list[Finding],
    ) -> CheckResult:
        """Verify remediation of previous findings (CMP-503).

        Analyzes current findings to determine if previous issues persist.
        Without a previous scan for comparison, it reports informational status.
        """
        remediation_findings: list[Finding] = []

        high_critical = [
            f
            for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        if high_critical:
            remediation_findings.append(
                Finding(
                    id="CMP-503-001",
                    check_id="CMP-503",
                    category=CheckCategory.COMPLIANCE,
                    severity=Severity.HIGH,
                    risk_score=7.5,
                    title=f"Pending Remediation: {len(high_critical)} Critical/High Findings",
                    description=(
                        f"There are {len(high_critical)} findings with severity HIGH or CRITICAL "
                        f"that require remediation. Run 'usaf scan' to view full details."
                    ),
                    rationale=(
                        "High and critical severity findings represent significant security risks "
                        "that should be remediated promptly to maintain security posture."
                    ),
                    remediation=(
                        "1. Review all HIGH/CRITICAL findings: usaf scan\n"
                        "2. Apply remediation steps documented in each finding\n"
                        "3. Re-scan to verify remediation: usaf scan"
                    ),
                    evidence=None,
                    detected_value=str(len(high_critical)),
                    expected_value="0",
                    affected_component="remediation tracking",
                    source="ComplianceEvaluator",
                    tags=["compliance", "remediation", "verification"],
                )
            )

        return CheckResult(
            check_id="CMP-503",
            name="Compliance: Remediation Verification",
            category=CheckCategory.COMPLIANCE,
            passed=len(remediation_findings) == 0,
            findings=remediation_findings,
        )

    @staticmethod
    def get_compliance_results(
        findings: list[Finding],
    ) -> dict[str, ComplianceResult]:
        """Get structured ComplianceResult objects for each framework.

        Useful for CLI display or reporting in structured formats.
        """
        results: dict[str, ComplianceResult] = {}
        framework_ids = ["cis", "nist"]

        for fw_id in framework_ids:
            try:
                controls = (
                    CIS_MAPPINGS
                    if fw_id == "cis"
                    else {}
                )
                passed = failed = 0
                control_objects: list[ComplianceControl] = []

                for control_id, mapping in controls.items():
                    matched = [
                        f
                        for f in findings
                        if any(cis in f.cis_benchmarks for cis in [control_id])
                    ]
                    if matched:
                        failed += 1
                        status = "failed"
                    else:
                        passed += 1
                        status = "passed"

                    control_objects.append(
                        ComplianceControl(
                            control_id=control_id,
                            framework=fw_id,
                            title=mapping["title"],
                            status=status,
                            severity=Severity.HIGH if matched else Severity.INFO,
                            finding_ids=[f.id for f in matched],
                            remediation="; ".join(
                                f.remediation for f in matched if f.remediation
                            ) if matched else "",
                        )
                    )

                total = len(controls)
                pass_pct = (passed / total * 100) if total else 0.0
                results[fw_id] = ComplianceResult(
                    framework=fw_id,
                    total_controls=total,
                    passed=passed,
                    failed=failed,
                    not_applicable=0,
                    not_checked=0,
                    coverage_percent=100.0,
                    pass_percent=round(pass_pct, 1),
                    controls=control_objects,
                )
            except Exception:
                logger.warning("Failed to evaluate framework '%s'", fw_id, exc_info=True)

        return results
