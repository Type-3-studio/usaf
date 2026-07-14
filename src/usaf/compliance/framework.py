from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from usaf.core.registry import registry
from usaf.models.finding import Finding
from usaf.models.result import ScanResult
from usaf.models.severity import Severity


class ComplianceControl(BaseModel):
    """A single compliance control mapping."""

    control_id: str = Field(description="The compliance control identifier")
    framework: str = Field(description="The compliance framework (CIS, NIST, PCI, etc.)")
    title: str = Field(description="Control description")
    status: str = Field(description="passed, failed, not_applicable, not_checked")
    severity: Severity = Field(default=Severity.INFO)
    finding_ids: list[str] = Field(default_factory=list, description="Finding IDs mapped to this control")
    remediation: str = Field(default="", description="Remediation steps for this control")


class ComplianceResult(BaseModel):
    """Result of a compliance framework evaluation."""

    framework: str = Field(description="Compliance framework name")
    total_controls: int = Field(description="Total controls evaluated")
    passed: int = Field(description="Controls passed")
    failed: int = Field(description="Controls failed")
    not_applicable: int = Field(description="Controls not applicable")
    not_checked: int = Field(description="Controls not checked")
    coverage_percent: float = Field(description="Percentage of controls with check coverage")
    pass_percent: float = Field(description="Percentage of applicable controls passed")
    controls: list[ComplianceControl] = Field(default_factory=list)

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


# Mapping of CIS controls to check IDs and finding patterns
# This provides a structured way to query compliance coverage
CIS_MAPPINGS: dict[str, dict[str, Any]] = {
    "CIS Ubuntu 22.04: 1.1.1": {
        "title": "Ensure mounting of unused filesystems is disabled",
        "check_ids": ["KERN-301"],
    },
    "CIS Ubuntu 22.04: 1.5.1": {
        "title": "Ensure address space layout randomization (ASLR) is enabled",
        "check_ids": ["KERN-101"],
    },
    "CIS Ubuntu 22.04: 1.5.2": {
        "title": "Ensure ptrace_scope is restricted",
        "check_ids": ["KERN-201"],
    },
    "CIS Ubuntu 22.04: 1.5.3": {
        "title": "Ensure core dumps are restricted",
        "check_ids": ["KERN-301"],
    },
    "CIS Ubuntu 22.04: 5.2.1": {
        "title": "Ensure permissions on /etc/ssh/sshd_config are configured",
        "check_ids": ["SSH-101", "SSH-102", "SSH-201"],
    },
    "CIS Ubuntu 22.04: 5.2.2": {
        "title": "Ensure SSH Protocol is set to 2",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.2.3": {
        "title": "Ensure SSH LogLevel is appropriate",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.2.4": {
        "title": "Ensure SSH X11 forwarding is disabled",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.2.5": {
        "title": "Ensure SSH MaxAuthTries is set to 4 or less",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.2.6": {
        "title": "Ensure SSH IgnoreRhosts is enabled",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.2.7": {
        "title": "Ensure SSH HostbasedAuthentication is disabled",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.2.8": {
        "title": "Ensure SSH root login is disabled",
        "check_ids": ["SSH-102"],
    },
    "CIS Ubuntu 22.04: 5.2.9": {
        "title": "Ensure SSH PermitEmptyPasswords is disabled",
        "check_ids": ["SSH-102"],
    },
    "CIS Ubuntu 22.04: 5.2.10": {
        "title": "Ensure SSH PermitUserEnvironment is disabled",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.2.11": {
        "title": "Ensure only approved MAC algorithms are used",
        "check_ids": ["SSH-201"],
    },
    "CIS Ubuntu 22.04: 5.2.12": {
        "title": "Ensure SSH Idle Timeout Interval is configured",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.2.13": {
        "title": "Ensure SSH LoginGraceTime is set to one minute or less",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.2.14": {
        "title": "Ensure SSH warning banner is configured",
        "check_ids": ["SSH-101"],
    },
    "CIS Ubuntu 22.04: 5.4.1": {
        "title": "Ensure password creation requirements are configured",
        "check_ids": ["USR-201"],
    },
    "CIS Ubuntu 22.04: 5.4.2": {
        "title": "Ensure lockout for failed password attempts is configured",
        "check_ids": ["USR-201"],
    },
    "CIS Ubuntu 22.04: 5.5.1": {
        "title": "Ensure password expiration is 365 days or less",
        "check_ids": ["USR-102"],
    },
    "CIS Ubuntu 22.04: 6.1.1": {
        "title": "Ensure permissions on /etc/passwd are configured",
        "check_ids": ["USR-102"],
    },
    "CIS Ubuntu 22.04: 6.1.2": {
        "title": "Ensure permissions on /etc/shadow are configured",
        "check_ids": ["USR-102"],
    },
    "CIS Ubuntu 22.04: 6.1.3": {
        "title": "Ensure permissions on /etc/group are configured",
        "check_ids": ["USR-102"],
    },
    "CIS Ubuntu 22.04: 6.1.4": {
        "title": "Ensure permissions on /etc/gshadow are configured",
        "check_ids": ["USR-102"],
    },
    "CIS Ubuntu 22.04: 6.1.10": {
        "title": "Ensure no duplicate UIDs exist",
        "check_ids": ["USR-101"],
    },
    "CIS Ubuntu 22.04: 6.1.11": {
        "title": "Ensure no duplicate GIDs exist",
        "check_ids": ["USR-101"],
    },
    "CIS Ubuntu 22.04: 6.1.12": {
        "title": "Ensure no duplicate user names exist",
        "check_ids": ["USR-101"],
    },
    "CIS Ubuntu 22.04: 6.1.13": {
        "title": "Ensure no duplicate group names exist",
        "check_ids": ["USR-101"],
    },
    "CIS Ubuntu 22.04: 6.2.1": {
        "title": "Ensure accounts in /etc/passwd use shadowed passwords",
        "check_ids": ["USR-102"],
    },
    "CIS Ubuntu 22.04: 6.2.2": {
        "title": "Ensure password fields are not empty",
        "check_ids": ["USR-201"],
    },
}

NIST_MAPPINGS: dict[str, dict[str, Any]] = {
    "NIST 800-53: AC-3": {
        "title": "Access Enforcement — enforce approved authorizations",
        "check_ids": ["PRM-101", "PRM-201", "USR-101"],
    },
    "NIST 800-53: AC-6": {
        "title": "Least Privilege — employ least privilege principle",
        "check_ids": ["PRM-101", "USR-101", "USR-201"],
    },
    "NIST 800-53: CM-6": {
        "title": "Configuration Settings — establish and enforce configuration settings",
        "check_ids": ["KERN-101", "KERN-201", "KERN-301", "SSH-101", "SSH-102", "SSH-201"],
    },
    "NIST 800-53: IA-5": {
        "title": "Authenticator Management — manage system authenticators",
        "check_ids": ["USR-201", "USR-102"],
    },
    "NIST 800-53: SC-7": {
        "title": "Boundary Protection — monitor and control communications at boundaries",
        "check_ids": ["NET-101", "NET-201"],
    },
    "NIST 800-53: SI-4": {
        "title": "System Monitoring — monitor, analyze, and protect communications",
        "check_ids": ["NET-201", "PRM-201"],
    },
}


class ComplianceFramework:
    """Queries findings against compliance frameworks (CIS, NIST, PCI, etc.).

    Provides structured gap analysis and coverage reporting,
    leveraging the existing CIS/MITRE/OWASP fields on findings.
    """

    SUPPORTED_FRAMEWORKS: dict[str, dict[str, dict[str, Any]]] = {
        "cis": CIS_MAPPINGS,
        "nist": NIST_MAPPINGS,
    }

    def get_findings_for(
        self, framework_id: str, findings: list[Finding]
    ) -> list[tuple[str, ComplianceControl]]:
        """Get findings that map to a specific compliance framework.

        Returns list of (control_id, ComplianceControl) tuples.
        """
        controls = self._get_controls_for_framework(framework_id)
        result: list[tuple[str, ComplianceControl]] = []

        for control_id, mapping in controls.items():
            matched = [
                f
                for f in findings
                if any(cis in f.cis_benchmarks for cis in [control_id])
                or f.id in mapping.get("check_ids", [])
            ]

            severity = Severity.INFO
            if matched:
                severity = max(f.severity for f in matched)

            control = ComplianceControl(
                control_id=control_id,
                framework=framework_id,
                title=mapping["title"],
                status="failed" if matched else "passed",
                severity=severity,
                finding_ids=[f.id for f in matched],
                remediation="; ".join(f.remediation for f in matched) if matched else "",
            )
            result.append((control_id, control))

        return result

    def get_coverage(self, framework_id: str, result: ScanResult) -> ComplianceResult:
        """Get coverage analysis for a compliance framework across the full scan."""
        controls = self._get_controls_for_framework(framework_id)
        findings = result.findings

        all_controls: list[ComplianceControl] = []
        passed = failed = not_applicable = not_checked = 0
        control_ids_checked: set[str] = set()

        for control_id, mapping in controls.items():
            for check_id in mapping.get("check_ids", []):
                if registry.get_class(check_id):
                    control_ids_checked.add(control_id)

        for control_id, mapping in controls.items():
            matched = [f for f in findings if any(cis in f.cis_benchmarks for cis in [control_id])]

            if control_id not in control_ids_checked and not matched:
                not_checked += 1
                status = "not_checked"
            elif matched:
                failed += 1
                status = "failed"
            else:
                passed += 1
                status = "passed"

            severity = Severity.INFO
            if matched:
                severity = max(f.severity for f in matched)

            all_controls.append(
                ComplianceControl(
                    control_id=control_id,
                    framework=framework_id,
                    title=mapping["title"],
                    status=status,
                    severity=severity,
                    finding_ids=[f.id for f in matched],
                    remediation="; ".join(f.remediation for f in matched) if matched else "",
                )
            )

        total = len(controls)
        applicable = total - not_applicable - not_checked
        coverage = (len(control_ids_checked) / total * 100) if total else 0.0
        pass_pct = (passed / applicable * 100) if applicable else 0.0

        return ComplianceResult(
            framework=framework_id,
            total_controls=total,
            passed=passed,
            failed=failed,
            not_applicable=not_applicable,
            not_checked=not_checked,
            coverage_percent=round(coverage, 1),
            pass_percent=round(pass_pct, 1),
            controls=all_controls,
        )

    def report_gap_analysis(
        self, framework_id: str, _result: ScanResult
    ) -> dict[str, list[dict[str, str]]]:
        """Identify gaps where CIS/NIST controls have no check coverage."""
        controls = self._get_controls_for_framework(framework_id)
        gaps: list[dict[str, str]] = []
        covered: list[dict[str, str]] = []

        for control_id, mapping in controls.items():
            check_ids = mapping.get("check_ids", [])
            available = [cid for cid in check_ids if cid in registry.get_all_ids()]

            if not available:
                gaps.append({"control": control_id, "title": mapping["title"], "status": "no check coverage"})
            else:
                covered.append({"control": control_id, "title": mapping["title"], "checks": ", ".join(available)})

        return {"covered": covered, "gaps": gaps}

    @staticmethod
    def _get_controls_for_framework(framework_id: str) -> dict[str, dict[str, Any]]:
        fw_lower = framework_id.lower()
        if fw_lower.startswith("cis"):
            return CIS_MAPPINGS
        if fw_lower.startswith("nist"):
            return NIST_MAPPINGS
        raise ValueError(f"Unsupported compliance framework: {framework_id}")
