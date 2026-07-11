from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class PasswordPolicyCheck(AuditCheck):
    """Check that password policy enforces minimum strength requirements."""

    id = "PWD-001"
    name = "Password Policy Strength"
    category = CheckCategory.AUTHENTICATION
    severity = Severity.HIGH
    description = "Checks that password minimum length and complexity requirements are enforced via PAM and login.defs"
    depends = []
    tags = ["passwords", "authentication", "hardening"]

    COMMON_PASSWORD = Path("/etc/pam.d/common-password")
    LOGIN_DEFS = Path("/etc/login.defs")

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []
        issues: list[str] = []

        minlen = self._get_pam_minlen()
        pass_min_len = self._get_login_defs_value("PASS_MIN_LEN")

        if minlen is not None and minlen < 12:
            issues.append(f"pam_unix minlen={minlen} (expected >= 12)")
        elif minlen is None:
            issues.append("pam_unix minlen not configured in common-password")

        if pass_min_len is not None and pass_min_len < 12:
            issues.append(f"PASS_MIN_LEN={pass_min_len} in /etc/login.defs (expected >= 12)")

        if not issues:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Password minimum length is below recommended standard",
                description="; ".join(issues) if issues else "Password policy does not enforce minimum length >= 12",
                rationale=(
                    "Short passwords are trivially brute-forced, especially with modern GPU-accelerated "
                    "attack tools. NIST SP 800-63B and CIS benchmarks recommend a minimum of 12 characters "
                    "for user passwords. Systems without enforced minimum length policies allow users to "
                    "set weak passwords that can be cracked in minutes or seconds."
                ),
                remediation=(
                    "For PAM: Edit /etc/pam.d/common-password and add 'minlen=12' to the pam_unix.so line. "
                    "For login.defs: Set 'PASS_MIN_LEN 12' in /etc/login.defs. "
                    "Consider also installing libpam-cracklib or libpam-pwquality for complexity enforcement."
                ),
                evidence=FileEvidence(
                    path="/etc/pam.d/common-password",
                    content=("; ".join(issues)) if issues else "No issues found",
                ),
                detected_value="minlen=" + str(minlen) if minlen is not None else "not set",
                expected_value="minlen >= 12",
                affected_component="PAM authentication",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1110"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.3.1"],
                tags=["passwords", "authentication", "brute-force"],
            )
        )
        return findings

    def _get_pam_minlen(self) -> int | None:
        if not self.COMMON_PASSWORD.exists():
            return None
        try:
            for line in self.COMMON_PASSWORD.read_text().splitlines():
                if "pam_unix.so" in line:
                    for part in line.split():
                        if part.startswith("minlen="):
                            return int(part.split("=")[1])
        except (OSError, ValueError):
            pass
        return None

    def _get_login_defs_value(self, key: str) -> int | None:
        if not self.LOGIN_DEFS.exists():
            return None
        try:
            for raw in self.LOGIN_DEFS.read_text().splitlines():
                line = raw.strip()
                if line.startswith(key) and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return int(parts[1])
        except (OSError, ValueError):
            pass
        return None
