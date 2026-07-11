from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class AppArmorStatusCheck(AuditCheck):
    id = "SEC-001"
    name = "AppArmor Status"
    category = CheckCategory.SECURITY
    severity = Severity.HIGH
    description = "Checks that AppArmor is enabled, loaded, and in enforcing mode"
    depends = []
    tags = ["security", "apparmor", "mandatory-access-control"]

    def _run_check(self, collectors: dict) -> list:
        findings = []
        enabled_path = Path("/sys/module/apparmor/parameters/enabled")

        if not enabled_path.exists():
            findings.append(
                self.finding(
                    finding_id="001",
                    title="AppArmor is not enabled in the kernel",
                    description="AppArmor kernel module is not loaded",
                    rationale=(
                        "AppArmor provides mandatory access control (MAC) beyond traditional "
                        "Unix permissions. Without it, compromised applications have full access "
                        "to the user's files and resources. Ubuntu ships with AppArmor by default "
                        "and disabling it significantly reduces the security posture."
                    ),
                    remediation=(
                        "Add 'apparmor=1 security=apparmor' to kernel cmdline in /etc/default/grub, "
                        "then 'update-grub' and reboot. Install: 'apt install apparmor apparmor-profiles'."
                    ),
                    evidence=FileEvidence(
                        path=str(enabled_path),
                        content="AppArmor module not loaded in kernel",
                    ),
                    detected_value="AppArmor not enabled",
                    expected_value="AppArmor enabled and enforcing",
                    affected_component="kernel (AppArmor LSM)",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1562"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.6"],
                    tags=["mac", "apparmor", "hardening"],
                )
            )
            return findings

        enabled = enabled_path.read_text().strip()
        if enabled == "Y":
            return findings

        findings.append(
            self.finding(
                finding_id="002",
                title="AppArmor is loaded but not enforcing",
                description=f"AppArmor enabled={enabled} (expected Y)",
                rationale=(
                    "AppArmor is compiled into the kernel but not enforcing any policies. "
                    "The LSM (Linux Security Module) is present but inactive, providing no "
                    "additional security controls over the default discretionary access control."
                ),
                remediation=(
                    "Ensure 'security=apparmor' is in the kernel cmdline. "
                    "Set 'apparmor=1' in /etc/default/grub, run 'update-grub', and reboot."
                ),
                evidence=FileEvidence(
                    path=str(enabled_path),
                    content=f"enabled={enabled}",
                ),
                detected_value=f"AppArmor enabled={enabled}",
                expected_value="AppArmor enabled=Y",
                affected_component=str(enabled_path),
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1562"],
                cis_benchmarks=["CIS Ubuntu 20.04: 1.6"],
                tags=["mac", "apparmor", "hardening"],
            )
        )
        return findings
