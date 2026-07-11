from __future__ import annotations

import os
import subprocess
from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, ProcessEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class AppArmorStatusCheck(AuditCheck):
    id = "SEC-101"
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
                    reference="https://ubuntu.com/security/apparmor",
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
                reference="https://ubuntu.com/security/apparmor",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1562"],
                cis_benchmarks=["CIS Ubuntu 20.04: 1.6"],
                tags=["mac", "apparmor", "hardening"],
            )
        )
        return findings


@register_check
class AppArmorServiceCoverageCheck(AuditCheck):
    id = "SEC-102"
    name = "AppArmor Profile Coverage for Services"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Detects running services without an AppArmor profile"
    depends = []
    tags = ["security", "apparmor", "services", "mandatory-access-control"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        if not _is_apparmor_enforcing():
            return findings

        unconfined = self._find_unconfined_services()
        for service_name, pids in sorted(unconfined.items(), key=lambda x: -len(x[1])):
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Service running without AppArmor profile: {service_name}",
                    description=(
                        f"Service '{service_name}' (PID{'s' if len(pids) > 1 else ''} "
                        f"{', '.join(str(p) for p in pids[:5])}"
                        f"{'...' if len(pids) > 5 else ''}) is running unconfined — "
                        f"no AppArmor profile is enforcing."
                    ),
                    rationale=(
                        "Every running service should be confined by an AppArmor profile to limit "
                        "the damage from a potential compromise. Services without profiles run "
                        "with the full privileges of their user, meaning any vulnerability can "
                        "lead to complete system access. AppArmor provides mandatory access "
                        "control that constrains what files, networks, and capabilities a "
                        "service can access even if the application is compromised."
                    ),
                    remediation=(
                        f"Install or create an AppArmor profile for '{service_name}'. "
                        "Check existing profiles: 'ls /etc/apparmor.d/'. "
                        "Install profiles: 'apt install apparmor-profiles apparmor-profiles-extra'. "
                        "Enforce: 'aa-enforce /etc/apparmor.d/<profile>'."
                    ),
                    evidence=ProcessEvidence(
                        pid=pids[0],
                        name=service_name,
                    ),
                    detected_value=f"Service '{service_name}' is unconfined ({len(pids)} processes)",
                    expected_value="Service confined by AppArmor profile",
                    affected_component=f"service:{service_name}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1562"],
                    tags=["apparmor", "mac", "least-privilege"],
                )
            )

        return findings

    @staticmethod
    def _find_unconfined_services() -> dict[str, list[int]]:
        unconfined: dict[str, list[int]] = {}

        try:
            result = subprocess.run(
                ["ps", "axk", "-pid", "--no-headers", "-o", "pid:1,comm:32"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode != 0:
                return unconfined
            for line in result.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) != 2:
                    continue
                pid_str, comm = parts
                if not pid_str.isdigit():
                    continue
                pid = int(pid_str)

                attr_path = f"/proc/{pid}/attr/current"
                try:
                    with open(attr_path) as f:
                        label = f.read().strip()
                except OSError:
                    continue

                if label == "unconfined" or "unconfined" in label:
                    base_name = comm[:20]
                    if base_name not in unconfined:
                        unconfined[base_name] = []
                    unconfined[base_name].append(pid)

        except (OSError, subprocess.SubprocessError):
            pass

        return unconfined


def _is_apparmor_enforcing() -> bool:
    try:
        enabled = Path("/sys/module/apparmor/parameters/enabled")
        if not enabled.exists():
            return False
        return enabled.read_text().strip() == "Y"
    except OSError:
        return False
