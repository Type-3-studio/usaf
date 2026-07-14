from __future__ import annotations

import os
import re as _re
import subprocess
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import CommandEvidence, FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

APPARMOR_PROFILES_DIR = "/etc/apparmor.d"


@register_check
class AppArmorComplainModeCheck(AuditCheck):
    id = "SEC-201"
    name = "AppArmor Profiles in Complain Mode"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Detects AppArmor profiles in complain/learn mode instead of enforce"
    depends = []
    tags = ["security", "apparmor", "profiles", "hardening"]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        if not self._apparmor_enabled():
            return findings

        try:
            result = subprocess.run(
                ["aa-status"],
                capture_output=True, text=True, timeout=15, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return findings

        for line in result.stdout.splitlines():
            if "profiles are in complain" in line:
                match = _re.search(r"(\d+)\s+profiles are in complain", line)
                if match and int(match.group(1)) > 0:
                    count = int(match.group(1))

                    complain_profiles = self._get_complain_profiles(result.stdout)

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"{count} AppArmor profiles in complain mode",
                            description=(
                                f"{count} AppArmor profile(s) are in complain mode: "
                                f"{', '.join(complain_profiles[:10])}"
                                f"{'...' if len(complain_profiles) > 10 else ''}. "
                                f"Complain mode logs violations but does not enforce."
                            ),
                            rationale=(
                                "AppArmor profiles in complain mode log access violations "
                                "but do not block them. These profiles provide no actual "
                                "security benefit — they only audit. All production profiles "
                                "should be in enforce mode."
                            ),
                            remediation=(
                                "Set profiles to enforce: "
                                "'aa-enforce /etc/apparmor.d/*'. "
                                "Or individually: 'aa-enforce <profile_name>'."
                            ),
                            evidence=CommandEvidence(
                                command="aa-status",
                                stdout=f"{count} profiles in complain mode",
                                exit_code=0,
                            ),
                            detected_value=f"{count} complain-mode profiles",
                            expected_value="0 complain-mode profiles",
                            affected_component="AppArmor",
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.1,
                            mitre_attack_ids=["T1562"],
                            tags=["apparmor", "profiles", "hardening"],
                        )
                    )
                break

        return findings

    @staticmethod
    def _apparmor_enabled() -> bool:
        try:
            p = Path("/sys/module/apparmor/parameters/enabled")
            return p.exists() and p.read_text().strip() == "Y"
        except OSError:
            return False

    @staticmethod
    def _get_complain_profiles(aa_status_output: str) -> list[str]:
        profiles: list[str] = []
        in_complain = False
        for line in aa_status_output.splitlines():
            if "profiles are in complain" in line:
                in_complain = True
                continue
            if "processes" in line and "are" in line:
                in_complain = False
            if in_complain and line.strip().startswith("-"):
                prof = line.strip().lstrip("-").strip()
                if prof:
                    profiles.append(prof)
        return profiles


@register_check
class AppArmorProfileIntegrityCheck(AuditCheck):
    id = "SEC-202"
    name = "AppArmor Profile Integrity"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Checks for AppArmor profiles with syntax errors or parse failures"
    depends = []
    tags = ["security", "apparmor", "profiles", "integrity"]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        if not os.path.isdir(APPARMOR_PROFILES_DIR):
            return findings

        try:
            result = subprocess.run(
                ["aa-status"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            output = result.stdout
        except (OSError, subprocess.SubprocessError):
            return findings

        if "profiles are in enforce" not in output and "profiles are in complain" not in output:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="AppArmor profiles not loaded",
                    description=(
                        "aa-status shows no loaded profiles. Profile files exist in "
                        "/etc/apparmor.d but none are loaded into the kernel."
                    ),
                    rationale=(
                        "Unloaded AppArmor profiles provide no security enforcement. "
                        "This may indicate profile syntax errors, missing dependencies, "
                        "or that the AppArmor service has not reloaded after profile changes."
                    ),
                    remediation=(
                        "Reload profiles: 'systemctl reload apparmor'. "
                        "Check for errors: 'journalctl -u apparmor'."
                    ),
                    evidence=CommandEvidence(
                        command="aa-status",
                        stdout=output[:200],
                        exit_code=0,
                    ),
                    detected_value="No loaded profiles",
                    expected_value="AppArmor profiles loaded and enforcing",
                    affected_component="AppArmor",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1562"],
                    tags=["apparmor", "profiles", "integrity"],
                )
            )

        try:
            parse_check = subprocess.run(
                ["aa-status", "--verbose"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if parse_check.returncode != 0:
                findings.append(
                    self.finding(
                        finding_id="002",
                        title="AppArmor profile parse errors",
                        description=f"aa-status returned error: {parse_check.stderr[:200]}.",
                        rationale="Parse errors in AppArmor profiles prevent them from loading. This leaves services unconfined.",
                        remediation="Check profile syntax: 'aa-parser /etc/apparmor.d/*'. Fix errors in affected profiles.",
                        evidence=CommandEvidence(
                            command="aa-status --verbose",
                            stderr=parse_check.stderr[:200],
                            exit_code=parse_check.returncode,
                        ),
                        detected_value="Profile parse errors",
                        expected_value="All profiles parse successfully",
                        affected_component="AppArmor",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1562"],
                        tags=["apparmor", "profiles", "integrity"],
                    )
                )
        except (OSError, subprocess.SubprocessError):
            pass

        return findings


@register_check
class AppArmorExtraProfilesCheck(AuditCheck):
    id = "SEC-203"
    name = "AppArmor Extra Profiles"
    category = CheckCategory.SECURITY
    severity = Severity.LOW
    description = "Checks that extra AppArmor profile packages are installed for common services"
    depends = ["apt"]
    tags = ["security", "apparmor", "profiles", "coverage"]

    EXTRA_PROFILE_PACKAGES: list[str] = [
        "apparmor-profiles",
        "apparmor-profiles-extra",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")
        installed_packages = {p.get("name", "") for p in apt_data.get("packages", [])}

        missing = [pkg for pkg in self.EXTRA_PROFILE_PACKAGES if pkg not in installed_packages]

        if not missing:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Extra AppArmor profiles not installed",
                description=(
                    f"Missing packages: {', '.join(missing)}. "
                    f"These contain AppArmor profiles for common services."
                ),
                rationale=(
                    "The apparmor-profiles-extra package includes profiles for "
                    "common services like MySQL, PostgreSQL, Apache, and Nginx. "
                    "Without it, many network services run unconfined."
                ),
                remediation=f"Install: 'apt install {' '.join(missing)}'.",
                evidence=RegistryEvidence(
                    key="packages.apparmor_profiles_extra",
                    value="not installed",
                    expected="installed",
                    source="dpkg",
                ),
                detected_value=f"Missing: {', '.join(missing)}",
                expected_value="apparmor-profiles[-extra] installed",
                affected_component="AppArmor profile coverage",
                confidence=Confidence.LOW,
                false_positive_probability=0.4,
                mitre_attack_ids=["T1562"],
                tags=["apparmor", "profiles", "coverage"],
            )
        )
        return findings


@register_check
class SeccompStatusCheck(AuditCheck):
    id = "SEC-204"
    name = "Seccomp Status"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Checks that seccomp is available and enabled in the kernel"
    depends = []
    tags = ["security", "seccomp", "kernel", "hardening"]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        seccomp_path = Path("/proc/sys/kernel/seccomp")
        if not seccomp_path.exists():
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Seccomp not available in kernel",
                    description="The /proc/sys/kernel/seccomp file does not exist. Seccomp is not enabled in this kernel.",
                    rationale="Seccomp (secure computing mode) allows filtering of system calls. Without it, containers and sandboxed applications cannot restrict syscall access.",
                    remediation="Ensure the kernel was built with CONFIG_SECCOMP=y. Recompile or upgrade kernel.",
                    evidence=RegistryEvidence(key="kernel.seccomp", value="not available", expected="available", source="/proc/sys/kernel/seccomp"),
                    detected_value="Seccomp not available",
                    expected_value="Seccomp available",
                    affected_component="Kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1562"],
                    tags=["security", "seccomp", "kernel", "hardening"],
                )
            )
            return findings

        try:
            val = seccomp_path.read_text().strip()
            if val == "2":
                return findings

            findings.append(
                self.finding(
                    finding_id="002",
                    title=f"Seccomp mode limited ({val})",
                    description=f"Seccomp is available but limited to mode {val} (2=full, 1=filter only, 0=disabled).",
                    rationale="Seccomp mode 1 only allows setting filters but doesn't enforce the strict mode. Mode 2 enables the full seccomp facility.",
                    remediation="Ensure CONFIG_SECCOMP_FILTER=y in kernel config for full seccomp support.",
                    evidence=RegistryEvidence(key="kernel.seccomp.mode", value=val, expected="2", source="/proc/sys/kernel/seccomp"),
                    detected_value=f"Seccomp mode {val}",
                    expected_value="Seccomp mode 2",
                    affected_component="Kernel",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1562"],
                    tags=["security", "seccomp", "kernel", "hardening"],
                )
            )
        except OSError:
            pass

        return findings


@register_check
class LsmStackingCheck(AuditCheck):
    id = "SEC-205"
    name = "LSM Stacking Status"
    category = CheckCategory.SECURITY
    severity = Severity.LOW
    description = "Checks which Linux Security Modules are active and their stacking order"
    depends = []
    tags = ["security", "lsm", "apparmor", "audit"]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []
        lsm_path = Path("/sys/kernel/security/lsm")

        if not lsm_path.exists():
            return findings

        try:
            lsm_list = lsm_path.read_text().strip().lower()
        except OSError:
            return findings

        active = [item for item in lsm_list.split(",") if item]

        if "apparmor" not in active:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="AppArmor not in LSM stack",
                    description=f"Active LSMs: {', '.join(active)}. AppArmor is not in the LSM stack.",
                    rationale="AppArmor is Ubuntu's primary mandatory access control system. If it's not in the LSM stack, no AppArmor policies are enforced regardless of profile configuration.",
                    remediation="Add 'security=apparmor' to kernel cmdline in /etc/default/grub, update-grub, and reboot.",
                    evidence=RegistryEvidence(key="kernel.security.lsm", value=lsm_list, expected="includes apparmor", source="/sys/kernel/security/lsm"),
                    detected_value=f"LSMs: {', '.join(active)}",
                    expected_value="apparmor in LSM stack",
                    affected_component="Kernel LSM",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1562"],
                    tags=["security", "lsm", "apparmor", "audit"],
                )
            )

        return findings


@register_check
class AppArmorCacheStatusCheck(AuditCheck):
    id = "SEC-206"
    name = "AppArmor Cache Status"
    category = CheckCategory.SECURITY
    severity = Severity.LOW
    description = "Checks that AppArmor profile cache is valid and up to date"
    depends = []
    tags = ["security", "apparmor", "cache", "performance"]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []
        cache_dirs = [
            Path("/var/cache/apparmor"),
            Path("/etc/apparmor.d/cache"),
        ]

        cache_found = False
        for cache_dir in cache_dirs:
            if cache_dir.is_dir():
                cache_found = True
                break

        if not cache_found:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="AppArmor cache directory missing",
                    description="No AppArmor cache directory found. Profile compilation will happen on every boot, slowing startup.",
                    rationale="The AppArmor cache stores compiled profiles to speed up boot. Without it, all profiles must be recompiled on each boot, delaying service startup.",
                    remediation="Create cache directory: 'mkdir -p /var/cache/apparmor' and reload: 'systemctl reload apparmor'.",
                    evidence=FileEvidence(
                        path="/var/cache/apparmor",
                        content="Cache directory does not exist",
                    ),
                    detected_value="No AppArmor cache",
                    expected_value="AppArmor cache present",
                    affected_component="AppArmor cache",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1562"],
                    tags=["apparmor", "cache", "performance"],
                )
            )

        return findings


@register_check
class ModuleLoadingRestrictionsCheck(AuditCheck):
    id = "SEC-207"
    name = "Kernel Module Loading Restrictions"
    category = CheckCategory.SECURITY
    severity = Severity.HIGH
    description = "Checks if kernel module loading is restricted via modules_disabled or module signing"
    depends = []
    tags = ["security", "kernel", "modules", "hardening"]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        mod_disabled = Path("/proc/sys/kernel/modules_disabled")
        if mod_disabled.exists():
            try:
                val = mod_disabled.read_text().strip()
                if val == "1":
                    return findings
            except OSError:
                pass

        if not mod_disabled.exists():
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Kernel module loading restriction not available",
                    description="/proc/sys/kernel/modules_disabled does not exist. This kernel may not support disabling module loading.",
                    rationale="Restricting kernel module loading prevents unauthorized kernel code execution. Without this restriction, any root-level process can load kernel modules to bypass security controls.",
                    remediation="Consider using module signing (CONFIG_MODULE_SIG) or setting modules_disabled=1 via sysctl if available.",
                    evidence=RegistryEvidence(key="kernel.modules_disabled", value="not available", expected="1", source="/proc/sys/kernel/modules_disabled"),
                    detected_value="modules_disabled not available",
                    expected_value="modules_disabled=1",
                    affected_component="Kernel module loading",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1562"],
                    tags=["security", "kernel", "modules", "hardening"],
                )
            )
        else:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Kernel module loading not disabled",
                    description="modules_disabled=0. Kernel modules can be loaded or unloaded at runtime.",
                    rationale="With module loading enabled, an attacker with root access can load malicious kernel modules to disable security mechanisms, hide processes, or install rootkits.",
                    remediation="Set 'kernel.modules_disabled=1' in /etc/sysctl.d/ and reboot. Ensure all needed modules are loaded first.",
                    evidence=RegistryEvidence(key="kernel.modules_disabled", value="0", expected="1", source="/proc/sys/kernel/modules_disabled"),
                    detected_value="modules_disabled=0",
                    expected_value="modules_disabled=1",
                    affected_component="Kernel module loading",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1562"],
                    tags=["security", "kernel", "modules", "hardening"],
                )
            )

        return findings


@register_check
class UnconfinedRootProcessesCheck(AuditCheck):
    id = "SEC-208"
    name = "Unconfined Root Processes"
    category = CheckCategory.SECURITY
    severity = Severity.HIGH
    description = "Detects root processes running without AppArmor confinement"
    depends = ["processes"]
    tags = ["security", "apparmor", "processes", "hardening"]
    max_findings = 100

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        proc_data = self._get_data(collectors, "processes")

        for proc in proc_data.get("processes", []):
            pid = proc.get("pid", 0)
            uid = proc.get("uid", 0)
            name = proc.get("name", "")

            if uid != 0:
                continue
            if pid <= 1:
                continue
            if not name:
                continue

            attr_path = f"/proc/{pid}/attr/current"
            try:
                with open(attr_path) as f:
                    label = f.read().strip()
            except OSError:
                continue

            if "unconfined" not in label.lower():
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unconfined root process: {name} (PID {pid})",
                    description=f"Root process '{name}' (PID {pid}) is running unconfined by AppArmor (label: '{label}').",
                    rationale="Root processes without AppArmor confinement have full system access. If compromised, an attacker has unrestricted access to all system resources.",
                    remediation=f"Create or load an AppArmor profile for '{name}': 'aa-enforce /etc/apparmor.d/<profile>'.",
                    evidence=RegistryEvidence(
                        key=f"process.{pid}.apparmor",
                        value=label,
                        expected="enforce mode profile",
                        source=f"/proc/{pid}/attr/current",
                    ),
                    detected_value=f"Process {name} (PID {pid}) unconfined",
                    expected_value="Process confined by AppArmor profile",
                    affected_component=f"Process: {name} (PID {pid})",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1562"],
                    tags=["security", "apparmor", "processes", "hardening"],
                )
            )
        return findings
