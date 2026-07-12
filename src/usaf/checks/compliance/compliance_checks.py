from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

SEPARATE_PARTITIONS: dict[str, str] = {
    "/tmp": "Separate /tmp partition (or tmpfs) prevents filling root FS",
    "/var": "Separate /var prevents log files from filling root FS",
    "/home": "Separate /home allows nodev/nosuid for user data",
    "/var/tmp": "Separate /var/tmp or bind mount isolates temporary files",
    "/var/log": "Separate /var/log prevents audit log filling root FS",
    "/var/log/audit": "Separate /var/log/audit protects audit logs",
}

MOUNT_OPTION_CHECKS: dict[str, list[str]] = {
    "/tmp": ["nodev", "nosuid", "noexec"],
    "/var/tmp": ["nodev", "nosuid", "noexec"],
    "/home": ["nodev", "nosuid"],
    "/dev/shm": ["nodev", "nosuid", "noexec"],
}

PARTITION_OPTIONS: dict[str, list[str]] = {
    "/tmp": ["nodev", "nosuid", "noexec"],
    "/var/tmp": ["nodev", "nosuid", "noexec"],
    "/home": ["nodev", "nosuid"],
    "/dev/shm": ["nodev", "nosuid", "noexec"],
}


@register_check
class LoginBannerCheck(AuditCheck):
    id = "CMP-102"
    name = "Login Warning Banner"
    category = CheckCategory.COMPLIANCE
    severity = Severity.LOW
    description = "Checks that system login banners exist (/etc/issue, /etc/issue.net)"
    depends = []
    tags = ["compliance", "legal", "banner"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        for path_str in ("/etc/issue", "/etc/issue.net"):
            p = Path(path_str)
            if not p.exists() or p.stat().st_size == 0:
                findings.append(self.finding(
                    finding_id="001" if path_str == "/etc/issue" else "002",
                    title=f"Missing login banner: {path_str}",
                    description=f"{path_str} does not exist or is empty",
                    rationale="Login banners provide legal warning to users. Required for PCI DSS, SOC 2, and other compliance frameworks.",
                    remediation=f"Create {path_str} with an authorized warning message.",
                    evidence=FileEvidence(path=path_str, content="missing or empty"),
                    detected_value=f"{path_str}: missing/empty",
                    expected_value=f"{path_str}: present with content",
                    affected_component=path_str,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    tags=["compliance", "legal"],
                ))
        return findings


@register_check
class SeparatePartitionCheck(AuditCheck):
    id = "CMP-103"
    name = "Separate Filesystem Partitions"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that key directories are on separate partitions"
    depends = ["mounts"]
    tags = ["compliance", "partitioning", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        mounts_data = self._get_data(collectors, "mounts")
        findings: list = []
        mount_points: set[str] = {m.get("mount_point", "") for m in mounts_data.get("mounts", [])}

        for required, reason in SEPARATE_PARTITIONS.items():
            is_separate = False
            for mp in mount_points:
                if mp == required or mp.startswith(required + "/"):
                    is_separate = True
                    break
            if not is_separate:
                findings.append(self.finding(
                    finding_id="001",
                    title=f"No separate {required} partition",
                    description=f"'{required}' is not on a separate partition. {reason}",
                    rationale="Separate partitions prevent resource exhaustion attacks and allow mount option hardening.",
                    remediation=f"Create a separate partition for {required} and update /etc/fstab.",
                    evidence=RegistryEvidence(
                        key=f"partition.{required}",
                        value="not separate",
                        expected=f"separate partition mounted at {required}",
                        source="/proc/mounts",
                    ),
                    detected_value=f"{required}: no separate partition",
                    expected_value=f"{required}: separate partition",
                    affected_component=f"filesystem/{required}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.15,
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.1"],
                    tags=["compliance", "partitioning"],
                ))

        return findings


@register_check
class MountOptionsCheck(AuditCheck):
    id = "CMP-104"
    name = "Filesystem Mount Options"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that sensitive filesystems have secure mount options"
    depends = ["mounts"]
    tags = ["compliance", "mount", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        mounts_data = self._get_data(collectors, "mounts")
        findings: list = []
        mount_map: dict[str, str] = {}

        for m in mounts_data.get("mounts", []):
            mp: str = m.get("mount_point", "")
            opts: str = m.get("options", "")
            mount_map[mp] = opts

        for target, required_opts in MOUNT_OPTION_CHECKS.items():
            opts_str = mount_map.get(target, "")
            if not opts_str:
                continue
            opts_lower = opts_str.lower()
            missing = [o for o in required_opts if o not in opts_lower]
            if missing:
                findings.append(self.finding(
                    finding_id="001",
                    title=f"Missing mount options on {target}: {', '.join(missing)}",
                    description=f"'{target}' is missing mount options: {', '.join(missing)}",
                    rationale=f"Mount options {' and '.join(missing)} on {target} prevent specific attacks.",
                    remediation=f"Add {', '.join(missing)} to {target} in /etc/fstab.",
                    evidence=RegistryEvidence(
                        key=f"mount.{target}.options",
                        value=opts_str,
                        expected=f"includes {', '.join(missing)}",
                        source="/proc/mounts",
                    ),
                    detected_value=f"{target}: {opts_str}",
                    expected_value=f"{target}: includes {', '.join(missing)}",
                    affected_component=f"mount/{target}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.1.2"],
                    tags=["compliance", "mount", "hardening"],
                ))

        return findings


@register_check
class TimeSyncCheck(AuditCheck):
    id = "CMP-105"
    name = "Time Synchronization"
    category = CheckCategory.COMPLIANCE
    severity = Severity.HIGH
    description = "Checks that time synchronization is active (NTP/Chrony/systemd-timesyncd)"
    depends = []
    tags = ["compliance", "time", "audit"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        timesync_active = self._check_service("systemd-timesyncd")
        chrony_active = self._check_service("chrony")
        ntp_active = self._check_service("ntp")
        ntpsec_active = self._check_service("ntpsec")

        if not any([timesync_active, chrony_active, ntp_active, ntpsec_active]):
            findings.append(self.finding(
                finding_id="001", title="No time synchronization service active",
                description="No time sync service (systemd-timesyncd, chrony, NTP) is active",
                rationale="Accurate system time is critical for audit logs, Kerberos auth, TLS certificate validation, and compliance.",
                remediation="Enable time sync: 'timedatectl set-ntp true' or install chrony.",
                evidence=RegistryEvidence(
                    key="time_sync", value="none active",
                    expected="One of: systemd-timesyncd, chrony, ntp, ntpsec",
                    source="systemctl",
                ),
                detected_value="No time sync active",
                expected_value="At least one time sync service active",
                affected_component="time synchronization",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1070"],
                cis_benchmarks=["CIS Ubuntu 20.04: 2.2.1"],
                tags=["compliance", "time"],
            ))

        return findings

    @staticmethod
    def _check_service(name: str) -> bool:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True, text=True, timeout=5, check=False,
            )
            return r.stdout.strip() == "active"
        except (OSError, subprocess.SubprocessError):
            return False


@register_check
class FileIntegrityToolCheck(AuditCheck):
    id = "CMP-106"
    name = "File Integrity Monitoring Tool"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that a file integrity monitoring tool is installed"
    depends = []
    tags = ["compliance", "integrity", "monitoring"]

    FIM_TOOLS: dict[str, str] = {
        "aide": "Advanced Intrusion Detection Environment",
        "tripwire": "Tripwire",
        "samhain": "Samhain",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        installed: list[str] = []

        for tool, desc in self.FIM_TOOLS.items():
            if self._is_installed(tool):
                installed.append(f"{tool} ({desc})")

        if not installed:
            findings.append(self.finding(
                finding_id="001", title="No file integrity tool installed",
                description="No file integrity monitoring tool (AIDE, Tripwire, Samhain) is installed",
                rationale="File integrity monitoring detects unauthorized file changes. Required by CIS, PCI DSS, and most compliance frameworks.",
                remediation="Install AIDE: 'apt install aide' and initialize: 'aideinit'.",
                evidence=RegistryEvidence(
                    key="fim_tool", value="none",
                    expected="aide, tripwire, or samhain installed",
                    source="dpkg",
                ),
                detected_value="No FIM tool",
                expected_value="at least one FIM tool",
                affected_component="filesystem integrity",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                cis_benchmarks=["CIS Ubuntu 20.04: 1.3"],
                tags=["compliance", "integrity"],
            ))

        return findings

    @staticmethod
    def _is_installed(tool: str) -> bool:
        try:
            r = subprocess.run(
                ["dpkg", "-l", tool],
                capture_output=True, text=True, timeout=10, check=False,
            )
            return "ii" in r.stdout
        except (OSError, subprocess.SubprocessError):
            return False


@register_check
class GrubPasswordCheck(AuditCheck):
    id = "CMP-107"
    name = "GRUB Bootloader Password"
    category = CheckCategory.COMPLIANCE
    severity = Severity.HIGH
    description = "Checks that GRUB bootloader has a password set"
    depends = []
    tags = ["compliance", "boot", "access-control"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        grub_cfg = Path("/boot/grub/grub.cfg")

        if not grub_cfg.exists():
            return findings

        try:
            content = grub_cfg.read_text()
            if "password_pbkdf2" not in content and "password" not in content:
                findings.append(self.finding(
                    finding_id="001", title="GRUB bootloader password not set",
                    description="No password_pbkdf2 or password directive found in /boot/grub/grub.cfg",
                    rationale="Without a GRUB password, anyone with physical or console access can boot into single-user mode or alter boot parameters to gain root access.",
                    remediation="Set a GRUB password: 'grub-mkpasswd-pbkdf2' and add to /etc/grub.d/40_custom.",
                    evidence=FileEvidence(path="/boot/grub/grub.cfg", content="no password directive found"),
                    detected_value="GRUB password: not set",
                    expected_value="password_pbkdf2 directive present",
                    affected_component="GRUB bootloader",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1542.001"],
                    tags=["compliance", "boot"],
                ))
        except OSError:
            pass

        return findings


@register_check
class RestrictedRootLoginCheck(AuditCheck):
    id = "CMP-108"
    name = "Restricted Root Login"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that direct root login via console is restricted"
    depends = []
    tags = ["compliance", "authentication", "access-control"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        securetty = Path("/etc/securetty")

        if securetty.exists():
            try:
                lines = securetty.read_text().splitlines()
                active = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
                if len(active) > 2:
                    findings.append(self.finding(
                        finding_id="001", title=f"Root login allowed on {len(active)} ttys",
                        description=f"/etc/securetty allows root login on {len(active)} terminals: {', '.join(active[:5])}",
                        rationale="Restricting root to local console only prevents remote direct root login. This is a defense-in-depth measure.",
                        remediation=f"Edit /etc/securetty to only include 'console' and 'tty1'. Current entries: {', '.join(active)}",
                        evidence=FileEvidence(path="/etc/securetty", content=f"active entries: {', '.join(active)}"),
                        detected_value=f"{len(active)} secure TTYs",
                        expected_value="2 or fewer (console, tty1)",
                        affected_component="/etc/securetty",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        tags=["compliance", "authentication"],
                    ))
            except OSError:
                pass

        return findings


@register_check
class AuditdServiceCheck(AuditCheck):
    id = "CMP-109"
    name = "Auditd Service Status"
    category = CheckCategory.COMPLIANCE
    severity = Severity.HIGH
    description = "Checks that auditd service is running and enabled"
    depends = []
    tags = ["compliance", "audit", "logging"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        active = self._check_active("auditd")
        enabled = self._check_enabled("auditd")

        if not active:
            findings.append(self.finding(
                finding_id="001", title="auditd service is not running",
                description="The auditd service is not currently active",
                rationale="auditd is required for system call auditing, which is mandatory for CIS, PCI DSS, and most compliance frameworks.",
                remediation="Start auditd: 'systemctl start auditd'. Enable: 'systemctl enable auditd'.",
                evidence=RegistryEvidence(key="auditd.active", value="inactive", expected="active", source="systemctl"),
                detected_value="auditd not running",
                expected_value="auditd running",
                affected_component="auditd",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                cis_benchmarks=["CIS Ubuntu 20.04: 3.1"],
                tags=["compliance", "audit"],
            ))

        if not enabled:
            findings.append(self.finding(
                finding_id="002", title="auditd service is not enabled",
                description="The auditd service is not enabled for boot",
                rationale="auditd must be enabled to start at boot for continuous auditing.",
                remediation="Enable auditd: 'systemctl enable auditd'.",
                evidence=RegistryEvidence(key="auditd.enabled", value="disabled", expected="enabled", source="systemctl"),
                detected_value="auditd not enabled",
                expected_value="auditd enabled",
                affected_component="auditd",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                tags=["compliance", "audit"],
            ))

        return findings

    @staticmethod
    def _check_active(name: str) -> bool:
        try:
            r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5, check=False)
            return r.stdout.strip() == "active"
        except (OSError, subprocess.SubprocessError):
            return False

    @staticmethod
    def _check_enabled(name: str) -> bool:
        try:
            r = subprocess.run(["systemctl", "is-enabled", name], capture_output=True, text=True, timeout=5, check=False)
            return r.stdout.strip() in ("enabled", "enabled-runtime")
        except (OSError, subprocess.SubprocessError):
            return False
