from __future__ import annotations

import os
import stat
from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


# SUID binaries that are expected in a standard Ubuntu/Debian installation.
# Includes common paths across /bin, /sbin, /usr/bin, /usr/sbin.
EXPECTED_SUID: set[str] = {
    "/bin/su", "/usr/bin/su",
    "/bin/sudo", "/usr/bin/sudo",
    "/bin/passwd", "/usr/bin/passwd",
    "/bin/gpasswd", "/usr/bin/gpasswd",
    "/bin/newgrp", "/usr/bin/newgrp",
    "/bin/chsh", "/usr/bin/chsh",
    "/bin/chfn", "/usr/bin/chfn",
    "/bin/mount", "/usr/bin/mount",
    "/bin/umount", "/usr/bin/umount",
    "/bin/fusermount", "/usr/bin/fusermount",
    "/bin/fusermount3", "/usr/bin/fusermount3",
    "/bin/pkexec", "/usr/bin/pkexec",
    "/bin/crontab", "/usr/bin/crontab",
    "/bin/at", "/usr/bin/at",
    "/bin/atq", "/usr/bin/atq",
    "/bin/atrm", "/usr/bin/atrm",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/sbin/unix_chkpwd",
    "/usr/libexec/polkit-1/polkit-agent-helper-1",
}


@register_check
class UnexpectedSUIDCheck(AuditCheck):
    """Check for unexpected SUID binaries that could indicate privilege escalation."""

    id = "PRM-001"
    name = "Unexpected SUID Binaries"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Identifies SUID root binaries not in the expected set"
    depends = []
    tags = ["suid", "privilege-escalation", "permissions"]

    def _run_check(self, collectors: dict) -> list:
        findings = []
        suid_binaries = self._find_suid_binaries()

        for path_str in suid_binaries:
            if path_str not in EXPECTED_SUID:
                path = Path(path_str)
                try:
                    stat_info = path.stat()
                except OSError:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Unexpected SUID binary: {path_str}",
                        description=f"'{path_str}' has the SUID bit set and is not in the expected list",
                        rationale=(
                            "SUID (Set User ID) binaries execute with the privileges of the file owner "
                            "(usually root). Each unexpected SUID binary is a potential privilege "
                            "escalation vector. Attackers may plant SUID binaries as backdoors or "
                            "legitimate software installations may add SUID binaries that weren't "
                            "reviewed. Every SUID binary should be justified and tracked."
                        ),
                        remediation=(
                            f"Investigate why '{path_str}' has the SUID bit set. "
                            f"If unauthorized: 'chmod u-s {path_str}'. "
                            f"If the software was recently installed, review the package's security posture."
                        ),
                        evidence=FileEvidence(
                            path=path_str,
                            permission=oct(stat_info.st_mode & 0o7777),
                            owner=str(stat_info.st_uid),
                            size=stat_info.st_size,
                        ),
                        detected_value=f"SUID bit set on {path_str}",
                        expected_value="No SUID bit",
                        affected_component=path_str,
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1548.001"],
                        tags=["privilege-escalation", "suid", "persistence"],
                    )
                )

        return findings

    def _find_suid_binaries(self) -> list[str]:
        """Find SUID binaries using Python standard library (no subprocess)."""
        suid_binaries: list[str] = []
        search_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]
        for search_path in search_paths:
            base = Path(search_path)
            if not base.is_dir():
                continue
            try:
                for entry in base.iterdir():
                    if entry.is_file() or entry.is_symlink():
                        try:
                            st = entry.stat()
                            if st.st_mode & stat.S_ISUID:
                                suid_binaries.append(str(entry))
                        except OSError:
                            continue
            except OSError:
                continue
        return sorted(suid_binaries)


@register_check
class WorldWritableFilesCheck(AuditCheck):
    """Check for world-writable system files that shouldn't be."""

    id = "PRM-002"
    name = "World-Writable System Files"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Identifies critical system files with world-writable permissions"
    depends = []
    tags = ["permissions", "file-integrity", "hardening"]

    CRITICAL_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/hosts",
        "/etc/hosts.allow",
        "/etc/hosts.deny",
        "/etc/ld.so.conf",
        "/etc/fstab",
    ]

    def _run_check(self, collectors: dict) -> list:
        findings = []
        for path_str in self.CRITICAL_PATHS:
            path = Path(path_str)
            if not path.exists():
                continue
            try:
                st = path.stat()
                if st.st_mode & stat.S_IWOTH:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"World-writable critical file: {path_str}",
                            description=f"'{path_str}' is writable by any user on the system",
                            rationale=(
                                "World-writable permissions on critical system files allow any user "
                                "to modify security-sensitive configurations. For example, a world-writable "
                                "/etc/passwd allows privilege escalation. A world-writable /etc/shadow "
                                "allows password hash replacement. This finding must be addressed immediately."
                            ),
                            remediation=(
                                f"Remove world-writable permissions: 'chmod o-w {path_str}'."
                            ),
                            evidence=FileEvidence(
                                path=path_str,
                                permission=oct(st.st_mode & 0o7777),
                                owner=st.st_uid,
                                size=st.st_size,
                            ),
                            detected_value=oct(st.st_mode & 0o7777),
                            expected_value="Permissions without o-w",
                            affected_component=path_str,
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.0,
                            mitre_attack_ids=["T1222"],
                            cis_benchmarks=["CIS Ubuntu 20.04: 1.7"],
                            tags=["permissions", "file-integrity"],
                        )
                    )
            except OSError:
                continue

        return findings
