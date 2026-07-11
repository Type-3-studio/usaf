from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

from usaf.collectors.packages.apt import get_package_for_file
from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class UnexpectedSUIDCheck(AuditCheck):
    """Check for unexpected SUID binaries that could indicate privilege escalation."""

    id = "PRM-001"
    name = "Unexpected SUID Binaries"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Identifies SUID root binaries not in the expected set or not owned by a package"
    depends = []
    tags = ["suid", "privilege-escalation", "permissions"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        suid_binaries = self._find_suid_binaries()

        for path_str in suid_binaries:
            path = Path(path_str)
            try:
                stat_info = path.stat()
            except OSError:
                continue

            owning_package = get_package_for_file(path_str)
            is_package_owned = owning_package is not None
            is_expected_suid = self._is_expected_suid(path_str, owning_package)

            if is_expected_suid:
                continue

            evidence = FileEvidence(
                path=path_str,
                permission=oct(stat_info.st_mode & 0o7777),
                owner=str(stat_info.st_uid),
                size=stat_info.st_size,
                content=(
                    f"Package: {owning_package}"
                    if owning_package
                    else "Not owned by any installed package"
                ),
            )

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected SUID binary: {path_str}",
                    description=self._build_description(path_str, owning_package),
                    rationale=(
                        "SUID (Set User ID) binaries execute with the privileges of the file owner "
                        "(usually root). Each unexpected SUID binary is a potential privilege "
                        "escalation vector. Attackers may plant SUID binaries as backdoors or "
                        "legitimate software installations may add SUID binaries that weren't "
                        "reviewed. Every SUID binary should be justified and tracked."
                    ),
                    remediation=self._build_remediation(path_str, owning_package),
                    evidence=evidence,
                    detected_value=f"SUID bit set on {path_str}",
                    expected_value="No SUID bit",
                    affected_component=path_str,
                    confidence=Confidence.LOW if is_package_owned else Confidence.HIGH,
                    false_positive_probability=0.8 if is_package_owned else 0.05,
                    mitre_attack_ids=["T1548.001"],
                    tags=["privilege-escalation", "suid", "persistence"],
                )
            )

        return findings

    def _is_expected_suid(self, path_str: str, owning_package: str | None) -> bool:
        """Common SUID binaries shipped with Ubuntu that are not a concern."""
        expected = {
            "/bin/su",
            "/usr/bin/su",
            "/bin/sudo",
            "/usr/bin/sudo",
            "/bin/passwd",
            "/usr/bin/passwd",
            "/bin/gpasswd",
            "/usr/bin/gpasswd",
            "/bin/newgrp",
            "/usr/bin/newgrp",
            "/bin/chsh",
            "/usr/bin/chsh",
            "/bin/chfn",
            "/usr/bin/chfn",
            "/bin/mount",
            "/usr/bin/mount",
            "/bin/umount",
            "/usr/bin/umount",
            "/bin/fusermount",
            "/usr/bin/fusermount",
            "/bin/fusermount3",
            "/usr/bin/fusermount3",
            "/bin/pkexec",
            "/usr/bin/pkexec",
            "/bin/crontab",
            "/usr/bin/crontab",
            "/bin/at",
            "/usr/bin/at",
            "/bin/atq",
            "/usr/bin/atq",
            "/bin/atrm",
            "/usr/bin/atrm",
            "/usr/lib/polkit-1/polkit-agent-helper-1",
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
            "/usr/lib/openssh/ssh-keysign",
            "/usr/sbin/unix_chkpwd",
            "/usr/libexec/polkit-1/polkit-agent-helper-1",
        }
        return path_str in expected

    def _build_description(self, path_str: str, owning_package: str | None) -> str:
        if owning_package:
            return (
                f"'{path_str}' has the SUID bit set. It is owned by the "
                f"'{owning_package}' package, which may be legitimate, but "
                f"should be verified against your security policy."
            )
        return (
            f"'{path_str}' has the SUID bit set and is not owned by any "
            f"installed package. This is highly suspicious."
        )

    def _build_remediation(self, path_str: str, owning_package: str | None) -> str:
        if owning_package:
            return (
                f"Review whether the '{owning_package}' package requires SUID on {path_str}. "
                f"If not: 'chmod u-s {path_str}'. To find the package: "
                f"'dpkg -S {path_str}'. If the package was intentionally installed, "
                f"add it to your policy allowlist."
            )
        return (
            f"Investigate '{path_str}' immediately. It is not owned by any installed package. "
            f"If unauthorized: 'chmod u-s {path_str}'. Check for malware: "
            f"'sha256sum {path_str}' and scan on VirusTotal."
        )

    def _find_suid_binaries(self) -> list[str]:
        """Find SUID binaries using Python standard library (no subprocess)."""
        seen: set[str] = set()
        search_paths = [
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
        ]
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
                                seen.add(str(entry))
                        except OSError:
                            continue
            except OSError:
                continue
        return sorted(seen)


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

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        for path_str in self.CRITICAL_PATHS:
            path = Path(path_str)
            if not path.exists():
                continue
            try:
                st = path.stat()
                if st.st_mode & stat.S_IWOTH:
                    owning_package = get_package_for_file(path_str)
                    is_package_owned = owning_package is not None

                    evidence = FileEvidence(
                        path=path_str,
                        permission=oct(st.st_mode & 0o7777),
                        owner=str(st.st_uid),
                        size=st.st_size,
                        content=(
                            f"Package: {owning_package}"
                            if owning_package
                            else "Not owned by any installed package"
                        ),
                    )

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"World-writable critical file: {path_str}",
                            description=(
                                f"'{path_str}' is writable by any user on the system"
                                + (f" (owned by {owning_package})" if owning_package else "")
                            ),
                            rationale=(
                                "World-writable permissions on critical system files allow any user "
                                "to modify security-sensitive configurations. For example, a world-writable "
                                "/etc/passwd allows privilege escalation. A world-writable /etc/shadow "
                                "allows password hash replacement. This finding must be addressed immediately."
                            ),
                            remediation=(
                                f"Remove world-writable permissions: 'chmod o-w {path_str}'."
                            ),
                            evidence=evidence,
                            detected_value=oct(st.st_mode & 0o7777),
                            expected_value="Permissions without o-w",
                            affected_component=path_str,
                            confidence=Confidence.LOW if is_package_owned else Confidence.HIGH,
                            false_positive_probability=0.7 if is_package_owned else 0.01,
                            mitre_attack_ids=["T1222"],
                            cis_benchmarks=["CIS Ubuntu 20.04: 1.7"],
                            tags=["permissions", "file-integrity"],
                        )
                    )
            except OSError:
                continue

        return findings
