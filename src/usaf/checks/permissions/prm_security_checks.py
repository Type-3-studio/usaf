from __future__ import annotations

import stat as stat_module
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


def _parse_mode_int(mode_str: str) -> int:
    try:
        return int(mode_str, 8) if mode_str.startswith("0") else int(mode_str)
    except (ValueError, TypeError):
        return 0


@register_check
class GroupWritableSetuidCheck(AuditCheck):
    id = "PRM-401"
    name = "Group-Writable SUID/SGID Binaries"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Detects SUID/SGID files that are group-writable"
    depends = ["filesystem"]
    tags = ["suid", "sgid", "permissions", "privilege-escalation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = collectors.get("filesystem", {})
        suid_list = fs_data.get("suid_files", [])

        for entry in suid_list:
            path_str = entry.get("path", "")
            mode_str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)
            if not (mode_int & (stat_module.S_ISUID | stat_module.S_ISGID)):
                continue
            if not (mode_int & stat_module.S_IWGRP):
                continue

            setuid = bool(mode_int & stat_module.S_ISUID)
            setgid = bool(mode_int & stat_module.S_ISGID)
            bits = "+".join(p for p, b in [("SUID", setuid), ("SGID", setgid)] if b)

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Group-writable setuid file: {path_str}",
                    description=(
                        f"'{path_str}' has {bits} set AND is group-writable "
                        f"(mode {mode_str}). Any member of the file's group "
                        f"can replace it with arbitrary code."
                    ),
                    rationale=(
                        "A group-writable SUID/SGID binary allows any user in the "
                        "owning group to replace the file. Combined with setuid, "
                        "this enables privilege escalation — a compromised group "
                        "member can swap the binary and execute with the file owner's "
                        "privileges."
                    ),
                    remediation=(
                        f"Remove group-write permission: 'chmod g-w {path_str}'. "
                        f"If group write is needed, consider removing setuid/setgid."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        owner=str(entry.get("uid", "")),
                        group=str(entry.get("gid", "")),
                        size=entry.get("size", 0),
                        content=f"Group-writable with {bits}",
                    ),
                    detected_value=f"Mode {mode_str}: {bits} + group-writable",
                    expected_value="SUID/SGID files must not be group-writable",
                    affected_component=path_str,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1548.001"],
                    tags=["suid", "sgid", "permissions", "privilege-escalation"],
                )
            )
        return findings


@register_check
class SGIDOnWorldWritableDirsCheck(AuditCheck):
    id = "PRM-402"
    name = "SGID on World-Writable Directories"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Detects world-writable directories with SGID bit set"
    depends = ["filesystem"]
    tags = ["sgid", "world-writable", "permissions", "privilege-escalation"]

    _KNOWN_SAFE_PATHS: set[str] = {
        "/var/log/journal",
        "/run/log/journal",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = collectors.get("filesystem", {})
        ww_list = fs_data.get("world_writable", [])

        for entry in ww_list:
            if not entry.get("is_dir"):
                continue

            path_str = entry.get("path", "")
            if path_str in self._KNOWN_SAFE_PATHS:
                continue

            mode_str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)
            if not (mode_int & stat_module.S_ISGID):
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"SGID on world-writable directory: {path_str}",
                    description=(
                        f"'{path_str}' is world-writable and has the SGID bit set "
                        f"(mode {mode_str}). New files inherit the directory's group."
                    ),
                    rationale=(
                        "SGID on world-writable directories causes all newly created "
                        "files to inherit the directory's group. This can be exploited: "
                        "an attacker creates a malicious file that inherits a privileged "
                        "group, potentially gaining elevated access."
                    ),
                    remediation=(
                        f"Remove SGID bit: 'chmod g-s {path_str}'. "
                        f"Or restrict permissions: 'chmod o-w {path_str}'."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        owner=str(entry.get("uid", "")),
                        content="World-writable directory with SGID",
                    ),
                    detected_value=f"Mode {mode_str}: world-writable + SGID",
                    expected_value="World-writable directories should not have SGID",
                    affected_component=path_str,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.15,
                    mitre_attack_ids=["T1548.001", "T1222"],
                    tags=["sgid", "world-writable", "permissions", "privilege-escalation"],
                )
            )
        return findings


@register_check
class SetuidWithCapabilitiesCheck(AuditCheck):
    id = "PRM-403"
    name = "SUID Files with Capabilities"
    category = CheckCategory.PERMISSIONS
    severity = Severity.MEDIUM
    description = "Detects SUID/SGID files that also have Linux capabilities"
    depends = ["filesystem"]
    tags = ["suid", "capabilities", "privilege-escalation"]

    REDUNDANT_CAP_INDICATORS: list[str] = [
        "cap_setuid",
        "cap_setgid",
        "cap_sys_admin",
        "cap_dac_override",
        "cap_dac_read_search",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = collectors.get("filesystem", {})
        suid_list = fs_data.get("suid_files", [])
        caps_list = fs_data.get("capabilities", [])

        caps_paths: dict[str, str] = {}
        for cap_entry in caps_list:
            c_path = cap_entry.get("path", "")
            c_caps = cap_entry.get("capabilities", "")
            if c_path and c_caps:
                caps_paths[c_path] = c_caps

        if not caps_paths:
            return findings

        for entry in suid_list:
            path_str = entry.get("path", "")
            mode_str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)
            if not (mode_int & (stat_module.S_ISUID | stat_module.S_ISGID)):
                continue

            file_caps = caps_paths.get(path_str)
            if not file_caps:
                continue

            caps_lower = file_caps.lower()
            redundant = [c for c in self.REDUNDANT_CAP_INDICATORS if c in caps_lower]

            setuid = bool(mode_int & stat_module.S_ISUID)
            setgid = bool(mode_int & stat_module.S_ISGID)
            bits = "+".join(p for p, b in [("SUID", setuid), ("SGID", setgid)] if b)

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"SUID/SGID with capabilities: {path_str}",
                    description=(
                        f"'{path_str}' has {bits} (mode {mode_str}) AND file "
                        f"capabilities: {file_caps}."
                        + (f" Redundant caps detected: {', '.join(redundant)}." if redundant else "")
                    ),
                    rationale=(
                        "SUID/SGID binaries with file capabilities create dangerous "
                        "privilege combinations. The setuid already grants the file "
                        "owner's privileges; extra capabilities like CAP_DAC_OVERRIDE "
                        "or CAP_SYS_ADMIN are unnecessary and expand the attack surface. "
                        "Capabilities on setuid binaries may also indicate configuration "
                        "errors or automated exploit attempts."
                    ),
                    remediation=(
                        f"Review capabilities: 'getcap {path_str}'. "
                        f"Remove unnecessary caps: 'setcap -r {path_str}'. "
                        f"Or remove SUID: 'chmod u-s {path_str}'."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        owner=str(entry.get("uid", "")),
                        content=f"Capabilities: {file_caps}",
                    ),
                    detected_value=f"{bits} with capabilities: {file_caps}",
                    expected_value="SUID/SGID files should not have extra capabilities",
                    affected_component=path_str,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1548.001"],
                    tags=["suid", "capabilities", "privilege-escalation"],
                )
            )
        return findings


@register_check
class WeakDefaultUmaskCheck(AuditCheck):
    id = "PRM-404"
    name = "Weak Default Umask"
    category = CheckCategory.PERMISSIONS
    severity = Severity.MEDIUM
    description = "Checks that the system default umask provides adequate permissions restriction"
    depends = []
    tags = ["permissions", "umask", "hardening"]

    STRONG_UMASK_MIN = 0o027

    UMASK_SOURCES: list[str] = [
        "/etc/login.defs",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zshenv",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        found_umask: str | None = None
        source: str | None = None
        value: int | None = None

        for filepath in self.UMASK_SOURCES:
            result = self._extract_umask(filepath)
            if result is not None:
                found_umask, source = result
                if found_umask:
                    try:
                        value = int(found_umask, 8)
                    except (ValueError, TypeError):
                        continue
                    break

        if value is None:
            return findings

        if value >= self.STRONG_UMASK_MIN:
            return findings

        umask_str = f"{value:03o}"

        findings.append(
            self.finding(
                finding_id="001",
                title=f"Weak default umask ({umask_str})",
                description=(
                    f"Default umask {umask_str} found in {source}. "
                    f"Recommended umask is {self.STRONG_UMASK_MIN:03o} or stricter."
                ),
                rationale=(
                    "A weak default umask (e.g., 0022 or 0002) causes newly created "
                    "files and directories to be world-readable or world-writable by "
                    "default. This increases the risk of accidental data exposure and "
                    "provides more opportunities for attackers to read or modify "
                    "newly created files."
                ),
                remediation=(
                    f"Set UMASK {self.STRONG_UMASK_MIN:03o} in {source}. "
                    f"Also set in /etc/pam.d/common-session: "
                    f"'session optional pam_umask.so umask={self.STRONG_UMASK_MIN:03o}'."
                ),
                evidence=RegistryEvidence(
                    key=f"umask.{Path(str(source)).name}",
                    value=umask_str,
                    expected=f"{self.STRONG_UMASK_MIN:03o}",
                    source=str(source),
                ),
                detected_value=f"umask {umask_str} in {source}",
                expected_value=f"umask {self.STRONG_UMASK_MIN:03o} or stricter",
                affected_component=str(source),
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1222"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.4"],
                tags=["permissions", "umask", "hardening"],
            )
        )
        return findings

    def _extract_umask(self, filepath: str) -> tuple[str, str] | None:
        try:
            text = Path(filepath).read_text()
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "UMASK" in stripped.upper() and not stripped.upper().startswith("UMASK"):
                    continue
                if stripped.upper().startswith("UMASK"):
                    parts = stripped.split(None, 1)
                    if len(parts) >= 2:
                        return parts[1].strip(), filepath
                    if "=" in stripped:
                        _, val = stripped.split("=", 1)
                        return val.strip(), filepath
        except OSError:
            pass
        return None


@register_check
class CriticalDirectoryOwnershipCheck(AuditCheck):
    id = "PRM-405"
    name = "Critical Directory Ownership"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Checks that critical system directories are owned by root"
    depends = []
    tags = ["permissions", "ownership", "hardening"]

    CRITICAL_DIRS: list[str] = [
        "/etc",
        "/bin",
        "/sbin",
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/lib",
        "/lib64",
        "/opt",
        "/root",
        "/boot",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []

        for dirpath in self.CRITICAL_DIRS:
            path = Path(dirpath)
            if not path.is_dir():
                continue

            try:
                st = path.stat()
            except OSError:
                continue

            if st.st_uid == 0:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Critical directory not owned by root: {dirpath}",
                    description=(
                        f"'{dirpath}' is owned by uid {st.st_uid} instead of root (0). "
                        f"System directories must be owned by root to prevent privilege "
                        f"escalation."
                    ),
                    rationale=(
                        "Critical system directories not owned by root allow the owning "
                        "user to control the contents of the directory. An attacker who "
                        "compromises that user can plant malicious executables, libraries, "
                        "or configuration files that affect all users of the system."
                    ),
                    remediation=(
                        f"Fix ownership: 'chown root:root {dirpath}'."
                    ),
                    evidence=FileEvidence(
                        path=dirpath,
                        permission=oct(stat_module.S_IMODE(st.st_mode))[2:],
                        owner=str(st.st_uid),
                        group=str(st.st_gid),
                        content=f"Owned by uid {st.st_uid}, expected root",
                    ),
                    detected_value=f"Owner uid {st.st_uid}",
                    expected_value="Owner uid 0 (root)",
                    affected_component=dirpath,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1222"],
                    tags=["permissions", "ownership", "hardening"],
                )
            )
        return findings


@register_check
class SetuidWithoutExecuteCheck(AuditCheck):
    id = "PRM-406"
    name = "SUID/SGID Without Execute Permission"
    category = CheckCategory.PERMISSIONS
    severity = Severity.MEDIUM
    description = "Detects SUID/SGID files where the owner/group cannot execute them"
    depends = ["filesystem"]
    tags = ["suid", "sgid", "permissions", "misconfiguration"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = collectors.get("filesystem", {})
        suid_list = fs_data.get("suid_files", [])

        for entry in suid_list:
            path_str = entry.get("path", "")
            mode_str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)

            setuid = bool(mode_int & stat_module.S_ISUID)
            setgid = bool(mode_int & stat_module.S_ISGID)

            if not setuid and not setgid:
                continue

            has_owner_exec = bool(mode_int & stat_module.S_IXUSR)
            has_group_exec = bool(mode_int & stat_module.S_IXGRP)

            issues: list[str] = []
            if setuid and not has_owner_exec:
                issues.append("SUID without owner execute")
            if setgid and not has_group_exec:
                issues.append("SGID without group execute")

            if not issues:
                continue

            bits = "+".join(p for p, b in [("SUID", setuid), ("SGID", setgid)] if b)

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Inert setuid/setgid: {path_str}",
                    description=(
                        f"'{path_str}' has {bits} set (mode {mode_str}) but "
                        f"{' and '.join(issues)}. The privilege elevation bits "
                        f"have no effect."
                    ),
                    rationale=(
                        "SUID/SGID bits on non-executable files are inert — they "
                        "do not grant any privilege. This usually indicates a "
                        "misconfiguration, failed attack attempt, or data corruption. "
                        "These inert bits should be removed to avoid confusion during "
                        "security audits and incident response."
                    ),
                    remediation=(
                        f"Remove inert SUID/SGID: 'chmod u-s,g-s {path_str}'. "
                        f"If execution is needed: 'chmod u+x {path_str}'."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        owner=str(entry.get("uid", "")),
                        size=entry.get("size", 0),
                        content=f"{bits} without execute permission",
                    ),
                    detected_value=f"Mode {mode_str}: {bits} without execute",
                    expected_value="SUID/SGID require execute permission",
                    affected_component=path_str,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1548.001"],
                    tags=["suid", "sgid", "permissions", "misconfiguration"],
                )
            )
        return findings


@register_check
class UnexpectedSGIDOnFilesCheck(AuditCheck):
    id = "PRM-407"
    name = "SGID on Non-Extutable Files"
    category = CheckCategory.PERMISSIONS
    severity = Severity.LOW
    description = "Detects files with SGID set that have no execute permission and are not binaries"
    depends = ["filesystem"]
    tags = ["sgid", "permissions", "anomaly"]

    SGID_BINARY_EXTENSIONS: set[str] = {
        "", ".so", ".o", ".a",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = collectors.get("filesystem", {})
        suid_list = fs_data.get("suid_files", [])

        for entry in suid_list:
            path_str = entry.get("path", "")
            mode_str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)

            if not (mode_int & stat_module.S_ISGID):
                continue
            if mode_int & stat_module.S_IXUSR:
                continue

            ext = Path(path_str).suffix
            if ext in self.SGID_BINARY_EXTENSIONS:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"SGID on non-executable file: {path_str}",
                    description=(
                        f"'{path_str}' has SGID set (mode {mode_str}) but is not "
                        f"executable and is not a binary/library file."
                    ),
                    rationale=(
                        "SGID on non-executable files that aren't binaries or libraries "
                        "is unusual. The SGID bit has no effect on non-executable files, "
                        "so this may indicate a misconfiguration, a failed exploit attempt, "
                        "or data corruption. These should be investigated and cleaned up."
                    ),
                    remediation=(
                        f"Remove SGID if not needed: 'chmod g-s {path_str}'. "
                        f"Investigate the file's origin."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        owner=str(entry.get("uid", "")),
                        size=entry.get("size", 0),
                        content="SGID on non-executable, non-binary file",
                    ),
                    detected_value=f"SGID on {path_str} (mode {mode_str})",
                    expected_value="SGID only on executables or libraries",
                    affected_component=path_str,
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1548.001"],
                    tags=["sgid", "permissions", "anomaly"],
                )
            )
        return findings


@register_check
class DangerousCapabilityCombinationsCheck(AuditCheck):
    id = "PRM-408"
    name = "Dangerous Capability Combinations"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Detects files with dangerous combinations of Linux capabilities"
    depends = ["filesystem"]
    tags = ["capabilities", "privilege-escalation", "permissions"]

    DANGEROUS_COMBOS: list[dict[str, Any]] = [
        {
            "caps": {"cap_sys_admin", "cap_dac_override"},
            "name": "Full system access (CAP_SYS_ADMIN + CAP_DAC_OVERRIDE)",
            "severity": Severity.CRITICAL,
        },
        {
            "caps": {"cap_sys_admin", "cap_dac_read_search"},
            "name": "System admin + read bypass (CAP_SYS_ADMIN + CAP_DAC_READ_SEARCH)",
            "severity": Severity.CRITICAL,
        },
        {
            "caps": {"cap_setuid", "cap_setgid"},
            "name": "Full identity control (CAP_SETUID + CAP_SETGID)",
            "severity": Severity.CRITICAL,
        },
        {
            "caps": {"cap_sys_ptrace", "cap_sys_admin"},
            "name": "Process injection with admin (CAP_SYS_PTRACE + CAP_SYS_ADMIN)",
            "severity": Severity.HIGH,
        },
        {
            "caps": {"cap_net_raw", "cap_sys_admin"},
            "name": "Network raw + system admin",
            "severity": Severity.HIGH,
        },
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = collectors.get("filesystem", {})
        caps_list = fs_data.get("capabilities", [])

        for entry in caps_list:
            path_str = entry.get("path", "")
            caps_raw = entry.get("capabilities", "")
            caps_lower = caps_raw.lower().replace(",", " ")
            caps_set = set()
            for raw_token in caps_lower.split():
                clean = raw_token.split("=", 1)[0].strip()
                if clean:
                    caps_set.add(clean)

            for combo in self.DANGEROUS_COMBOS:
                required = combo["caps"]
                if not required.issubset(caps_set):
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Dangerous capability combo: {combo['name']}",
                        description=(
                            f"'{path_str}' has {combo['name']}: {caps_raw}. "
                            f"This combination grants extensive system privileges."
                        ),
                        rationale=(
                            "Certain combinations of Linux capabilities compound to "
                            "grant near-root or full-root privileges. For example, "
                            "CAP_SYS_ADMIN + CAP_DAC_OVERRIDE together allow a "
                            "process to bypass virtually all kernel security checks. "
                            "These combinations should never appear on non-system binaries."
                        ),
                        remediation=(
                            f"Review capabilities on '{path_str}': 'getcap {path_str}'. "
                            f"Remove dangerous caps: 'setcap -r {path_str}'. "
                            f"Or restrict to only needed capabilities."
                        ),
                        evidence=FileEvidence(
                            path=path_str,
                            content=f"Capabilities: {caps_raw}",
                        ),
                        detected_value=f"{combo['name']} on {path_str}",
                        expected_value="No dangerous capability combinations",
                        affected_component=path_str,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1548.001"],
                        tags=["capabilities", "privilege-escalation", "permissions"],
                    )
                )
        return findings
