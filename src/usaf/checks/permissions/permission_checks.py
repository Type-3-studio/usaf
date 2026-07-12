from __future__ import annotations

import stat as stat_module
from typing import Any

from usaf.collectors.packages.apt import get_package_for_file
from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

DANGEROUS_CAPABILITIES: dict[str, str] = {
    "cap_sys_admin": "Full system administration (equivalent to root)",
    "cap_dac_override": "Bypass file read/write/execute permission checks",
    "cap_dac_read_search": "Bypass file read and directory search permission checks",
    "cap_setuid": "Arbitrarily change UID (privilege escalation)",
    "cap_setgid": "Arbitrarily change GID (privilege escalation)",
    "cap_sys_ptrace": "Debug and modify any process (memory/code injection)",
    "cap_sys_module": "Load/unload kernel modules (kernel code execution)",
    "cap_sys_boot": "Reboot the system",
    "cap_sys_rawio": "Raw I/O operations (disk/port access)",
    "cap_kill": "Send signals to any process (denial of service)",
    "cap_linux_immutable": "Set FS_APPEND_FL/FS_IMMUTABLE_FL on files",
    "cap_mknod": "Create device nodes",
    "cap_sys_time": "Change system clock",
}

KNOWN_SAFE_CAPABILITIES: dict[str, str] = {
    "cap_net_raw": "Raw sockets (ping, traceroute)",
    "cap_net_admin": "Network administration (DHCP, firewall)",
    "cap_net_bind_service": "Bind to privileged ports (<1024)",
    "cap_net_broadcast": "Socket broadcast",
    "cap_chown": "Change file ownership",
    "cap_fowner": "Bypass permission checks on own files",
    "cap_audit_write": "Write to audit log",
    "cap_audit_control": "Configure audit subsystem",
    "cap_ipc_lock": "Lock memory (mlock)",
    "cap_sys_nice": "Raise process priority",
    "cap_sys_resource": "Override resource limits",
    "cap_syslog": "Read kernel ring buffer (dmesg)",
    "cap_wake_alarm": "Wake system from suspend",
    "cap_block_suspend": "Block system suspend",
}

KNOWN_SGID_PACKAGES: set[str] = {
    "coreutils",
    "shadow",
    "util-linux",
    "util-linux-extra",
    "bsdutils",
    "login",
    "screen",
    "tmux",
    "openssh-client",
    "openssh-server",
    "cron",
    "anacron",
    "at",
    "postfix",
    "dovecot-core",
    "cups",
    "cups-bsd",
}

_builtin_sgid_allowlist: set[str] = {
    "/usr/bin/screen",
    "/usr/bin/ssh-agent",
    "/usr/bin/write",
    "/usr/bin/wall",
    "/usr/bin/lastlog",
    "/usr/bin/expiry",
    "/usr/bin/crontab",
    "/usr/bin/dotlockfile",
    "/usr/bin/mutt_dotlock",
    "/usr/sbin/unix_chkpwd",
}

_builtin_capability_allowlist: set[str] = {
    "/usr/bin/ping",
    "/bin/ping",
    "/usr/bin/traceroute6.iputils",
    "/usr/bin/arping",
    "/usr/sbin/arping",
    "/usr/bin/nmap",
    "/usr/sbin/chronyd",
    "/usr/lib/systemd/systemd-timesyncd",
    "/usr/lib/systemd/systemd-logind",
}


def _parse_mode_int(mode_str: str) -> int:
    try:
        return int(mode_str, 8)
    except (ValueError, TypeError):
        return 0


@register_check
class SGIDBinariesCheck(AuditCheck):
    id = "PRM-301"
    name = "Unexpected SGID Binaries"
    category = CheckCategory.PERMISSIONS
    severity = Severity.MEDIUM
    description = "Identifies SGID binaries not in the expected set or not owned by a known-safe package"
    depends = ["filesystem"]
    tags = ["sgid", "privilege-escalation", "permissions"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data: Any = collectors.get("filesystem")
        if not fs_data:
            return findings
        suid_list: list[dict[str, Any]] = fs_data.get("suid_files", [])

        for entry in suid_list:
            path_str: str = entry.get("path", "")
            mode_str: str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)
            if not (mode_int & stat_module.S_ISGID):
                continue
            if path_str in _builtin_sgid_allowlist:
                continue

            pkg = get_package_for_file(path_str)
            is_pkg_known = pkg is not None and pkg in KNOWN_SGID_PACKAGES
            confidence = Confidence.LOW if is_pkg_known else Confidence.MEDIUM
            fp_prob = 0.8 if is_pkg_known else 0.2
            evidence = FileEvidence(
                path=path_str,
                permission=mode_str,
                owner=str(entry.get("uid", "?")),
                size=entry.get("size", 0),
                content=f"Package: {pkg}" if pkg else "Not owned by any installed package",
            )
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected SGID binary: {path_str}",
                    description=(
                        f"'{path_str}' has the SGID bit set (mode {mode_str}). "
                        f"Package: {pkg or 'none'}. "
                        f"SGID binaries execute with the group of the file."
                    ),
                    rationale=(
                        "SGID binaries execute with the group of the file owner, "
                        "which can lead to privilege escalation if the group has "
                        "elevated permissions. Each SGID binary should be justified."
                    ),
                    remediation=(
                        f"Review whether '{path_str}' requires SGID. "
                        f"To remove: 'chmod g-s {path_str}'."
                    ),
                    evidence=evidence,
                    detected_value=f"SGID bit set on {path_str}",
                    expected_value="No unexpected SGID binaries",
                    affected_component=path_str,
                    confidence=confidence,
                    false_positive_probability=fp_prob,
                    mitre_attack_ids=["T1548.001"],
                    tags=["privilege-escalation", "sgid", "permissions"],
                )
            )

        return findings


@register_check
class DangerousCapabilitiesCheck(AuditCheck):
    id = "PRM-302"
    name = "Dangerous File Capabilities"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Detects files with Linux capabilities that grant effective root-equivalent privileges"
    depends = ["filesystem"]
    tags = ["capabilities", "privilege-escalation", "permissions"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data: Any = collectors.get("filesystem")
        if not fs_data:
            return findings
        caps_list: list[dict[str, Any]] = fs_data.get("capabilities", [])

        for entry in caps_list:
            path_str: str = entry.get("path", "")
            caps_raw: str = entry.get("capabilities", "")
            if not caps_raw:
                continue
            caps_lower = caps_raw.lower()
            found_dangerous = [
                (cap, desc) for cap, desc in DANGEROUS_CAPABILITIES.items()
                if cap in caps_lower
            ]
            if not found_dangerous:
                continue
            cap_desc = "; ".join(f"{cap} ({desc})" for cap, desc in found_dangerous)
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Dangerous capability on {path_str}",
                    description=f"'{path_str}' has dangerous capabilities: {cap_desc}",
                    rationale=(
                        "Certain Linux capabilities grant privileges equivalent to root. "
                        "cap_sys_admin, cap_dac_override, cap_setuid, and cap_sys_ptrace "
                        "are particularly dangerous as they allow complete system compromise "
                        "if the binary is compromised."
                    ),
                    remediation=(
                        f"Review the capabilities on '{path_str}'. "
                        f"Remove dangerous capabilities: "
                        f"'sudo setcap -r {path_str}'"
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        content=f"Capabilities: {caps_raw}",
                        permission=caps_raw,
                    ),
                    detected_value=caps_raw,
                    expected_value="No dangerous capabilities",
                    affected_component=path_str,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1548.003"],
                    tags=["capabilities", "privilege-escalation"],
                )
            )

        return findings


@register_check
class MissingStickyBitCheck(AuditCheck):
    id = "PRM-303"
    name = "World-Writable Directories Without Sticky Bit"
    category = CheckCategory.PERMISSIONS
    severity = Severity.MEDIUM
    description = "Detects world-writable directories missing the sticky bit"
    depends = ["filesystem"]
    tags = ["sticky-bit", "permissions", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data: Any = collectors.get("filesystem")
        if not fs_data:
            return findings
        ww_list: list[dict[str, Any]] = fs_data.get("world_writable", [])

        for entry in ww_list:
            if not entry.get("is_dir", False):
                continue
            mode_str: str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)
            if mode_int & stat_module.S_ISVTX:
                continue
            path_str: str = entry.get("path", "")
            if self._is_expected_writable_dir(path_str):
                continue
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"World-writable directory without sticky bit: {path_str}",
                    description=(
                        f"'{path_str}' is world-writable (mode {mode_str}) "
                        f"but missing the sticky bit."
                    ),
                    rationale=(
                        "World-writable directories without the sticky bit allow any user "
                        "to delete or rename files owned by other users. This is a classic "
                        "TOC/TOU (time of check, time of use) attack vector where an attacker "
                        "replaces a file with a malicious version."
                    ),
                    remediation=(
                        f"Add sticky bit: 'chmod +t {path_str}'. "
                        f"If this directory should not be world-writable: "
                        f"'chmod o-w {path_str}'."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        owner=str(entry.get("uid", "?")),
                    ),
                    detected_value=f"Mode {mode_str}, no sticky bit",
                    expected_value="Sticky bit set on world-writable directory",
                    affected_component=path_str,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1548.001", "T1574.002"],
                    tags=["sticky-bit", "privilege-escalation"],
                )
            )

        return findings

    @staticmethod
    def _is_expected_writable_dir(path_str: str) -> bool:
        expected = {
            "/tmp",
            "/var/tmp",
            "/dev/shm",
        }
        return path_str.rstrip("/") in expected


@register_check
class WorldWritablePathExecutablesCheck(AuditCheck):
    id = "PRM-304"
    name = "World-Writable Executables in PATH"
    category = CheckCategory.PERMISSIONS
    severity = Severity.CRITICAL
    description = "Detects world-writable executable files in system PATH directories"
    depends = ["filesystem"]
    tags = ["world-writable", "privilege-escalation", "permissions"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data: Any = collectors.get("filesystem")
        if not fs_data:
            return findings
        exec_list: list[dict[str, Any]] = fs_data.get("path_executables", [])

        for entry in exec_list:
            mode_str: str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)
            if not (mode_int & stat_module.S_IWOTH):
                continue
            path_str: str = entry.get("path", "")
            pkg = get_package_for_file(path_str)
            if pkg is not None:
                continue
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"World-writable executable in PATH: {path_str}",
                    description=(
                        f"'{path_str}' is world-writable (mode {mode_str}) "
                        f"and not owned by any installed package."
                    ),
                    rationale=(
                        "World-writable executables in PATH allow any user to "
                        "replace or modify the binary. When another user (especially "
                        "root) runs the command, the attacker's code executes with "
                        "the target user's privileges — enabling privilege escalation, "
                        "persistence, and lateral movement."
                    ),
                    remediation=(
                        f"Remove world-writable permissions: 'chmod o-w {path_str}'. "
                        f"If the file is malicious: 'rm {path_str}' and reinstall "
                        f"the affected package."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        owner=str(entry.get("uid", "?")),
                        size=entry.get("size", 0),
                    ),
                    detected_value=f"World-writable: {mode_str}",
                    expected_value="Not world-writable",
                    affected_component=path_str,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.02,
                    mitre_attack_ids=["T1574.001", "T1574.002"],
                    tags=["world-writable", "privilege-escalation"],
                )
            )

        return findings


@register_check
class SetuidShellScriptsCheck(AuditCheck):
    id = "PRM-305"
    name = "SUID/SGID Shell Scripts"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Detects shell scripts with SUID/SGID bits set"
    depends = ["filesystem"]
    tags = ["suid", "sgid", "scripts", "privilege-escalation"]

    _script_shebangs: set[bytes] = {
        b"#!/bin/sh",
        b"#!/bin/bash",
        b"#!/bin/dash",
        b"#!/bin/zsh",
        b"#!/bin/ksh",
        b"#!/usr/bin/sh",
        b"#!/usr/bin/bash",
        b"#!/usr/bin/dash",
        b"#!/usr/bin/zsh",
        b"#!/usr/bin/ksh",
        b"#!/usr/bin/python",
        b"#!/usr/bin/python3",
        b"#!/usr/bin/env python",
        b"#!/usr/bin/env python3",
        b"#!/usr/bin/perl",
        b"#!/usr/bin/env perl",
        b"#!/usr/bin/ruby",
        b"#!/usr/bin/env ruby",
        b"#!/usr/bin/lua",
        b"#!/usr/bin/env lua",
        b"#!" + b"/usr/bin/node",
        b"#!" + b"/usr/bin/env node",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data: Any = collectors.get("filesystem")
        if not fs_data:
            return findings
        suid_list: list[dict[str, Any]] = fs_data.get("suid_files", [])

        for entry in suid_list:
            path_str: str = entry.get("path", "")
            mode_str: str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)
            if not (mode_int & (stat_module.S_ISUID | stat_module.S_ISGID)):
                continue
            if not self._is_script(path_str):
                continue
            setuid = bool(mode_int & stat_module.S_ISUID)
            setgid = bool(mode_int & stat_module.S_ISGID)
            bits = "+".join(
                p for p, b in [("SUID", setuid), ("SGID", setgid)] if b
            )
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Setuid shell script: {path_str}",
                    description=(
                        f"'{path_str}' is a shell script with {bits} set "
                        f"(mode {mode_str})."
                    ),
                    rationale=(
                        "Setuid shell scripts are dangerous because they can be "
                        "subverted through shell metacharacters, environment variables "
                        "(SHELLOPTS, IFS, PATH), or race conditions. "
                        "Most modern Linux systems ignore setuid on interpreted scripts "
                        "for this reason."
                    ),
                    remediation=(
                        f"Remove {bits} from '{path_str}': "
                        f"'chmod {'u-s' if setuid else ''}{'g-s' if setgid else ''} {path_str}'. "
                        f"Use a compiled wrapper or capabilities instead."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        size=entry.get("size", 0),
                        content=self._get_first_line(path_str),
                    ),
                    detected_value=f"{bits} shell script at {path_str}",
                    expected_value="No setuid shell scripts",
                    affected_component=path_str,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1548.001"],
                    tags=["suid", "scripts", "privilege-escalation"],
                )
            )

        return findings

    @staticmethod
    def _is_script(path_str: str) -> bool:
        try:
            with open(path_str, "rb") as f:
                header = f.read(32)
            for shebang in SetuidShellScriptsCheck._script_shebangs:
                if header.startswith(shebang):
                    return True
            return False
        except OSError:
            return False

    @staticmethod
    def _get_first_line(path_str: str) -> str | None:
        try:
            with open(path_str, "rb") as f:
                return f.readline().decode("utf-8", errors="replace").strip()
        except OSError:
            return None


@register_check
class NonRootSetuidOwnershipCheck(AuditCheck):
    id = "PRM-306"
    name = "SUID/SGID Files Not Owned by Root"
    category = CheckCategory.PERMISSIONS
    severity = Severity.MEDIUM
    description = "Detects SUID/SGID files owned by users other than root"
    depends = ["filesystem"]
    tags = ["suid", "sgid", "ownership", "permissions"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data: Any = collectors.get("filesystem")
        if not fs_data:
            return findings
        suid_list: list[dict[str, Any]] = fs_data.get("suid_files", [])

        for entry in suid_list:
            path_str: str = entry.get("path", "")
            uid: int = entry.get("uid", 0)
            if uid == 0:
                continue
            mode_str: str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)
            if not (mode_int & (stat_module.S_ISUID | stat_module.S_ISGID)):
                continue
            setuid = bool(mode_int & stat_module.S_ISUID)
            setgid = bool(mode_int & stat_module.S_ISGID)
            bits = "+".join(
                p for p, b in [("SUID", setuid), ("SGID", setgid)] if b
            )
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Setuid file owned by non-root user: {path_str}",
                    description=(
                        f"'{path_str}' has {bits} set but is owned by UID {uid} "
                        f"(mode {mode_str})."
                    ),
                    rationale=(
                        "SUID/SGID files should normally be owned by root. "
                        "A non-root owner with a setuid binary can escalate "
                        "to that user's privileges. This may indicate a "
                        "misconfiguration or tampering."
                    ),
                    remediation=(
                        f"Change ownership to root: 'chown root {path_str}'. "
                        f"Or remove setuid/setgid bits if not required."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        owner=str(uid),
                        size=entry.get("size", 0),
                    ),
                    detected_value=f"Owner UID={uid}, {bits}",
                    expected_value="SUID/SGID files owned by root (UID 0)",
                    affected_component=path_str,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.15,
                    mitre_attack_ids=["T1548.001"],
                    tags=["suid", "sgid", "ownership"],
                )
            )

        return findings


@register_check
class UnexpectedCapabilitiesCheck(AuditCheck):
    id = "PRM-307"
    name = "Unexpected File Capabilities"
    category = CheckCategory.PERMISSIONS
    severity = Severity.MEDIUM
    description = "Detects files with capabilities that are not from known packages"
    depends = ["filesystem"]
    tags = ["capabilities", "permissions", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data: Any = collectors.get("filesystem")
        if not fs_data:
            return findings
        caps_list: list[dict[str, Any]] = fs_data.get("capabilities", [])

        for entry in caps_list:
            path_str: str = entry.get("path", "")
            caps_raw: str = entry.get("capabilities", "")
            if not caps_raw:
                continue
            if path_str in _builtin_capability_allowlist:
                continue
            pkg = get_package_for_file(path_str)
            if pkg is not None:
                continue
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Capabilities on untracked binary: {path_str}",
                    description=(
                        f"'{path_str}' has capabilities ({caps_raw}) "
                        f"but is not from any installed package."
                    ),
                    rationale=(
                        "Files with capabilities gain special privileges. "
                        "When found on binaries not owned by any package, "
                        "this is highly suspicious — the binary may be "
                        "an attacker-placed backdoor with extra privileges."
                    ),
                    remediation=(
                        f"Investigate '{path_str}'. Remove capabilities: "
                        f"'sudo setcap -r {path_str}'. "
                        f"If malicious, remove the file and scan for malware."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        content=f"Capabilities: {caps_raw}",
                        permission=caps_raw,
                    ),
                    detected_value=caps_raw,
                    expected_value="No capabilities on untracked binaries",
                    affected_component=path_str,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1548.003"],
                    tags=["capabilities", "persistence"],
                )
            )

        return findings


@register_check
class WorldWritableSetuidFilesCheck(AuditCheck):
    id = "PRM-308"
    name = "World-Writable SUID/SGID Files"
    category = CheckCategory.PERMISSIONS
    severity = Severity.CRITICAL
    description = "Detects SUID/SGID files that are world-writable"
    depends = ["filesystem"]
    tags = ["suid", "sgid", "world-writable", "privilege-escalation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data: Any = collectors.get("filesystem")
        if not fs_data:
            return findings
        suid_list: list[dict[str, Any]] = fs_data.get("suid_files", [])

        for entry in suid_list:
            path_str: str = entry.get("path", "")
            mode_str: str = entry.get("mode", "")
            mode_int = _parse_mode_int(mode_str)
            if not (mode_int & (stat_module.S_ISUID | stat_module.S_ISGID)):
                continue
            if not (mode_int & stat_module.S_IWOTH):
                continue
            setuid = bool(mode_int & stat_module.S_ISUID)
            setgid = bool(mode_int & stat_module.S_ISGID)
            bits = "+".join(
                p for p, b in [("SUID", setuid), ("SGID", setgid)] if b
            )
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"World-writable setuid file: {path_str}",
                    description=(
                        f"'{path_str}' has {bits} set AND is world-writable "
                        f"(mode {mode_str})."
                    ),
                    rationale=(
                        "A world-writable SUID/SGID binary allows any user to "
                        "replace the file with arbitrary code that executes "
                        "with elevated privileges. This is one of the most "
                        "dangerous permission combinations — it grants immediate "
                        "root or group privilege escalation."
                    ),
                    remediation=(
                        f"Remove world-writable permissions: 'chmod o-w {path_str}'. "
                        f"Also consider removing SUID/SGID if not required: "
                        f"'chmod {'u-s ' if setuid else ''}{'g-s' if setgid else ''}{path_str}'."
                    ),
                    evidence=FileEvidence(
                        path=path_str,
                        permission=mode_str,
                        owner=str(entry.get("uid", "?")),
                        size=entry.get("size", 0),
                    ),
                    detected_value=f"Mode {mode_str}: {bits} + world-writable",
                    expected_value="SUID/SGID files must not be world-writable",
                    affected_component=path_str,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1548.001"],
                    tags=["suid", "sgid", "world-writable", "privilege-escalation"],
                )
            )

        return findings
