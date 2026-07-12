from __future__ import annotations

import datetime
import os
import stat
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class SensitiveFilePermissionsCheck(AuditCheck):
    id = "FS-601"
    name = "Sensitive File Permissions"
    category = CheckCategory.FILESYSTEM
    severity = Severity.HIGH
    description = "Checks that sensitive system files have appropriate restrictive permissions"
    depends = []
    tags = ["filesystem", "permissions", "sensitive-files", "hardening"]

    SENSITIVE_FILES: list[dict[str, Any]] = [
        {"path": "/etc/shadow", "max_perms": 0o640, "owner": 0},
        {"path": "/etc/gshadow", "max_perms": 0o640, "owner": 0},
        {"path": "/etc/security/opasswd", "max_perms": 0o600, "owner": 0},
        {"path": "/etc/ssh/ssh_host_rsa_key", "max_perms": 0o600, "owner": 0},
        {"path": "/etc/ssh/ssh_host_ecdsa_key", "max_perms": 0o600, "owner": 0},
        {"path": "/etc/ssh/ssh_host_ed25519_key", "max_perms": 0o600, "owner": 0},
        {"path": "/etc/ssh/sshd_config", "max_perms": 0o644, "owner": 0},
        {"path": "/etc/sudoers", "max_perms": 0o440, "owner": 0},
        {"path": "/etc/sudoers.d", "max_perms": 0o550, "owner": 0},
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []

        for entry in self.SENSITIVE_FILES:
            path = Path(entry["path"])
            if not path.exists():
                continue

            try:
                st = path.stat()
            except OSError:
                continue

            mode = stat.S_IMODE(st.st_mode)
            max_perms = entry["max_perms"]
            owner_ok = st.st_uid == entry["owner"]

            issues: list[str] = []
            if not owner_ok:
                issues.append(f"owned by uid {st.st_uid} instead of {entry['owner']}")

            if mode & ~max_perms & (stat.S_IRWXO | stat.S_IWGRP):
                perms_str = oct(mode)[2:]
                issues.append(f"permissions {perms_str} (too permissive)")

            if not issues:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Weak permissions on {entry['path']}",
                    description=(
                        f"'{entry['path']}' has {', '.join(issues)}. "
                        f"Expected mode {oct(max_perms)[2:]} owned by uid {entry['owner']}."
                    ),
                    rationale=(
                        "Sensitive system files with overly permissive access allow "
                        "unauthorized users to read or modify critical authentication "
                        "and configuration data. Exposure of shadow files leaks password "
                        "hashes; exposed SSH private keys enable credential theft."
                    ),
                    remediation=(
                        f"Fix permissions: 'chmod {oct(max_perms)[2:]} {entry['path']}'."
                        + (f" Fix owner: 'chown {entry['owner']} {entry['path']}'." if not owner_ok else "")
                    ),
                    evidence=FileEvidence(
                        path=entry["path"],
                        permission=oct(mode)[2:],
                        owner=str(st.st_uid),
                        group=str(st.st_gid),
                        size=st.st_size,
                        modified=datetime.datetime.fromtimestamp(st.st_mtime),
                    ),
                    detected_value=f"Permissions {oct(mode)[2:]}, uid {st.st_uid}",
                    expected_value=f"Mode {oct(max_perms)[2:]}, uid {entry['owner']}",
                    affected_component=entry["path"],
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1222"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.1"],
                    tags=["filesystem", "permissions", "sensitive-files", "hardening"],
                )
            )
        return findings


@register_check
class HomeDirectoryPermissionsCheck(AuditCheck):
    id = "FS-602"
    name = "Home Directory Permissions"
    category = CheckCategory.FILESYSTEM
    severity = Severity.MEDIUM
    description = "Checks that user home directories are not world-readable or world-writable"
    depends = ["users"]
    tags = ["filesystem", "home", "permissions", "privacy"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")
        users = users_data.get("users", [])

        for user_entry in users:
            home = user_entry.get("home", "")
            uid = user_entry.get("uid", 0)

            if not home or home == "/nonexistent" or uid < 1000:
                continue

            home_path = Path(home)
            if not home_path.is_dir():
                continue

            try:
                st = home_path.stat()
            except OSError:
                continue

            mode = stat.S_IMODE(st.st_mode)
            issues: list[str] = []

            if mode & stat.S_IWOTH:
                issues.append("world-writable")
            if mode & stat.S_IROTH:
                issues.append("world-readable")

            if not issues:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Insecure home directory: {home}",
                    description=(
                        f"Home directory '{home}' for uid {uid} has "
                        f"{' and '.join(issues)} permissions ({oct(mode)[2:]}). "
                        f"This exposes user files to other system users."
                    ),
                    rationale=(
                        "World-readable home directories allow any user on the system to "
                        "access personal files, SSH keys, browser data, and credentials. "
                        "World-writable home directories allow other users to plant "
                        "malicious files like .bashrc or .ssh/authorized_keys."
                    ),
                    remediation=(
                        f"Restrict permissions: 'chmod 750 {home}'. "
                        f"If the user needs group access: 'chmod 770 {home}'. "
                        f"Remove world access: 'chmod o-rwx {home}'."
                    ),
                    evidence=FileEvidence(
                        path=home,
                        permission=oct(mode)[2:],
                        owner=str(st.st_uid),
                        group=str(st.st_gid),
                        content=f"Home directory for uid {uid}",
                    ),
                    detected_value=f"Permissions {oct(mode)[2:]} on {home}",
                    expected_value="Home directory not world-readable or world-writable",
                    affected_component=home,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1222"],
                    tags=["filesystem", "home", "permissions", "privacy"],
                )
            )
        return findings


@register_check
class WorldWritableStickyBitCheck(AuditCheck):
    id = "FS-603"
    name = "Sticky Bit on World-Writable Directories"
    category = CheckCategory.FILESYSTEM
    severity = Severity.MEDIUM
    description = "Verifies that key world-writable directories have the sticky bit set"
    depends = []
    tags = ["filesystem", "sticky-bit", "permissions", "hardening"]

    CRITICAL_WW_DIRS: list[str] = [
        "/tmp",
        "/var/tmp",
        "/dev/shm",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        for dirpath in self.CRITICAL_WW_DIRS:
            path = Path(dirpath)
            if not path.is_dir():
                continue

            try:
                st = path.stat()
            except OSError:
                continue

            mode = stat.S_IMODE(st.st_mode)

            if mode & stat.S_ISVTX:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Missing sticky bit on {dirpath}",
                    description=(
                        f"'{dirpath}' is world-writable but does not have the sticky bit "
                        f"set. Current permissions: {oct(mode)[2:]}."
                    ),
                    rationale=(
                        "The sticky bit on world-writable directories prevents users from "
                        "deleting or renaming files owned by other users. Without it, any "
                        "user can delete or replace files in /tmp and similar directories, "
                        "enabling TOCTOU race attacks and file planting."
                    ),
                    remediation=(
                        f"Set sticky bit: 'chmod +t {dirpath}'. "
                        f"Verify: 'ls -ld {dirpath}'."
                    ),
                    evidence=FileEvidence(
                        path=dirpath,
                        permission=oct(mode)[2:],
                        owner=str(st.st_uid),
                        content="Missing sticky bit on world-writable directory",
                    ),
                    detected_value=f"Permissions {oct(mode)[2:]} without sticky bit",
                    expected_value=f"Permissions with sticky bit (e.g., 1777) on {dirpath}",
                    affected_component=dirpath,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1222"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.1"],
                    tags=["filesystem", "sticky-bit", "permissions", "hardening"],
                )
            )
        return findings


@register_check
class TempDirMountSecurityCheck(AuditCheck):
    id = "FS-604"
    name = "Temporary Directory Mount Security"
    category = CheckCategory.FILESYSTEM
    severity = Severity.HIGH
    description = "Checks that /tmp, /var/tmp, and /dev/shm are mounted with noexec, nosuid, nodev"
    depends = ["mounts"]
    tags = ["filesystem", "mounts", "temp", "hardening"]

    SECURE_TEMP_DIRS: dict[str, list[str]] = {
        "/tmp": ["noexec", "nosuid", "nodev"],
        "/var/tmp": ["noexec", "nosuid", "nodev"],
        "/dev/shm": ["noexec", "nosuid", "nodev"],
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        mounts_data = self._get_data(collectors, "mounts")
        mounts = mounts_data.get("mounts", [])

        mount_map: dict[str, dict[str, Any]] = {}
        for m in mounts:
            mount_map[m.get("mount_point", "")] = m

        for dirpath, required_options in self.SECURE_TEMP_DIRS.items():
            mount = mount_map.get(dirpath)
            if mount is None:
                continue

            options_str = mount.get("options", "")
            options = set(options_str.split(","))

            missing: list[str] = [opt for opt in required_options if opt not in options]

            if not missing:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Insecure mount options on {dirpath}",
                    description=(
                        f"'{dirpath}' is missing security mount options: "
                        f"{', '.join(missing)}. Current options: {options_str}."
                    ),
                    rationale=(
                        "Temporary directories without noexec allow direct execution of "
                        "binaries by attackers. Without nosuid, SUID binaries can be used "
                        "for privilege escalation. Without nodev, device nodes can be "
                        "created to access raw disk or memory."
                    ),
                    remediation=(
                        f"Add to /etc/fstab for '{mount.get('device', dirpath)} {dirpath}': "
                        f"'defaults,{','.join(missing)} 0 0'. "
                        f"Remount: 'mount -o remount,{','.join(missing)} {dirpath}'."
                    ),
                    evidence=RegistryEvidence(
                        key=f"mount.{dirpath}.options",
                        value=options_str,
                        expected=f"defaults,{','.join(missing)}",
                        source="/proc/mounts",
                    ),
                    detected_value=f"Missing {', '.join(missing)} on {dirpath}",
                    expected_value=f"{'/'.join(required_options)} set on {dirpath}",
                    affected_component=dirpath,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1222"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.1"],
                    tags=["hardening", "mounts", "temp", "filesystem"],
                )
            )
        return findings


@register_check
class FilesystemSpaceCheck(AuditCheck):
    id = "FS-605"
    name = "Filesystem Space Exhaustion Risk"
    category = CheckCategory.FILESYSTEM
    severity = Severity.MEDIUM
    description = "Identifies mounted filesystems at risk of space exhaustion (>90% usage)"
    depends = ["mounts"]
    tags = ["filesystem", "disk-space", "monitoring", "availability"]
    max_findings = 20

    CRITICAL_THRESHOLD = 90.0

    MONITORED_MOUNTS: set[str] = {
        "/", "/var", "/var/log", "/var/log/audit",
        "/home", "/tmp", "/boot", "/opt",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        mounts_data = self._get_data(collectors, "mounts")
        disk_usage = mounts_data.get("disk_usage", {})
        mounts = mounts_data.get("mounts", [])

        mount_fstypes: dict[str, str] = {}
        for m in mounts:
            mount_fstypes[m.get("mount_point", "")] = m.get("fstype", "")

        for mount_point, _total_bytes in disk_usage.items():
            if mount_point not in self.MONITORED_MOUNTS and mount_point not in disk_usage:
                continue

            if not self._should_monitor(mount_point, mount_fstypes):
                continue

            usage_pct = self._get_usage_pct(mount_point)
            if usage_pct is None:
                continue

            if usage_pct < self.CRITICAL_THRESHOLD:
                continue

            fstype = mount_fstypes.get(mount_point, "unknown")

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Filesystem space critical: {mount_point}",
                    description=(
                        f"'{mount_point}' ({fstype}) is at {usage_pct:.1f}% capacity. "
                        f"This may cause system instability, audit log loss, and "
                        f"service failures."
                    ),
                    rationale=(
                        "Filesystem space exhaustion is a common denial-of-service vector. "
                        "Full /var partitions prevent logging (covering attacker tracks). "
                        "Full / partitions can crash the system. Monitoring space usage "
                        "is critical for availability and forensic readiness."
                    ),
                    remediation=(
                        f"Free space on {mount_point}: "
                        f"'du -sh {mount_point}/* | sort -rh | head -10' to find large files. "
                        f"Remove unnecessary files, rotate logs, or add disk capacity."
                    ),
                    evidence=RegistryEvidence(
                        key=f"disk.{mount_point}.usage_pct",
                        value=f"{usage_pct:.1f}%",
                        expected=f"<{self.CRITICAL_THRESHOLD:.0f}%",
                        source=f"statvfs({mount_point})",
                    ),
                    detected_value=f"{usage_pct:.1f}% used on {mount_point}",
                    expected_value=f"Less than {self.CRITICAL_THRESHOLD:.0f}% used",
                    affected_component=mount_point,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1499"],
                    tags=["filesystem", "disk-space", "monitoring", "availability"],
                )
            )
        return findings

    def _should_monitor(self, mount_point: str, fstypes: dict[str, str]) -> bool:
        fstype = fstypes.get(mount_point, "")
        if fstype in ("proc", "sysfs", "tmpfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "efivarfs", "pstore", "securityfs", "bpf", "debugfs", "tracefs", "configfs", "autofs", "overlay", "squashfs"):
            return False
        if mount_point.startswith("/snap/"):
            return False
        return not mount_point.startswith("/var/lib/snapd/")

    def _get_usage_pct(self, mount_point: str) -> float | None:
        try:
            st = os.statvfs(mount_point)
            total = st.f_frsize * st.f_blocks
            free = st.f_frsize * st.f_bfree
            if total == 0:
                return None
            return (1.0 - free / total) * 100.0
        except OSError:
            return None


@register_check
class DotFilePermissionHijackingCheck(AuditCheck):
    id = "FS-606"
    name = "Dot-File Permission Hijacking"
    category = CheckCategory.FILESYSTEM
    severity = Severity.HIGH
    description = "Checks for world-writable shell init files in user home directories"
    depends = ["users"]
    tags = ["filesystem", "dotfiles", "permissions", "persistence"]

    INIT_FILES: list[str] = [
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
        ".zlogin",
        ".cshrc",
        ".tcshrc",
        ".kshrc",
        ".shrc",
        ".config/autostart",
        ".local/share/applications",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")
        users = users_data.get("users", [])

        for user_entry in users:
            home = user_entry.get("home", "")
            uid = user_entry.get("uid", 0)

            if not home or home == "/nonexistent" or uid < 1000:
                continue

            for init_file in self.INIT_FILES:
                full_path = Path(home) / init_file
                if not full_path.exists():
                    continue

                try:
                    st = full_path.stat()
                except OSError:
                    continue

                mode = stat.S_IMODE(st.st_mode)

                if not (mode & stat.S_IWOTH):
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"World-writable init file: {full_path}",
                        description=(
                            f"'{full_path}' is world-writable (permissions {oct(mode)[2:]}). "
                            f"Any user can modify this shell initialization file, "
                            f"executing arbitrary code when the user logs in."
                        ),
                        rationale=(
                            "World-writable shell init files are a high-risk persistence "
                            "vector. Any user on the system can inject malicious commands "
                            "that execute when the target user logs in, enabling lateral "
                            "movement, credential theft, and privilege escalation."
                        ),
                        remediation=(
                            f"Restrict permissions: 'chmod 644 {full_path}'. "
                            f"If the file should be executable: 'chmod 755 {full_path}'."
                        ),
                        evidence=FileEvidence(
                            path=str(full_path),
                            permission=oct(mode)[2:],
                            owner=str(st.st_uid),
                            size=st.st_size,
                            content="World-writable shell init file",
                        ),
                        detected_value=f"World-writable ({oct(mode)[2:]})",
                        expected_value="Not world-writable",
                        affected_component=str(full_path),
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1546.004", "T1059"],
                        tags=["filesystem", "dotfiles", "permissions", "persistence"],
                    )
                )
        return findings


@register_check
class SystemBinaryOwnershipCheck(AuditCheck):
    id = "FS-607"
    name = "System Binary Root Ownership"
    category = CheckCategory.FILESYSTEM
    severity = Severity.HIGH
    description = "Checks that critical system binaries are owned by root"
    depends = []
    tags = ["filesystem", "binaries", "ownership", "integrity"]
    max_findings = 50

    SYSTEM_BIN_DIRS: list[str] = [
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        checked: set[str] = set()

        for bindir in self.SYSTEM_BIN_DIRS:
            path = Path(bindir)
            if not path.is_dir():
                continue

            try:
                for entry in path.iterdir():
                    if not entry.is_file() and not entry.is_symlink():
                        continue
                    try:
                        sp = str(entry)
                        if sp in checked:
                            continue
                        checked.add(sp)

                        st = entry.stat()
                        if st.st_uid == 0:
                            continue

                        findings.append(
                            self.finding(
                                finding_id="001",
                                title=f"Non-root owned binary: {sp}",
                                description=(
                                    f"'{sp}' is owned by uid {st.st_uid} instead of root (0). "
                                    f"System binaries must be owned by root to prevent "
                                    f"privilege escalation."
                                ),
                                rationale=(
                                    "System binaries not owned by root allow the owning user "
                                    "to modify or replace them. An attacker who compromises "
                                    "a non-root user can replace that user's binaries with "
                                    "malicious versions executed by other users or services."
                                ),
                                remediation=(
                                    f"Fix ownership: 'chown root:root {sp}'."
                                ),
                                evidence=FileEvidence(
                                    path=sp,
                                    permission=oct(stat.S_IMODE(st.st_mode)),
                                    owner=str(st.st_uid),
                                    group=str(st.st_gid),
                                    size=st.st_size,
                                    content=f"Owned by uid {st.st_uid}, expected root",
                                ),
                                detected_value=f"Owner uid {st.st_uid}",
                                expected_value="Owner uid 0 (root)",
                                affected_component=sp,
                                confidence=Confidence.HIGH,
                                false_positive_probability=0.1,
                                mitre_attack_ids=["T1222", "T1548"],
                                tags=["filesystem", "binaries", "ownership", "integrity"],
                            )
                        )
                    except OSError:
                        continue
            except PermissionError:
                continue

        return findings


@register_check
class WorldWritableCronDirectoriesCheck(AuditCheck):
    id = "FS-608"
    name = "World-Writable Cron and Script Directories"
    category = CheckCategory.FILESYSTEM
    severity = Severity.HIGH
    description = "Checks that cron, systemd, and script directories are not world-writable"
    depends = []
    tags = ["filesystem", "cron", "systemd", "persistence", "privilege-escalation"]

    SENSITIVE_SCRIPT_DIRS: list[str] = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
        "/etc/cron.d",
        "/etc/systemd/system",
        "/etc/systemd/user",
        "/usr/lib/systemd/system",
        "/etc/init.d",
        "/etc/rc.local",
        "/etc/profile.d",
        "/etc/bash.bashrc",
        "/etc/bashrc",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []

        for dirpath in self.SENSITIVE_SCRIPT_DIRS:
            path = Path(dirpath)
            if not path.exists():
                continue

            try:
                st = path.stat()
            except OSError:
                continue

            if not stat.S_ISDIR(st.st_mode) and not path.is_file():
                continue

            mode = stat.S_IMODE(st.st_mode)

            if not (mode & stat.S_IWOTH):
                continue

            entry_type = "directory" if path.is_dir() else "file"

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"World-writable {entry_type}: {dirpath}",
                    description=(
                        f"'{dirpath}' is world-writable (permissions {oct(mode)[2:]}). "
                        f"Any user on the system can modify scheduled tasks and "
                        f"startup scripts."
                    ),
                    rationale=(
                        "World-writable cron, systemd, and init directories allow any user "
                        "to add or modify scheduled tasks and startup scripts. This is a "
                        "high-risk persistence and privilege escalation vector — an attacker "
                        "can plant a cron job or systemd service that executes with root "
                        "privileges."
                    ),
                    remediation=(
                        f"Restrict permissions: 'chmod 755 {dirpath}'. "
                        f"Check for unauthorized files inside: 'ls -la {dirpath}'."
                    ),
                    evidence=FileEvidence(
                        path=dirpath,
                        permission=oct(mode)[2:],
                        owner=str(st.st_uid),
                        content=f"World-writable {entry_type}",
                    ),
                    detected_value=f"World-writable ({oct(mode)[2:]})",
                    expected_value="Not world-writable (e.g., 755)",
                    affected_component=dirpath,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1053", "T1543", "T1222"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.1"],
                    tags=["filesystem", "cron", "systemd", "persistence", "privilege-escalation"],
                )
            )
        return findings
