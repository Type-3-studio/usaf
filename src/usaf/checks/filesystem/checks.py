from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from usaf.collectors.packages.apt import get_package_for_file
from usaf.collectors.packages.resolver import resolve_package
from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import CommandEvidence, FileEvidence, ProcessEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class UnexpectedFilesInEtcCheck(AuditCheck):
    id = "FS-101"
    name = "Unexpected Files in /etc"
    category = CheckCategory.FILESYSTEM
    severity = Severity.MEDIUM
    description = "Identifies files in /etc not owned by any package and not in the known set"
    depends = ["filesystem"]
    tags = ["filesystem", "etc", "file-integrity"]

    KNOWN_ETC_FILES: set[str] = {
        "passwd", "shadow", "group", "gshadow",
        "hosts", "hostname", "fstab", "mtab",
        "resolv.conf", "nsswitch.conf", "hosts.allow", "hosts.deny",
        "issue", "issue.net", "motd",
        "profile", "bash.bashrc", "bashrc", "inputrc",
        "environment", "default", "skel",
        "crontab", "cron.d", "cron.daily", "cron.hourly",
        "cron.monthly", "cron.weekly",
        "aliases", "mailname",
        "shells", "sudoers", "sudoers.d",
        "timezone", "localtime",
        "ld.so.conf", "ld.so.conf.d", "ld.so.cache",
        "kernel", "modules", "modprobe.d", "modprobe.conf",
        "sysctl.conf", "sysctl.d",
        "security", "pam.d", "pam.conf",
        "networks", "protocols", "services", "rpc",
        "apt", "apt.conf", "apt.conf.d", "apt_preferences.d",
        "cifs-utils", "samba",
        "ssh", "ssh_config", "sshd_config",
        "ca-certificates", "ssl", "certs",
        "init.d", "rc0.d", "rc1.d", "rc2.d", "rc3.d",
        "rc4.d", "rc5.d", "rc6.d", "rcS.d",
        "init", "inittab",
        "sysconfig", "NetworkManager", "network",
        "logrotate.d", "logrotate.conf",
        "rsyslog.conf", "rsyslog.d",
        "ufw", "ufw.conf",
        "apparmor.d", "apparmor",
        "systemd", "systemd/system",
        "machine-id", "machine-info",
        "host.conf", "hosts.equiv",
        "update-motd.d",
        "legal", "lsb-release", "os-release",
        "selinux",
        "adduser.conf", "deluser.conf",
        "debconf.conf", "dpkg",
        "python3", "python3.10", "python3.11", "python3.12",
        "ImageMagick-6",
        "terminfo",
        "mke2fs.conf",
        "libaudit.conf",
        "request-key.conf",
        "wgetrc",
        "bind",
        "fonts",
        "gss",
        "request-key.d",
        "alternatives",
        "X11",
        "xdg",
        "php",
        "mysql",
        "postgresql-common",
        "subuid", "subgid",
        "login.defs",
        ".pwd.lock", ".resolv.conf.systemd-resolved.bak",
        "locale.conf", "locale.gen", "locale.alias",
        "nftables.conf",
        "iproute2",
        "sysstat",
        "tpm2-tss",
        "oem-config",
        "moduli",
        "cloud",
        "vmware-tools",
        "libnl-3",
        "popt.d",
        "pm",
        "slshrc",
        "ltrace.conf",
        "nscd.conf",
        "prelink.conf.d",
        "speech-dispatcher",
        "ucf.conf",
        "updatedb.conf",
        "vim",
        "vtrgb",
        "wbem",
        "wodim.conf",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = self._get_data(collectors, "filesystem")
        etc_snapshots = fs_data.get("etc_snapshots", {})
        files = etc_snapshots.get("files", [])

        for entry in files:
            name = entry.get("name", "")
            path = entry.get("path", "")

            if name in self.KNOWN_ETC_FILES:
                continue

            owning_package = get_package_for_file(path)
            if owning_package is not None:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected file in /etc: {name}",
                    description=(
                        f"'{path}' is not in the known /etc file set and is not owned by "
                        f"any installed package."
                    ),
                    rationale=(
                        "Files in /etc that are not owned by a package may indicate "
                        "unauthorized software installation, persistent backdoors, or "
                        "configuration drift. All files in /etc should be tracked."
                    ),
                    remediation=(
                        f"Investigate '{path}'. If legitimate, exclude via policy. "
                        f"If unauthorized: 'rm {path}'."
                    ),
                    evidence=FileEvidence(
                        path=path,
                        permission=entry.get("mode"),
                        owner=str(entry.get("uid", "")),
                        size=entry.get("size"),
                        content=f"Type: {'dir' if entry.get('is_dir') else 'file'}",
                    ),
                    detected_value=f"File {name} present in /etc",
                    expected_value="File should be known or package-owned",
                    affected_component=path,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1070.004"],
                    tags=["filesystem", "etc", "file-integrity"],
                )
            )
        return findings


@register_check
class UnexpectedPathExecutablesCheck(AuditCheck):
    id = "FS-102"
    name = "Unexpected Executables in PATH"
    category = CheckCategory.FILESYSTEM
    severity = Severity.MEDIUM
    description = "Identifies executables in PATH directories not owned by any package"
    depends = ["filesystem"]
    tags = ["filesystem", "path", "executables"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = self._get_data(collectors, "filesystem")
        executables = fs_data.get("path_executables", [])

        for entry in executables:
            path = entry.get("path", "")
            owning_package = get_package_for_file(path)

            if owning_package is not None:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected executable in PATH: {path}",
                    description=(
                        f"'{path}' is executable and in a PATH directory, but is not owned "
                        f"by any installed package."
                    ),
                    rationale=(
                        "Executables in PATH directories that are not owned by a package may "
                        "indicate unauthorized software, backdoors, or persistent threats. "
                        "Attackers often place malicious executables in PATH directories for "
                        "persistence and easy execution."
                    ),
                    remediation=(
                        f"Investigate '{path}'. If unauthorized: 'rm {path}'. "
                        f"If legitimate, ensure it is installed via apt."
                    ),
                    evidence=FileEvidence(
                        path=path,
                        permission=entry.get("mode"),
                        owner=str(entry.get("uid", "")),
                        size=entry.get("size"),
                        content="Not owned by any installed package",
                    ),
                    detected_value=f"Executable {path} not package-owned",
                    expected_value="All PATH executables should be package-owned",
                    affected_component=path,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1036", "T1505"],
                    tags=["filesystem", "path", "executables"],
                )
            )
        return findings


@register_check
class HiddenFilesInWorldWritableCheck(AuditCheck):
    id = "FS-201"
    name = "Hidden Files in World-Writable Directories"
    category = CheckCategory.FILESYSTEM
    severity = Severity.MEDIUM
    description = "Identifies hidden files (dot-files) in world-writable locations"
    depends = ["filesystem"]
    tags = ["filesystem", "hidden", "world-writable"]
    max_findings = 200

    _KNOWN_SAFE_HIDDEN_NAMES: set[str] = {
        ".X11-unix", ".XIM-unix", ".font-unix", ".ICE-unix",
    }
    _KNOWN_SAFE_HIDDEN_PREFIXES: tuple[str, ...] = (
        ".X", ".tmp", ".com.google.Chrome", ".org.chromium",
        ".com.canonical.", ".dde-workspace",
    )
    _KNOWN_SAFE_HIDDEN_PATH_SUBSTRINGS: tuple[str, ...] = (
        "/__MACOSX/",
    )

    def _is_safe_hidden(self, name: str, path: str) -> bool:
        if name in self._KNOWN_SAFE_HIDDEN_NAMES:
            return True
        if name.startswith(self._KNOWN_SAFE_HIDDEN_PREFIXES):
            return True
        if name.startswith("._"):
            return True
        return any(sub in path for sub in self._KNOWN_SAFE_HIDDEN_PATH_SUBSTRINGS)

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = self._get_data(collectors, "filesystem")
        ww_entries = fs_data.get("world_writable", [])

        for entry in ww_entries:
            path = entry.get("path", "")
            name = Path(path).name

            if not name.startswith("."):
                continue
            if self._is_safe_hidden(name, path):
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Hidden file in world-writable location: {path}",
                    description=(
                        f"'{path}' is a hidden file located in a world-writable directory, "
                        f"making it susceptible to tampering."
                    ),
                    rationale=(
                        "Hidden files in world-writable locations allow attackers to store "
                        "malicious data, scripts, or configuration files easily overlooked "
                        "by administrators. Combined with world-writable permissions, these "
                        "files can be modified by any user on the system."
                    ),
                    remediation=(
                        f"Investigate '{path}'. If unauthorized: 'rm {path}'. "
                        f"If legitimate, consider moving to a non-world-writable location."
                    ),
                    evidence=FileEvidence(
                        path=path,
                        permission=entry.get("mode"),
                        owner=str(entry.get("uid", "")),
                        size=entry.get("size"),
                    ),
                    detected_value=f"Hidden file {name} in world-writable location",
                    expected_value="No hidden files in world-writable locations",
                    affected_component=path,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1564.001"],
                    tags=["filesystem", "hidden", "world-writable"],
                )
            )
        return findings


@register_check
class DeletedBinaryRunningCheck(AuditCheck):
    id = "FS-202"
    name = "Deleted Binaries Still Running"
    category = CheckCategory.FILESYSTEM
    severity = Severity.HIGH
    description = "Detects processes whose binary has been deleted from disk"
    depends = ["processes"]
    tags = ["filesystem", "processes", "malware", "forensics"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        proc_data = self._get_data(collectors, "processes")
        processes = proc_data.get("processes", [])

        for proc in processes:
            binary = proc.get("binary")
            if not binary:
                continue

            if Path(binary).exists():
                continue

            ppid = proc.get("ppid")
            if ppid == 2 or binary.startswith("/proc/"):
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Deleted binary still running: {binary}",
                    description=(
                        f"Process '{proc.get('name')}' (PID {proc.get('pid')}) is running "
                        f"from '{binary}' which no longer exists on disk."
                    ),
                    rationale=(
                        "A process running from a binary deleted from disk is a strong "
                        "indicator of malware. Attackers often delete their binaries after "
                        "execution to evade forensic analysis."
                    ),
                    remediation=(
                        f"Investigate PID {proc.get('pid')} immediately. "
                        f"Dump binary from /proc: 'cat /proc/{proc.get('pid')}/exe > /tmp/dump.bin'. "
                        f"Kill process: 'kill -9 {proc.get('pid')}'."
                    ),
                    evidence=ProcessEvidence(
                        pid=int(proc.get("pid", 0)),
                        name=str(proc.get("name", "")),
                        binary=binary,
                        cmdline=str(proc.get("cmdline", "")),
                    ),
                    detected_value=f"Binary {binary} deleted, process still running",
                    expected_value="All running processes should have their binary on disk",
                    affected_component=binary,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1070.004", "T1564"],
                    tags=["forensics", "malware", "process-integrity"],
                )
            )
        return findings


@register_check
class UnexpectedSymlinksInEtcCheck(AuditCheck):
    id = "FS-301"
    name = "Unexpected Symlinks in /etc"
    category = CheckCategory.FILESYSTEM
    severity = Severity.LOW
    description = "Identifies unexpected symbolic links in /etc"
    depends = ["filesystem"]
    tags = ["filesystem", "etc", "symlinks"]

    _KNOWN_SAFE_SYMLINKS: set[str] = {
        "localtime",
        "mtab",
        "os-release",
        "resolv.conf",
        "printcap",
        "rmt",
        "vtrgb",
        "vconsole.conf",
        "kernel-img.conf",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = self._get_data(collectors, "filesystem")
        etc_snapshots = fs_data.get("etc_snapshots", {})
        files = etc_snapshots.get("files", [])

        for entry in files:
            if not entry.get("is_symlink"):
                continue

            path = entry.get("path", "")
            name = entry.get("name", "")

            if name in self._KNOWN_SAFE_SYMLINKS:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected symlink in /etc: {name}",
                    description=(
                        f"'{path}' is a symbolic link in /etc. Symlinks can redirect "
                        f"configuration file access to attacker-controlled locations."
                    ),
                    rationale=(
                        "Symbolic links in /etc can be used by attackers to redirect "
                        "configuration file reads to attacker-controlled locations. "
                        "Unexpected or recently-added symlinks should be investigated."
                    ),
                    remediation=(
                        f"Investigate '{path}'. Verify the link target using "
                        f"'readlink {path}'. If unauthorized: 'rm {path}'."
                    ),
                    evidence=FileEvidence(
                        path=path,
                        permission=entry.get("mode"),
                        owner=str(entry.get("uid", "")),
                        size=entry.get("size"),
                        content="Symbolic link in /etc",
                    ),
                    detected_value=f"Symlink {name} in /etc",
                    expected_value="No unexpected symlinks in /etc",
                    affected_component=path,
                    confidence=Confidence.LOW,
                    false_positive_probability=0.7,
                    mitre_attack_ids=["T1574"],
                    tags=["filesystem", "etc", "symlinks"],
                )
            )
        return findings


@register_check
class ImmutableFileDriftCheck(AuditCheck):
    id = "FS-302"
    name = "Immutable File Drift"
    category = CheckCategory.FILESYSTEM
    severity = Severity.HIGH
    description = "Checks that critical system files have the immutable (i) attribute set"
    depends = []
    tags = ["filesystem", "immutable", "file-integrity", "hardening"]

    CRITICAL_FILES: list[str] = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []

        for filepath in self.CRITICAL_FILES:
            path = Path(filepath)
            if not path.exists():
                continue

            if self._check_immutable(filepath):
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Immutable attribute not set on critical file: {filepath}",
                    description=(
                        f"'{filepath}' does not have the immutable (i) attribute. "
                        f"Critical system files should be made immutable to prevent "
                        f"unauthorized modifications."
                    ),
                    rationale=(
                        "The immutable (i) attribute prevents modification, deletion, or "
                        "renaming of the file, even by root. Without it, an attacker with "
                        "root privileges can modify system configuration files to establish "
                        "persistence, hide backdoors, or escalate privileges."
                    ),
                    remediation=(
                        f"Set immutable attribute: 'chattr +i {filepath}'. "
                        f"Verify with: 'lsattr {filepath}'. "
                        f"Remove with 'chattr -i {filepath}' before making changes."
                    ),
                    evidence=CommandEvidence(
                        command=f"lsattr {filepath}",
                        stdout=f"Expected 'i' flag for {filepath}",
                        exit_code=0,
                    ),
                    detected_value=f"No immutable flag on {filepath}",
                    expected_value=f"Immutable (i) flag set on {filepath}",
                    affected_component=filepath,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1070", "T1565"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.7"],
                    tags=["hardening", "immutable", "file-integrity"],
                )
            )
        return findings

    def _check_immutable(self, filepath: str) -> bool:
        try:
            result = subprocess.run(
                ["lsattr", filepath],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode != 0:
                return False
            attributes = result.stdout.split(None, 1)[0] if result.stdout else ""
            return "i" in attributes
        except (OSError, subprocess.SubprocessError):
            return False


@register_check
class UnexpectedFileCapabilitiesCheck(AuditCheck):
    id = "FS-401"
    name = "Unexpected File Capabilities"
    category = CheckCategory.PERMISSIONS
    severity = Severity.MEDIUM
    description = "Identifies files with Linux capabilities not from known-safe packages"
    depends = ["filesystem"]
    tags = ["filesystem", "capabilities", "permissions"]

    _known_safe_capability_packages: set[str] = {
        "coreutils",
        "bash",
        "util-linux",
        "systemd",
        "iputils-ping",
        "openssh-client",
        "openssh-server",
        "curl",
        "wget",
        "ca-certificates",
        "dbus",
        "tar",
        "gzip",
        "python3",
        "perl-base",
        "grep",
        "findutils",
        "sed",
        "gawk",
        "xserver-xorg-core",
        "policykit-1",
        "snapd",
        "docker-ce",
        "containerd.io",
        "runc",
        "cups",
        "postfix",
        "dovecot-core",
        "ntp",
        "chrony",
        "accountsservice",
        "libvirt-daemon-system",
        "qemu-kvm",
        "wireguard-tools",
        "fuse3",
        "fuse",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = self._get_data(collectors, "filesystem")
        capabilities = fs_data.get("capabilities", [])

        for entry in capabilities:
            path = entry.get("path", "")
            caps = entry.get("capabilities", "")

            if not caps:
                continue

            owning_package = get_package_for_file(path)

            if owning_package is not None and owning_package in self._known_safe_capability_packages:
                continue

            if owning_package is not None:
                confidence = Confidence.MEDIUM
                fp_probability = 0.3
            else:
                confidence = Confidence.HIGH
                fp_probability = 0.05

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected file capabilities: {path}",
                    description=(
                        f"'{path}' has Linux capabilities set ({caps})."
                        + (f" Owned by package '{owning_package}'." if owning_package else "")
                    ),
                    rationale=(
                        "Linux capabilities grant fine-grained privileges to executable files "
                        "without requiring full SUID. Misconfigured capabilities can be "
                        "exploited for privilege escalation (e.g., CAP_DAC_OVERRIDE, "
                        "CAP_SYS_ADMIN, CAP_NET_RAW)."
                    ),
                    remediation=(
                        f"Review capabilities on '{path}'. "
                        f"Remove capabilities: 'setcap -r {path}'. "
                        f"View: 'getcap {path}'."
                    ),
                    evidence=FileEvidence(
                        path=path,
                        content=f"Capabilities: {caps}",
                    ),
                    detected_value=f"Capabilities {caps} on {path}",
                    expected_value="No unexpected file capabilities",
                    affected_component=path,
                    confidence=confidence,
                    false_positive_probability=fp_probability,
                    mitre_attack_ids=["T1548.001"],
                    tags=["capabilities", "permissions", "privilege-escalation"],
                )
            )
        return findings


@register_check
class WorldWritableDirectoriesCheck(AuditCheck):
    id = "FS-402"
    name = "World-Writable Directories"
    category = CheckCategory.PERMISSIONS
    severity = Severity.MEDIUM
    description = "Identifies world-writable directories outside expected locations"
    depends = ["filesystem"]
    tags = ["filesystem", "permissions", "world-writable"]
    max_findings = 200

    KNOWN_WW_EXCEPTIONS: set[str] = {
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/run/lock",
        "/var/run/lock",
    }

    _WW_IGNORED_PREFIXES: tuple[str, ...] = (
        "/proc/",
        "/sys/",
        "/run/",
        "/var/run/",
    )

    _WW_IGNORED_SUBSTRINGS: tuple[str, ...] = (
        "/node_modules/",
    )

    def _is_ww_ignored(self, path: str) -> bool:
        if path in self.KNOWN_WW_EXCEPTIONS:
            return True
        if path.startswith(self._WW_IGNORED_PREFIXES):
            return True
        return any(sub in path for sub in self._WW_IGNORED_SUBSTRINGS)

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = self._get_data(collectors, "filesystem")
        ww_entries = fs_data.get("world_writable", [])

        for entry in ww_entries:
            if not entry.get("is_dir"):
                continue
            if entry.get("is_symlink"):
                continue

            path = entry.get("path", "")

            if self._is_ww_ignored(path):
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"World-writable directory: {path}",
                    description=(
                        f"'{path}' is a world-writable directory, allowing any user to "
                        f"create, modify, or delete files within it."
                    ),
                    rationale=(
                        "World-writable directories outside designated locations (like /tmp) "
                        "allow any user to write files. Attackers can plant malicious files, "
                        "stage attacks, or exploit race conditions through TOCTOU vulnerabilities."
                    ),
                    remediation=(
                        f"Remove world-writable permissions: 'chmod o-w {path}'. "
                        f"If write access is needed, use ACLs: "
                        f"'setfacl -m u:user:rwx {path}'."
                    ),
                    evidence=FileEvidence(
                        path=path,
                        permission=entry.get("mode"),
                        owner=str(entry.get("uid", "")),
                        content="World-writable directory",
                    ),
                    detected_value=f"Directory {path} is world-writable ({entry.get('mode')})",
                    expected_value="No unexpected world-writable directories",
                    affected_component=path,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1222"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.1"],
                    tags=["permissions", "world-writable", "hardening"],
                )
            )
        return findings


@register_check
class OrphanedFilesCheck(AuditCheck):
    id = "FS-403"
    name = "Orphaned Files (Not Owned by Package)"
    category = CheckCategory.FILESYSTEM
    severity = Severity.MEDIUM
    description = "Identifies files on the system not owned by any installed package"
    depends = ["filesystem", "apt"]
    tags = ["filesystem", "orphaned", "file-integrity"]
    max_findings = 500

    _IGNORED_PREFIXES = (
        "/var/lib/flatpak/",
        "/var/lib/snapd/",
        "/snap/",
        "/var/log/",
        "/var/cache/",
        "/var/tmp/",
        "/tmp/",
        "/var/lib/containers/",
        "/var/lib/docker/",
        "/var/lib/lxd/",
        "/var/lib/machines/",
        "/var/spool/",
        "/var/backups/",
        "/var/mail/",
        "/var/crash/",
        "/var/metrics/",
        "/var/lib/postgresql/",
        "/var/lib/mysql/",
        "/var/lib/mongodb/",
        "/var/lib/redis/",
        "/var/lib/rabbitmq/",
        "/var/www/",
        "/var/games/",
        "/var/opt/",
        "/var/lib/snapd/",
    )

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        fs_data = self._get_data(collectors, "filesystem")

        seen_paths: set[str] = set()
        file_entries: list[dict[str, Any]] = []

        etc_files = fs_data.get("etc_snapshots", {}).get("files", [])
        for e in etc_files:
            file_entries.append(e)

        for e in fs_data.get("path_executables", []):
            file_entries.append(e)

        for entry in file_entries:
            path = entry.get("path", "")
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)

            if path.startswith(self._IGNORED_PREFIXES):
                continue

            owning_package = resolve_package(path)
            if owning_package is not None:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Orphaned file: {path}",
                    description=(
                        f"'{path}' is present on the filesystem but is not owned by "
                        f"any installed package."
                    ),
                    rationale=(
                        "Files not owned by any package may indicate manual installations, "
                        "leftover files from removed packages, or malicious files placed by "
                        "attackers. Tracking all files to their source package is important "
                        "for integrity management."
                    ),
                    remediation=(
                        f"Investigate '{path}'. If from a removed package: "
                        f"'dpkg --purge <package>'. If unauthorized: 'rm {path}'."
                    ),
                    evidence=FileEvidence(
                        path=path,
                        permission=entry.get("mode"),
                        owner=str(entry.get("uid", "")),
                        size=entry.get("size"),
                        content="Not owned by any installed package",
                    ),
                    detected_value=f"File {path} is orphaned",
                    expected_value="All files should be owned by an installed package",
                    affected_component=path,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.4,
                    mitre_attack_ids=["T1070.004"],
                    tags=["filesystem", "orphaned", "file-integrity"],
                )
            )
        return findings


@register_check
class MountOptionGapsCheck(AuditCheck):
    id = "FS-501"
    name = "Mount Option Security Gaps"
    category = CheckCategory.FILESYSTEM
    severity = Severity.MEDIUM
    description = "Checks mounted filesystems for missing security hardening options"
    depends = ["mounts"]
    tags = ["filesystem", "mounts", "hardening"]

    KNOWN_SAFE_FSTYPES: set[str] = {
        "squashfs", "tmpfs", "devtmpfs", "proc", "sysfs",
        "cgroup", "cgroup2", "devpts", "hugetlbfs", "mqueue",
        "pstore", "efivarfs", "fusectl", "fuse.gvfsd-fuse",
        "rpc_pipefs", "configfs", "bpf", "debugfs", "tracefs",
        "securityfs", "autofs", "overlay",
    }

    WRITABLE_FSTYPES: set[str] = {
        "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs",
        "jfs", "reiserfs", "vfat", "ntfs", "ntfs3",
        "exfat", "f2fs", "ocfs2", "hfsplus",
    }

    SECURE_MOUNT_POINTS: dict[str, list[str]] = {
        "/tmp": ["noexec", "nosuid", "nodev"],
        "/var/tmp": ["noexec", "nosuid", "nodev"],
        "/home": ["nosuid", "nodev"],
        "/dev/shm": ["noexec", "nosuid", "nodev"],
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        finding_counter: int = 0
        mounts_data = self._get_data(collectors, "mounts")
        mounts = mounts_data.get("mounts", [])

        for mount in mounts:
            mount_point = mount.get("mount_point", "")
            fstype = mount.get("fstype", "")
            options_str = mount.get("options", "")
            options = set(options_str.split(","))
            device = mount.get("device", "")

            if fstype in self.KNOWN_SAFE_FSTYPES:
                continue

            if mount_point in self.SECURE_MOUNT_POINTS:
                required_options = self.SECURE_MOUNT_POINTS[mount_point]
                for opt in required_options:
                    if opt not in options:
                        finding_counter += 1
                        findings.append(
                            self.finding(
                                finding_id=f"{finding_counter:03d}",
                                title=f"Missing {opt} on {mount_point}",
                                description=(
                                    f"'{mount_point}' ({fstype}) is mounted without the "
                                    f"'{opt}' option. Current options: {options_str}"
                                ),
                                rationale=self._rationale_for_option(opt, mount_point),
                                remediation=(
                                    f"Add '{opt}' to /etc/fstab for '{device} {mount_point}': "
                                    f"'defaults,{opt} 0 2'. "
                                    f"Remount: 'mount -o remount,{opt} {mount_point}'."
                                ),
                                evidence=RegistryEvidence(
                                    key=f"mount.{mount_point}.{opt}",
                                    value="not set",
                                    expected=opt,
                                    source=f"/proc/mounts ({mount_point})",
                                ),
                                detected_value=f"Option '{opt}' not set on {mount_point}",
                                expected_value=f"'{opt}' should be set on {mount_point}",
                                affected_component=mount_point,
                                confidence=Confidence.MEDIUM,
                                false_positive_probability=0.2,
                                mitre_attack_ids=["T1222"],
                                cis_benchmarks=["CIS Ubuntu 20.04: 1.1"],
                                tags=["mounts", "hardening", "filesystem"],
                            )
                        )

            elif fstype in self.WRITABLE_FSTYPES:
                if mount_point.startswith("/snap"):
                    continue
                missing_options: list[str] = []
                if "noexec" not in options:
                    missing_options.append("noexec")
                if "nosuid" not in options:
                    missing_options.append("nosuid")
                if "nodev" not in options:
                    missing_options.append("nodev")

                if not missing_options:
                    continue

                finding_counter += 1
                opt_list = ", ".join(missing_options)
                findings.append(
                    self.finding(
                        finding_id=f"{finding_counter:03d}",
                        title=f"Missing mount hardening options on {mount_point}",
                        description=(
                            f"'{mount_point}' ({fstype}) is a writable filesystem missing "
                            f"security options: {opt_list}. Current options: {options_str}"
                        ),
                        rationale=(
                            "Writable filesystems should use noexec (prevent binary execution), "
                            "nosuid (block SUID binaries), and nodev (block device nodes) "
                            "where applicable to limit attack surface."
                        ),
                        remediation=(
                            f"Add missing options in /etc/fstab for '{device} {mount_point}': "
                            f"'defaults,{','.join(missing_options)} 0 2'. "
                            f"Remount: 'mount -o remount,{','.join(missing_options)} {mount_point}'."
                        ),
                        evidence=RegistryEvidence(
                            key=f"mount.{mount_point}.options",
                            value=options_str,
                            expected=f"defaults,{','.join(missing_options)}",
                            source="/proc/mounts",
                        ),
                        detected_value=f"Missing {opt_list} on {mount_point}",
                        expected_value=f"{mount_point} should have {', '.join(missing_options)}",
                        affected_component=mount_point,
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1222"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 1.1"],
                        tags=["mounts", "hardening", "filesystem"],
                    )
                )

        return findings

    def _rationale_for_option(self, opt: str, mount_point: str) -> str:
        rationales = {
            "noexec": (
                f"'{mount_point}' without 'noexec' allows direct execution of binaries. "
                f"Attackers can download and run malicious binaries from writable locations."
            ),
            "nosuid": (
                f"'{mount_point}' without 'nosuid' allows SUID binary execution. "
                f"Attackers can use this for privilege escalation."
            ),
            "nodev": (
                f"'{mount_point}' without 'nodev' allows device node creation. "
                f"Attackers can create device nodes to access raw disk or memory."
            ),
        }
        return rationales.get(opt, f"'{mount_point}' is missing the '{opt}' mount option.")
