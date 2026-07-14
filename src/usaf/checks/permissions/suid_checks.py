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
    """Check for unexpected SUID binaries that could indicate privilege escalation.

    Uses a layered approach to minimize false positives:
      1. Built-in allowlist (common Ubuntu SUID binaries)
      2. Config-driven allowlist (user-defined in usaf.yaml suid_allowlist)
      3. Package-ownership check (binaries from official packages are low-risk)
    """

    id = "PRM-101"
    name = "Unexpected SUID Binaries"
    category = CheckCategory.PERMISSIONS
    severity = Severity.HIGH
    description = "Identifies SUID root binaries not in the expected set or not owned by a package"
    depends = []
    tags = ["suid", "privilege-escalation", "permissions"]

    # Built-in allowlist of common Ubuntu SUID binaries that are expected
    # and do not represent a security concern.
    _builtin_allowlist: set[str] = {
        # Core system utilities
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
        # Privilege escalation
        "/bin/pkexec",
        "/usr/bin/pkexec",
        "/usr/lib/polkit-1/polkit-agent-helper-1",
        "/usr/libexec/polkit-1/polkit-agent-helper-1",
        "/usr/lib/policykit-1/polkit-agent-helper-1",
        # SSH
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/ssh/ssh-keysign",
        "/usr/libexec/openssh/ssh-keysign",
        # Cron / at
        "/bin/crontab",
        "/usr/bin/crontab",
        "/bin/at",
        "/usr/bin/at",
        "/bin/atq",
        "/usr/bin/atq",
        "/bin/atrm",
        "/usr/bin/atrm",
        "/usr/bin/batch",
        # Shadow utilities
        "/usr/sbin/unix_chkpwd",
        "/usr/sbin/pam_timestamp_check",
        "/usr/libexec/unix_chkpwd",
        # Networking
        "/bin/ping",
        "/usr/bin/ping",
        "/bin/ping6",
        "/usr/bin/ping6",
        # X11
        "/usr/bin/Xorg",
        # Snap
        "/usr/lib/snapd/snap-confine",
        "/usr/libexec/snapd/snap-confine",
        # D-Bus
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        "/usr/libexec/dbus-1.0/dbus-daemon-launch-helper",
    }

    # Package-based allowlist: SUID binaries owned by these known-safe packages
    # are considered expected and get LOW confidence / high false-positive rate.
    # This eliminates the need for a path-level allowlist entry for every SUID
    # binary shipped by standard Ubuntu packages.
    _known_suid_packages: set[str] = {
        # Core system utilities
        "coreutils",             # su, passwd, chsh, chfn, newgrp, gpasswd
        "sudo",                  # sudo, sudoedit
        "sudo-rs",               # Rust implementation of sudo (su-rs, sudo-rs, sudoedit-rs)
        "sudo-ldap",             # sudo LDAP variant
        "shadow",                # login, su, passwd, chfn, chsh, newgrp, expiry, chage
        "login",                 # login
        "util-linux",            # mount, umount, wall, write
        "util-linux-extra",      # wall, write (extra)
        "bsdutils",              # wall (Debian/Ubuntu)
        # Authentication / PAM
        "libpam-modules",        # unix_chkpwd, pam_timestamp_check
        "libpam-modules-bin",    # unix_chkpwd (binary package)
        "libpam-ldap",           # PAM LDAP helpers
        "libpam-krb5",           # PAM Kerberos helpers
        # SSH
        "openssh-client",        # ssh-keysign
        "openssh-server",        # ssh-keysign
        # Scheduling
        "cron",                  # crontab
        "anacron",               # anacron
        "at",                    # at, batch, atq, atrm
        # Networking
        "iputils-ping",          # ping, ping6
        "iputils-arping",        # arping
        "iputils-tracepath",     # traceroute6.iputils
        "fuse3",                 # fusermount3
        "fuse",                  # fusermount (legacy)
        "ppp",                   # pppd
        "pppconfig",             # PPP configuration helpers
        "wireguard-tools",       # wg-quick
        # PolicyKit / D-Bus
        "policykit-1",           # pkexec, polkit-agent-helper-1
        "dbus",                  # dbus-daemon-launch-helper
        "dbus-user-session",     # D-Bus session helper
        # Display / X11
        "xserver-xorg-core",     # Xorg
        "xserver-xorg-video-intel",
        "x11-utils",
        # Snap / Container
        "snapd",                 # snap-confine
        "containerd.io",         # Docker container SUID helpers
        "docker-ce",             # Docker community edition
        "docker-ce-cli",
        "docker.io",             # Docker (Ubuntu package)
        "runc",                  # Container runtime
        # Removable media / storage
        "eject",                 # dmcrypt-get-device
        "udisks2",               # udisks helpers
        "udisks",                # udisks (legacy)
        # Terminal / PTY
        "utempter",              # utempter terminal recording helper
        # Virtualization
        "qemu-kvm",              # QEMU/KVM SUID helpers
        "qemu-user",             # QEMU user-mode helpers
        "spice-client-glib-usb-acl-helper",  # SPICE USB redirection
        "spice-client-gtk",      # SPICE GTK helpers
        # Mail / Groupware
        "dovecot-core",          # Dovecot IMAP SUID helpers
        "dovecot-imapd",
        "dovecot-pop3d",
        "postfix",               # Postfix SUID helpers
        "sendmail-base",         # Sendmail SUID helpers
        # Printing
        "cups",                  # CUPS printing helpers
        "cups-bsd",              # CUPS BSD commands
        "cups-client",           # CUPS client utilities
        # System monitoring
        "rgmanager",             # Resource group manager
        "irqbalance",            # IRQ balance
        # Filesystem
        "dosfstools",            # mkfs.vfat SUID (for removable media)
        "ntfs-3g",               # NTFS mount helper
        "exfat-utils",           # exFAT helpers
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        config_allowlist = self._load_config_allowlist(collectors)
        combined_allowlist = self._builtin_allowlist | config_allowlist
        suid_binaries = self._find_suid_binaries()

        for path_str in suid_binaries:
            path = Path(path_str)
            try:
                stat_info = path.stat()
            except OSError:
                continue

            owning_package = get_package_for_file(path_str)
            is_package_owned = owning_package is not None
            is_allowlisted = path_str in combined_allowlist

            if is_allowlisted:
                continue

            if is_package_owned and owning_package in self._known_suid_packages:
                confidence = Confidence.LOW
                fp_probability = 0.8
            elif is_package_owned:
                confidence = Confidence.MEDIUM
                fp_probability = 0.3
            else:
                confidence = Confidence.HIGH
                fp_probability = 0.05

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
                        "reviewed. Every SUID binary should be justified and tracked. "
                        "Add expected SUID binaries to usaf.yaml under suid_allowlist to "
                        "dismiss this finding."
                    ),
                    remediation=self._build_remediation(path_str, owning_package),
                    evidence=evidence,
                    detected_value=f"SUID bit set on {path_str}",
                    expected_value="No unexpected SUID binaries",
                    affected_component=path_str,
                    confidence=confidence,
                    false_positive_probability=fp_probability,
                    mitre_attack_ids=["T1548.001"],
                    tags=["privilege-escalation", "suid", "persistence"],
                )
            )

        return findings

    def _load_config_allowlist(self, _collectors: dict[str, Any] | None = None) -> set[str]:
        """Load user-defined SUID allowlist from configuration."""
        if self._config is None:
            return set()
        return {str(p) for p in self._config.suid_allowlist if p}

    def _build_description(self, path_str: str, owning_package: str | None) -> str:
        if owning_package and owning_package in self._known_suid_packages:
            return (
                f"'{path_str}' has the SUID bit set. It is owned by the known-safe "
                f"package '{owning_package}' and is likely legitimate. "
                f"If expected, add to suid_allowlist in usaf.yaml to dismiss."
            )
        if owning_package:
            return (
                f"'{path_str}' has the SUID bit set. It is owned by the "
                f"'{owning_package}' package. To suppress this finding, "
                f"add it to suid_allowlist in usaf.yaml."
            )
        return (
            f"'{path_str}' has the SUID bit set and is not owned by any "
            f"installed package. This is highly suspicious."
        )

    def _build_remediation(self, path_str: str, owning_package: str | None) -> str:
        if owning_package and owning_package in self._known_suid_packages:
            return (
                f"'{path_str}' is from the known-safe package '{owning_package}'. "
                f"This is likely a false positive. To dismiss: add to "
                f"suid_allowlist in usaf.yaml. To remove SUID: "
                f"'chmod u-s {path_str}' (may break functionality)."
            )
        if owning_package:
            return (
                f"Review whether '{path_str}' requires SUID. "
                f"If legitimate: add to suid_allowlist in usaf.yaml under checks. "
                f"If not: 'chmod u-s {path_str}'. "
                f"Package: '{owning_package}'."
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

    id = "PRM-201"
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

    def _run_check(self, _collectors: dict[str, Any]) -> list:
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
