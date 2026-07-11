from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

from usaf.collectors.packages.apt import get_package_for_file
from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, NetworkEvidence, ProcessEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

KNOWN_SAFE_SERVICES: set[str] = {
    "accounts-daemon", "acpid", "acpi-support", "adduser",
    "anacron", "apache2", "apparmor", "apport", "apt-cacher",
    "apt-daily", "apt-daily-upgrade", "atd",
    "avahi-daemon", "bluetooth", "brltty", "casper",
    "chrony", "colord", "console-setup", "containerd",
    "cron", "cups", "cups-browsed", "dbus", "dirmngr",
    "docker", "dovecot", "e2scrub_all", "ebtables",
    "friendly-recovery", "gdm3", "getty", "glances",
    "grafana-server", "grub-common", "haveged", "hddtemp",
    "hp-systray", "hplip", "htpdate", "irqbalance",
    "isc-dhcp-client", "isc-dhcp-server", "kbd", "kmod",
    "lightdm", "lm-sensors", "lvm2", "lxd-containers",
    "mdadm", "mysql", "nginx", "NetworkManager",
    "networking", "nfs-common", "nfs-kernel-server",
    "nftables", "nscd", "ntp", "ntpsec", "openvpn",
    "os-prober", "php7.4-fpm", "php8.1-fpm", "php8.2-fpm",
    "php8.3-fpm", "php-fpm", "plymouth", "plymouth-log",
    "polkit", "postfix", "postgresql", "ppp", "pppd-dns",
    "procps", "prometheus-node-exporter", "prometheus-server",
    "psensor", "pulseaudio", "rpcbind", "rsync",
    "rsyslog", "sanedsnapd", "screen-cleanup", "serial-getty",
    "snapd", "snapd.apparmor", "spice-vdagent", "ssh",
    "sshd", "sslh", "systemd-binfmt", "systemd-fsck",
    "systemd-hwdb-update", "systemd-journald",
    "systemd-journal-flush", "systemd-logind",
    "systemd-modules-load", "systemd-pstore",
    "systemd-random-seed", "systemd-remount-fs",
    "systemd-resolved", "systemd-sysctl",
    "systemd-sysusers", "systemd-timedated",
    "systemd-timesyncd", "systemd-tmpfiles",
    "systemd-udevd", "systemd-update-utmp",
    "systemd-userdbd", "systemd-user-sessions",
    "thermald", "timidity", "tlp", "ufw",
    "unattended-upgrades", "uuidd", "vgauth",
    "virtualbox", "whoopsie", "wpa_supplicant",
    "x11-common", "xserver-xorg",
}

KNOWN_SAFE_PORTS: dict[int, tuple[str, str]] = {
    22: ("ssh", "SSH daemon"),
    53: ("systemd-resolved", "DNS resolver"),
    68: ("dhcpd", "DHCP client"),
    80: ("nginx", "HTTP"),
    123: ("ntpd", "NTP daemon"),
    443: ("apache2", "HTTPS"),
    514: ("rsyslog", "Syslog daemon"),
    631: ("cups", "CUPS printing"),
    3306: ("mysql", "MySQL database"),
    5432: ("postgresql", "PostgreSQL database"),
    6379: ("redis-server", "Redis cache"),
    8080: ("nginx", "HTTP alternative"),
    8443: ("nginx", "HTTPS alternative"),
    9090: ("prometheus", "Prometheus metrics"),
}

EXPECTED_ROOT_SERVICES: set[str] = {
    "accounts-daemon", "acpid", "apparmor", "apport",
    "apt-daily", "apt-daily-upgrade", "atd",
    "avahi-daemon", "chrony", "colord", "containerd",
    "cron", "cups", "cups-browsed", "dbus",
    "docker", "e2scrub_all", "ebtables",
    "gdm3", "getty", "grub-common", "haveged",
    "irqbalance", "isc-dhcp-client", "isc-dhcp-server",
    "kbd", "kmod", "lvm2", "lxd-containers",
    "mdadm", "networking", "nfs-common",
    "nfs-kernel-server", "nftables", "nginx",
    "NetworkManager", "nscd", "ntp", "ntpsec",
    "openvpn", "plymouth", "plymouth-log",
    "polkit", "postfix", "postgresql",
    "procps", "prometheus-node-exporter",
    "prometheus-server", "rsync", "rsyslog",
    "snapd", "ssh", "sshd",
    "systemd-journald", "systemd-logind",
    "systemd-modules-load", "systemd-resolved",
    "systemd-timesyncd", "systemd-udevd",
    "ufw", "unattended-upgrades", "uuidd",
    "whoopsie", "wpa_supplicant",
}

UNIT_SEARCH_DIRS = [
    Path("/etc/systemd/system"),
    Path("/lib/systemd/system"),
    Path("/run/systemd/system"),
]


def _strip_service_suffix(name: str) -> str:
    for suffix in (".service", ".socket", ".timer", ".target", ".path", ".mount", ".device", ".slice"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _read_unit_file(unit_name: str) -> tuple[str | None, str | None]:
    for sd in UNIT_SEARCH_DIRS:
        unit_path = sd / unit_name
        if unit_path.exists():
            try:
                return str(unit_path), unit_path.read_text()
            except OSError:
                continue
    return None, None


def _find_unit_file_path(unit_name: str) -> str | None:
    for sd in UNIT_SEARCH_DIRS:
        unit_path = sd / unit_name
        if unit_path.exists():
            return str(unit_path)
    return None


def _parse_execstart(content: str) -> str | None:
    in_service = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            in_service = section in ("service", "socket", "timer")
            continue
        if not in_service:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key != "ExecStart":
            continue
        value = stripped.split("=", 1)[1].strip() if "=" in stripped else ""
        if not value:
            continue
        if value.startswith("@"):
            parts = value.split(None, 1)
            if len(parts) > 1:
                value = parts[1]
            else:
                continue
        for prefix in ("-", "!", "+", "@"):
            if value.startswith(prefix):
                value = value[1:].strip()
        binary = value.split(None, 1)[0] if value else None
        if binary:
            return binary
    return None


def _find_pid_by_inode(target_inode: int) -> int | None:
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        fd_dir = entry / "fd"
        if not fd_dir.is_dir():
            continue
        try:
            for fd_entry in fd_dir.iterdir():
                try:
                    link = os.readlink(str(fd_entry))
                    if link.startswith("socket:") and f"[{target_inode}]" in link:
                        return pid
                except OSError:
                    continue
        except OSError:
            continue
    return None


@register_check
class UnexpectedEnabledServicesCheck(AuditCheck):
    id = "SVC-102"
    name = "Unexpected Enabled Services"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Identifies enabled systemd services that are not in the known-safe set"
    depends: ClassVar[list[str]] = ["systemd"]
    tags: ClassVar[list[str]] = ["services", "enabled", "unknown-services"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        services = sys_data.get("services", [])

        for service in services:
            load_val = service.get("load", "")
            active_val = service.get("active", "")
            sub_val = service.get("sub", "")
            unit_name = service.get("name", "")

            if load_val != "loaded":
                continue
            if active_val != "active":
                continue
            if sub_val not in ("running", "exited"):
                continue

            short_name = _strip_service_suffix(unit_name)
            if short_name in KNOWN_SAFE_SERVICES:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected enabled service: {short_name}",
                    description=(
                        f"Service '{unit_name}' is loaded and active but is not in the "
                        f"known-safe services list."
                    ),
                    rationale=(
                        "Unauthorized or unexpected services increase the attack surface. "
                        "Attackers may install services for persistence, data exfiltration, "
                        "or as backdoors. Every enabled service should be justified and tracked."
                    ),
                    remediation=(
                        f"Investigate '{short_name}'. If unauthorized: "
                        f"'systemctl disable --now {unit_name}'. "
                        f"Remove associated package: 'apt purge <package>'."
                    ),
                    evidence=RegistryEvidence(
                        key=short_name,
                        value=f"active/{sub_val}",
                        expected="known-safe service",
                        source=f"systemctl ({unit_name})",
                    ),
                    detected_value=f"Service '{short_name}' is enabled and active",
                    expected_value="All enabled services should be in the known-safe set",
                    affected_component=short_name,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1543.002"],
                    tags=["services", "unknown-services", "attack-surface"],
                )
            )
        return findings


@register_check
class ServicesRunningAsRootCheck(AuditCheck):
    id = "SVC-201"
    name = "Services Running as Root"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Identifies services running as root that are not expected to"
    depends: ClassVar[list[str]] = ["systemd", "processes"]
    tags: ClassVar[list[str]] = ["services", "root", "privilege"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        proc_data = self._get_data(collectors, "processes")
        services = sys_data.get("services", [])
        processes = proc_data.get("processes", [])

        for service in services:
            active_val = service.get("active", "")
            unit_name = service.get("name", "")

            if active_val != "active":
                continue

            short_name = _strip_service_suffix(unit_name)
            if short_name in EXPECTED_ROOT_SERVICES:
                continue

            _unit_path, unit_content = _read_unit_file(unit_name)
            binary_path = None
            if unit_content:
                binary_path = _parse_execstart(unit_content)

            if not binary_path:
                continue

            matching_procs = []
            for proc in processes:
                proc_binary = proc.get("binary") or ""
                proc_cmdline = proc.get("cmdline") or ""
                if binary_path in proc_cmdline or binary_path == proc_binary:
                    matching_procs.append(proc)

            if not matching_procs:
                continue

            running_as_root = False
            for proc in matching_procs:
                uid = proc.get("uid")
                if uid is not None and uid == 0:
                    running_as_root = True
                    evidence = ProcessEvidence(
                        pid=int(proc.get("pid", 0)),
                        name=str(proc.get("name", "")),
                        binary=str(proc.get("binary", "")),
                        cmdline=str(proc.get("cmdline", "")),
                        user="root",
                        state=str(proc.get("state", "")),
                    )
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Service running as root: {short_name}",
                            description=(
                                f"Service '{short_name}' (PID {proc.get('pid')}) is running "
                                f"as root but is not in the expected root services list."
                            ),
                            rationale=(
                                "Services running as root have full system access. If compromised, "
                                "an attacker gains root privileges immediately. Services should run "
                                "with the minimum privileges necessary using dedicated service "
                                "accounts or DynamicUser where possible."
                            ),
                            remediation=(
                                f"Configure '{short_name}' to run as a non-root user. "
                                f"Set User= and Group= in the [Service] section: "
                                f"'systemctl edit {unit_name}'. Consider using "
                                f"DynamicUser=yes for systemd-managed UIDs."
                            ),
                            evidence=evidence,
                            detected_value=f"Service '{short_name}' runs as root (UID 0)",
                            expected_value=f"Service '{short_name}' should run as non-root",
                            affected_component=short_name,
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.3,
                            mitre_attack_ids=["T1068"],
                            tags=["services", "root", "privilege-escalation"],
                        )
                    )

            if not running_as_root:
                continue

        return findings


@register_check
class ServicesFromUnknownBinariesCheck(AuditCheck):
    id = "SVC-202"
    name = "Services From Unknown Binaries"
    category = CheckCategory.SERVICES
    severity = Severity.HIGH
    description = "Identifies active services whose binaries are not owned by any installed package"
    depends: ClassVar[list[str]] = ["systemd"]
    tags: ClassVar[list[str]] = ["services", "binaries", "unknown", "malware"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        services = sys_data.get("services", [])

        for service in services:
            active_val = service.get("active", "")
            unit_name = service.get("name", "")

            if active_val != "active":
                continue

            _u_path, unit_content = _read_unit_file(unit_name)
            if not unit_content:
                continue

            binary_path = _parse_execstart(unit_content)
            if not binary_path:
                continue

            owning_package = get_package_for_file(binary_path)
            if owning_package is not None:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Service binary not owned by package: {binary_path}",
                    description=(
                        f"Service '{unit_name}' uses binary '{binary_path}' which is not "
                        f"owned by any installed package."
                    ),
                    rationale=(
                        "Binaries not owned by any package may indicate manually compiled, "
                        "downloaded, or malicious software. Without package management, "
                        "the binary will not receive security updates and cannot be verified "
                        "through dpkg integrity checks."
                    ),
                    remediation=(
                        f"Investigate '{binary_path}' immediately. "
                        f"If legitimate: install via apt. "
                        f"If unauthorized: 'systemctl disable --now {unit_name}' and "
                        f"remove binary: 'rm {binary_path}'."
                    ),
                    evidence=FileEvidence(
                        path=binary_path,
                        content=f"Service: {unit_name} | Not owned by any package",
                    ),
                    detected_value=f"Service '{unit_name}' uses unowned binary '{binary_path}'",
                    expected_value="All service binaries should be owned by a package",
                    affected_component=binary_path,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1543.002", "T1505"],
                    tags=["services", "binaries", "unknown", "malware"],
                )
            )
        return findings


@register_check
class FailedServicesCheck(AuditCheck):
    id = "SVC-301"
    name = "Failed Services"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Identifies systemd services that have failed"
    depends: ClassVar[list[str]] = ["systemd"]
    tags: ClassVar[list[str]] = ["services", "failed", "availability"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        services = sys_data.get("services", [])

        for service in services:
            active_val = service.get("active", "")
            sub_val = service.get("sub", "")
            unit_name = service.get("name", "")
            description = service.get("description", "")

            if sub_val != "failed" and active_val != "failed":
                continue

            short_name = _strip_service_suffix(unit_name)

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Failed service: {short_name}",
                    description=(
                        f"Service '{unit_name}' is in failed state "
                        f"(active={active_val}, sub={sub_val}). "
                        f"Description: {description}"
                    ),
                    rationale=(
                        "Failed services indicate configuration errors, missing dependencies, "
                        "or malicious activity. Attackers may cause service failures to disable "
                        "security controls (e.g., fail2ban, auditd)."
                    ),
                    remediation=(
                        f"Investigate: 'systemctl status {unit_name}'. "
                        f"View logs: 'journalctl -u {unit_name}'. "
                        f"Restart: 'systemctl reset-failed {unit_name}' and "
                        f"'systemctl start {unit_name}'. "
                        f"Check for configuration issues."
                    ),
                    evidence=RegistryEvidence(
                        key=short_name,
                        value=f"active={active_val}, sub={sub_val}",
                        expected="active/running",
                        source=f"systemctl ({unit_name})",
                    ),
                    detected_value=f"Service '{short_name}' is in failed state",
                    expected_value="All services should be in active/running state",
                    affected_component=short_name,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1489"],
                    tags=["services", "failed", "availability"],
                )
            )
        return findings


@register_check
class UnexpectedListeningServicesCheck(AuditCheck):
    id = "SVC-302"
    name = "Unexpected Listening Services"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Identifies listening services on unexpected ports"
    depends: ClassVar[list[str]] = ["systemd", "sockets"]
    tags: ClassVar[list[str]] = ["services", "listening", "network", "ports"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        sock_data = self._get_data(collectors, "sockets")
        services = sys_data.get("services", [])

        active_services: dict[str, str] = {}
        for svc in services:
            if svc.get("active") == "active":
                short = _strip_service_suffix(str(svc.get("name", "")))
                active_services[short] = str(svc.get("name", ""))

        for proto_key in ("tcp", "tcp6"):
            listeners = sock_data.get(proto_key, [])
            for listener in listeners:
                local_port = listener.get("local_port")
                if local_port is None:
                    continue
                local_port = int(local_port)
                local_addr = str(listener.get("local_address", ""))
                inode = listener.get("inode")

                if local_port in KNOWN_SAFE_PORTS:
                    continue

                matched_service = None
                if inode is not None:
                    pid = _find_pid_by_inode(int(inode))
                    if pid is not None:
                        matched_service = self._match_pid_to_service(pid, services)

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Unexpected listening service on port {local_port}",
                        description=(
                            f"Found a listening TCP socket on port {local_port} "
                            f"(protocol={listener.get('protocol')}, address={local_addr})"
                            + (f" matching service '{matched_service}'" if matched_service else "")
                            + " that is not in the known-safe port list."
                        ),
                        rationale=(
                            "Listening network services expose the system to network-based "
                            "attacks. Every open port should be justified and monitored. "
                            "Unexpected listening services may indicate malware C2, "
                            "unauthorized backdoors, or misconfigured applications."
                        ),
                        remediation=(
                            f"Investigate the service listening on port {local_port}. "
                            f"Use: 'ss -tlnp | grep :{local_port}'. "
                            f"If unauthorized: stop and disable the associated service."
                        ),
                        evidence=NetworkEvidence(
                            protocol=str(listener.get("protocol", "")),
                            local_address=local_addr,
                            local_port=local_port,
                            state=str(listener.get("state", "")),
                            pid=pid if inode is not None and (pid := _find_pid_by_inode(int(inode))) else None,
                            process_name=matched_service,
                        ),
                        detected_value=f"Listening on port {local_port}",
                        expected_value="Only known-safe ports should be listening",
                        affected_component=f"port:{local_port}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1043", "T1505"],
                        tags=["services", "network", "listening", "ports"],
                    )
                )
        return findings

    def _match_pid_to_service(self, pid: int, services: list[dict[str, Any]]) -> str | None:
        proc_dir = Path(f"/proc/{pid}")
        if not proc_dir.is_dir():
            return None
        try:
            cmdline = (proc_dir / "cmdline").read_bytes().replace(b"\x00", b" ").strip().decode("utf-8", errors="replace")
        except OSError:
            return None
        for svc in services:
            unit_name = str(svc.get("name", ""))
            _u_p, unit_content = _read_unit_file(unit_name)
            if not unit_content:
                continue
            binary_path = _parse_execstart(unit_content)
            if binary_path and binary_path in cmdline:
                return _strip_service_suffix(unit_name)
        return None


@register_check
class RecentlyInstalledServicesCheck(AuditCheck):
    id = "SVC-401"
    name = "Recently Installed Services"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Identifies services whose unit files were recently modified"
    depends: ClassVar[list[str]] = ["systemd"]
    tags: ClassVar[list[str]] = ["services", "recent", "installed", "persistence"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        services = sys_data.get("services", [])
        cutoff = datetime.now(UTC) - timedelta(days=7)

        for service in services:
            active_val = service.get("active", "")
            unit_name = service.get("name", "")

            if active_val != "active":
                continue

            unit_path_str = _find_unit_file_path(unit_name)
            if not unit_path_str:
                continue

            unit_path = Path(unit_path_str)
            try:
                mtime = datetime.fromtimestamp(unit_path.stat().st_mtime, tz=UTC)
            except OSError:
                continue

            if mtime >= cutoff:
                short_name = _strip_service_suffix(unit_name)
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Recently modified service unit: {short_name}",
                        description=(
                            f"Service '{unit_name}' has a unit file at '{unit_path_str}' "
                            f"that was modified on {mtime.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                            f"(within the last 7 days)."
                        ),
                        rationale=(
                            "Recently created or modified service unit files may indicate "
                            "unauthorized software installation, persistence mechanisms, or "
                            "malware deployment. Attackers commonly install systemd services "
                            "for persistent access."
                        ),
                        remediation=(
                            f"Investigate '{short_name}'. Check the unit file: "
                            f"'systemctl cat {unit_name}'. If unauthorized: "
                            f"'systemctl disable --now {unit_name}' and "
                            f"'rm {unit_path_str}'."
                        ),
                        evidence=FileEvidence(
                            path=unit_path_str,
                            modified=mtime,
                            content=f"Service: {short_name} | Recently modified unit file",
                        ),
                        detected_value=f"Unit file modified on {mtime.isoformat()}",
                        expected_value="Unit files should not be recently modified",
                        affected_component=unit_path_str,
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1543.002", "T1070"],
                        tags=["services", "persistence", "recent"],
                    )
                )
        return findings


@register_check
class ModifiedSystemdUnitCheck(AuditCheck):
    id = "SVC-402"
    name = "Modified Systemd Unit Files"
    category = CheckCategory.SERVICES
    severity = Severity.HIGH
    description = "Identifies systemd unit files that have been modified from their package defaults"
    depends: ClassVar[list[str]] = ["systemd"]
    tags: ClassVar[list[str]] = ["services", "file-integrity", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        services = sys_data.get("services", [])

        seen_units: set[str] = set()

        for service in services:
            unit_name = service.get("name", "")
            active_val = service.get("active", "")

            if unit_name in seen_units:
                continue
            seen_units.add(unit_name)

            etc_path = Path(f"/etc/systemd/system/{unit_name}")
            lib_path = Path(f"/lib/systemd/system/{unit_name}")
            dropin_dir = Path(f"/etc/systemd/system/{unit_name}.d")
            dropin_run = Path(f"/run/systemd/system/{unit_name}.d")

            has_etc_override = etc_path.exists()
            has_lib_unit = lib_path.exists()
            has_dropin = dropin_dir.exists() or dropin_run.exists()

            if not has_etc_override and not has_lib_unit:
                continue

            if not has_etc_override and not has_dropin:
                continue

            short_name = _strip_service_suffix(unit_name)
            override_type = []
            if has_etc_override and has_lib_unit:
                override_type.append("modified unit (override in /etc)")
            elif has_etc_override and not has_lib_unit:
                override_type.append("custom unit (only in /etc)")
            if has_dropin:
                override_type.append("drop-in overrides present")

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Modified systemd unit: {short_name}",
                    description=(
                        f"Service '{unit_name}' has been modified from its package default. "
                        f"Overrides: {', '.join(override_type)}."
                    ),
                    rationale=(
                        "Modified systemd unit files may indicate security hardening, "
                        "but they can also represent unauthorized changes. Attackers may "
                        "modify unit files to add malicious ExecStart, Environment, "
                        "or security policy overrides. Unit file integrity should be tracked."
                    ),
                    remediation=(
                        f"Review changes: 'systemctl cat {unit_name}'. "
                        f"Compare with package default: "
                        f"'diff /lib/systemd/system/{unit_name} /etc/systemd/system/{unit_name}' "
                        f"if both exist. To revert: 'rm /etc/systemd/system/{unit_name}' "
                        f"and 'systemctl daemon-reload'."
                    ),
                    evidence=FileEvidence(
                        path=str(etc_path) if has_etc_override else str(dropin_dir),
                        content=(
                            f"Override type: {', '.join(override_type)} | "
                            f"Active: {active_val}"
                        ),
                    ),
                    detected_value=f"Unit '{unit_name}' has overrides: {', '.join(override_type)}",
                    expected_value="No overrides from package defaults",
                    affected_component=unit_name,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1543.002", "T1574"],
                    tags=["services", "file-integrity", "hardening"],
                )
            )
        return findings

__all__ = [
    "FailedServicesCheck",
    "ModifiedSystemdUnitCheck",
    "RecentlyInstalledServicesCheck",
    "ServicesFromUnknownBinariesCheck",
    "ServicesRunningAsRootCheck",
    "UnexpectedEnabledServicesCheck",
    "UnexpectedListeningServicesCheck",
]
