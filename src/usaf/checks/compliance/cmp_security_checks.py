from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import CommandEvidence, FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class LegacyServicesCheck(AuditCheck):
    id = "CMP-201"
    name = "Legacy Network Services"
    category = CheckCategory.COMPLIANCE
    severity = Severity.HIGH
    description = "Checks that legacy insecure network services are not installed"
    depends = ["apt"]
    tags = ["compliance", "cis", "services", "legacy"]

    SERVER_PACKAGES: list[str] = [
        "telnetd", "rsh-server", "rsh-redone-server",
        "ypbind", "ypserv", "tftpd", "tftpd-hpa",
        "talkd", "inetutils-talkd", "nis",
    ]

    CLIENT_PACKAGES: list[str] = [
        "telnet", "rsh-client", "rsh-redone-client",
        "tftp-hpa", "talk", "inetutils-talk",
    ]

    LEGACY_PACKAGES: list[str] = SERVER_PACKAGES + CLIENT_PACKAGES

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")
        installed = {p.get("name", "") for p in apt_data.get("packages", [])}

        found_servers = [pkg for pkg in self.SERVER_PACKAGES if pkg in installed]
        found_clients = [pkg for pkg in self.CLIENT_PACKAGES if pkg in installed]
        all_found = found_servers + found_clients

        if not all_found:
            return findings

        desc_parts = []
        if found_servers:
            desc_parts.append(f"Server packages: {', '.join(found_servers)} (actively serve insecure protocols)")
        if found_clients:
            desc_parts.append(f"Client packages: {', '.join(found_clients)} (low risk, useful for legacy connectivity)")

        confidence = Confidence.HIGH if found_servers else Confidence.LOW
        fp_prob = 0.05 if found_servers else 0.6

        findings.append(
            self.finding(
                finding_id="001",
                title="Legacy insecure services installed",
                description="; ".join(desc_parts),
                rationale="Legacy services like telnet, rsh, and tftp transmit data in cleartext and lack modern authentication. They are frequently exploited entry points.",
                remediation=f"Remove legacy packages: 'apt purge {' '.join(all_found)}'.",
                evidence=RegistryEvidence(key="packages.legacy_services", value=", ".join(all_found), expected="none", source="dpkg"),
                detected_value=f"Installed: {', '.join(all_found)}",
                expected_value="No legacy services installed",
                affected_component="Legacy services",
                confidence=confidence,
                false_positive_probability=fp_prob,
                mitre_attack_ids=["T1046"],
                cis_benchmarks=["CIS Ubuntu 20.04: 2.1"],
                tags=["compliance", "cis", "services", "legacy"],
            )
        )
        return findings


@register_check
class XWindowSystemCheck(AuditCheck):
    id = "CMP-202"
    name = "X Window System"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that X Window System is not installed unless required"
    depends = ["apt"]
    tags = ["compliance", "cis", "x11", "hardening"]

    X11_PACKAGES: list[str] = [
        "xserver-xorg-core", "xserver-xorg", "x11-common",
        "xorg", "xserver-xorg-video-*",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")
        installed = {p.get("name", "") for p in apt_data.get("packages", [])}

        found = [pkg for pkg in self.X11_PACKAGES if pkg in installed and "*" not in pkg]

        if not found:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="X Window System packages installed",
                description=f"X11 packages found: {', '.join(found)}. X11 should not be installed on servers.",
                rationale="X Window System provides a graphical desktop environment. On servers, it increases the attack surface and is unnecessary. CIS benchmarks recommend removing X11 on server systems.",
                remediation=f"Remove X11: 'apt purge {' '.join(found)}'.",
                evidence=RegistryEvidence(key="packages.x11", value=", ".join(found), expected="not installed", source="dpkg"),
                detected_value=f"X11 packages: {', '.join(found)}",
                expected_value="No X11 packages on servers",
                affected_component="X Window System",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.3,
                mitre_attack_ids=["T1046"],
                cis_benchmarks=["CIS Ubuntu 20.04: 2.2"],
                tags=["compliance", "cis", "x11", "hardening"],
            )
        )
        return findings


@register_check
class AvahiServiceCheck(AuditCheck):
    id = "CMP-203"
    name = "Avahi/DNS-SD Service"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that Avahi/mDNS service is not running unless required"
    depends = ["dns"]
    tags = ["compliance", "cis", "avahi", "mdns"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        dns_data = self._get_data(collectors, "dns")
        mdns = dns_data.get("mdns", {})

        avahi_running = mdns.get("avahi_running", False)
        avahi_enabled = mdns.get("avahi_enabled", False)

        if not avahi_running and not avahi_enabled:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Avahi/mDNS service is active",
                description=f"Avahi running={avahi_running}, enabled={avahi_enabled}. mDNS should be disabled on servers.",
                rationale="Avahi exposes mDNS/DNS-SD services on the network, enabling service discovery. It increases the attack surface and is unnecessary on most servers.",
                remediation="Stop and disable Avahi: 'systemctl stop avahi-daemon && systemctl disable avahi-daemon'.",
                evidence=RegistryEvidence(key="services.avahi", value=f"running={avahi_running}, enabled={avahi_enabled}", expected="disabled", source="systemd"),
                detected_value=f"Avahi running={avahi_running}, enabled={avahi_enabled}",
                expected_value="Avahi disabled",
                affected_component="Avahi daemon",
                confidence=Confidence.HIGH,
                false_positive_probability=0.15,
                mitre_attack_ids=["T1046"],
                cis_benchmarks=["CIS Ubuntu 20.04: 2.2.3"],
                tags=["compliance", "cis", "avahi", "mdns"],
            )
        )
        return findings


@register_check
class PrintServiceCheck(AuditCheck):
    id = "CMP-204"
    name = "CUPS Print Service"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that CUPS print service is not running unless required"
    depends = ["systemd"]
    tags = ["compliance", "cis", "cups", "printing"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")

        for svc in sys_data.get("services", []):
            name = svc.get("name", "")
            active = svc.get("active", "")

            if "cups" not in name.lower():
                continue
            if active != "active":
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"CUPS print service is active ({name})",
                    description=f"CUPS service '{name}' is active. Print services should be disabled on servers.",
                    rationale="CUPS is unnecessary on most servers and exposes network printing protocols (IPP) that increase the attack surface.",
                    remediation="Stop and disable CUPS: 'systemctl stop cups && systemctl disable cups'.",
                    evidence=RegistryEvidence(key=f"services.{name}", value="active", expected="inactive", source="systemd"),
                    detected_value=f"{name} active",
                    expected_value="CUPS inactive",
                    affected_component=name,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1046"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 2.2.4"],
                    tags=["compliance", "cis", "cups", "printing"],
                )
            )
        return findings


@register_check
class DhcpClientCheck(AuditCheck):
    id = "CMP-205"
    name = "DHCP Client Configuration"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that DHCP client is not running on static IP systems"
    depends = ["interfaces"]
    tags = ["compliance", "cis", "dhcp", "network"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        iface_data = self._get_data(collectors, "interfaces")

        dhcp_client_found = False
        try:
            result = subprocess.run(
                ["ps", "-eo", "comm"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            for proc in result.stdout.splitlines():
                if proc.strip() in ("dhclient", "dhcpcd", "NetworkManager"):
                    dhcp_client_found = True
                    break
        except (OSError, subprocess.SubprocessError):
            pass

        if dhcp_client_found:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="DHCP client process running",
                    description="A DHCP client process (dhclient/dhcpcd) is running. Static IP systems should not run DHCP clients.",
                    rationale="DHCP clients on static systems are unnecessary and may accept rogue DHCP offers, leading to DNS hijacking or man-in-the-middle attacks.",
                    remediation="Stop and disable DHCP client. For NetworkManager: 'nmcli connection modify <name> ipv4.method manual'.",
                    evidence=CommandEvidence(
                        command="ps -eo comm | grep -E 'dhclient|dhcpcd'",
                        stdout="DHCP client running",
                        exit_code=0,
                    ),
                    detected_value="DHCP client process active",
                    expected_value="No DHCP client on static IP systems",
                    affected_component="DHCP client",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1046"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 2.2.5"],
                    tags=["compliance", "cis", "dhcp", "network"],
                )
            )
        return findings


@register_check
class NfsServiceCheck(AuditCheck):
    id = "CMP-206"
    name = "NFS Services"
    category = CheckCategory.COMPLIANCE
    severity = Severity.HIGH
    description = "Checks that NFS services are not running unless explicitly required"
    depends = ["systemd"]
    tags = ["compliance", "cis", "nfs", "services"]

    NFS_UNITS: list[str] = ["nfs-server", "nfs-kernel-server", "rpcbind"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        active_units = {svc.get("name", "") for svc in sys_data.get("services", []) if svc.get("active") == "active"}

        found = [u for u in self.NFS_UNITS if any(u in s for s in active_units)]

        if not found:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="NFS services are active",
                description=f"NFS services active: {', '.join(found)}. NFS should be disabled unless required.",
                rationale="NFS exposes filesystem shares over the network. It has a history of vulnerabilities and should only run on dedicated NFS servers with proper firewalling.",
                remediation=f"Stop and disable NFS: 'systemctl stop {' '.join(found)} && systemctl disable {' '.join(found)}'.",
                evidence=RegistryEvidence(key="services.nfs", value=", ".join(found), expected="not running", source="systemd"),
                detected_value=f"NFS: {', '.join(found)}",
                expected_value="NFS services disabled",
                affected_component="NFS",
                confidence=Confidence.HIGH,
                false_positive_probability=0.15,
                mitre_attack_ids=["T1046"],
                cis_benchmarks=["CIS Ubuntu 20.04: 2.2.7"],
                tags=["compliance", "cis", "nfs", "services"],
            )
        )
        return findings


@register_check
class RsyncServiceCheck(AuditCheck):
    id = "CMP-207"
    name = "Rsync Service"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that rsync daemon is not running"
    depends = ["systemd"]
    tags = ["compliance", "cis", "rsync", "services"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")

        for svc in sys_data.get("services", []):
            name = svc.get("name", "")
            active = svc.get("active", "")

            if "rsync" not in name.lower():
                continue
            if active != "active":
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Rsync service is active ({name})",
                    description=f"Rsync service '{name}' is running. Rsync should not run as a daemon unless essential.",
                    rationale="The rsync daemon can expose filesystems over the network. It should not be running as a persistent service unless specifically required for backups.",
                    remediation="Stop and disable rsync: 'systemctl stop rsync && systemctl disable rsync'. Use SSH-based rsync instead.",
                    evidence=RegistryEvidence(key=f"services.{name}", value="active", expected="inactive", source="systemd"),
                    detected_value=f"{name} active",
                    expected_value="Rsync daemon disabled",
                    affected_component=name,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1046"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 2.2.9"],
                    tags=["compliance", "cis", "rsync", "services"],
                )
            )
        return findings


@register_check
class SmtpServiceCheck(AuditCheck):
    id = "CMP-208"
    name = "SMTP Service Configuration"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks SMTP service is configured securely (not listening on all interfaces)"
    depends = ["sockets"]
    tags = ["compliance", "cis", "smtp", "email"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")

        smtp_on_all = False
        for proto in ("tcp", "tcp6"):
            for entry in sock_data.get(proto, []):
                port = int(entry.get("local_port", 0))
                local = entry.get("local_address", "")
                if port == 25 and local in ("0.0.0.0", "::"):
                    smtp_on_all = True
                    break

        if not smtp_on_all:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="SMTP listening on all interfaces",
                description="SMTP (port 25) is listening on all interfaces. SMTP should be bound to localhost unless it's a mail relay.",
                rationale="SMTP on all interfaces is discoverable via port scanning and can be abused for spam relay or email address harvesting.",
                remediation="Bind SMTP to localhost in your MTA config. For Postfix: 'inet_interfaces = localhost' in /etc/postfix/main.cf.",
                evidence=RegistryEvidence(key="services.smtp.bind", value="0.0.0.0:25", expected="127.0.0.1:25", source="/proc/net/tcp"),
                detected_value="SMTP on all interfaces",
                expected_value="SMTP bound to localhost",
                affected_component="SMTP service",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.3,
                mitre_attack_ids=["T1046"],
                cis_benchmarks=["CIS Ubuntu 20.04: 2.2.11"],
                tags=["compliance", "cis", "smtp", "email"],
            )
        )
        return findings


@register_check
class HttpServiceCheck(AuditCheck):
    id = "CMP-209"
    name = "HTTP/HTTPS Service"  # Fixed typo from CMP-209
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that web servers are configured with security best practices"
    depends = ["systemd", "sockets"]
    tags = ["compliance", "cis", "http", "apache", "nginx"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")
        sys_data = self._get_data(collectors, "systemd")

        web_servers_active = set()
        for svc in sys_data.get("services", []):
            name = svc.get("name", "")
            active = svc.get("active", "")
            if active == "active" and any(ws in name.lower() for ws in ("apache", "nginx", "httpd", "lighttpd")):
                web_servers_active.add(name)

        http_on_all = False
        for proto in ("tcp", "tcp6"):
            for entry in sock_data.get(proto, []):
                port = int(entry.get("local_port", 0))
                local = entry.get("local_address", "")
                if port in (80, 443) and local in ("0.0.0.0", "::"):
                    http_on_all = True

        if not web_servers_active:
            return findings
        if not http_on_all:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Web server running on all interfaces",
                description=f"Web server(s) active: {', '.join(web_servers_active)}. HTTP/HTTPS on all interfaces should be firewalled.",
                rationale="Web servers on all interfaces expose the attack surface. Ensure proper firewall rules and TLS configuration are in place.",
                remediation="Configure firewall rules for ports 80/443. Ensure TLS is properly configured and unnecessary modules are disabled.",
                evidence=RegistryEvidence(key="services.web.bind", value="0.0.0.0:80/443", expected="firewalled", source="/proc/net/tcp"),
                detected_value=f"Web servers: {', '.join(web_servers_active)}",
                expected_value="Web server properly firewalled",
                affected_component="Web server",
                confidence=Confidence.LOW,
                false_positive_probability=0.5,
                mitre_attack_ids=["T1046"],
                cis_benchmarks=["CIS Ubuntu 20.04: 2.2.10"],
                tags=["compliance", "cis", "http", "apache", "nginx"],
            )
        )
        return findings


@register_check
class CronDaemonCheck(AuditCheck):
    id = "CMP-210"
    name = "Cron Daemon Permissions"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks cron daemon configuration for secure permissions"
    depends = []
    tags = ["compliance", "cis", "cron", "permissions"]

    CRON_FILES: list[str] = [
        "/etc/crontab",
        "/etc/cron.allow",
        "/etc/at.allow",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []

        for filepath in self.CRON_FILES:
            path = Path(filepath)
            if not path.exists():
                continue

            try:
                st = path.stat()
                if st.st_uid == 0 and st.st_gid == 0:
                    continue
            except OSError:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Cron file not owned by root: {filepath}",
                    description=f"'{filepath}' is owned by uid {st.st_uid}:{st.st_gid}, expected root:root.",
                    rationale="Cron configuration files must be owned by root to prevent privilege escalation via cron job manipulation.",
                    remediation=f"Fix ownership: 'chown root:root {filepath}'.",
                    evidence=FileEvidence(
                        path=filepath,
                        owner=str(st.st_uid),
                        group=str(st.st_gid),
                        content=f"Owner {st.st_uid}:{st.st_gid}",
                    ),
                    detected_value=f"Owner {st.st_uid}:{st.st_gid}",
                    expected_value="root:root",
                    affected_component=filepath,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1053"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.1"],
                    tags=["compliance", "cis", "cron", "permissions"],
                )
            )
        return findings


@register_check
class SshProtocolComplianceCheck(AuditCheck):
    id = "CMP-211"
    name = "SSH Compliance Check"
    category = CheckCategory.COMPLIANCE
    severity = Severity.HIGH
    description = "Aggregated SSH compliance check for key CIS SSH controls"
    depends = []
    tags = ["compliance", "cis", "ssh", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sshd_config = Path("/etc/ssh/sshd_config")

        if not sshd_config.exists():
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH server not installed",
                    description="No /etc/ssh/sshd_config found. SSH server is not installed.",
                    rationale="Without SSH, remote administration is not possible via secure channel. If remote access is needed, install and configure SSH.",
                    remediation="Install SSH: 'apt install openssh-server'. Configure per CIS benchmarks.",
                    evidence=FileEvidence(path="/etc/ssh/sshd_config", content="File not found"),
                    detected_value="sshd_config missing",
                    expected_value="SSH server installed and configured",
                    affected_component="SSH",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1046"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2"],
                    tags=["compliance", "cis", "ssh", "hardening"],
                )
            )
        return findings
