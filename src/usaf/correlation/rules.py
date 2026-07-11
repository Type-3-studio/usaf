from __future__ import annotations

from usaf.correlation.engine import CorrelatedFinding, CorrelationRule
from usaf.models.evidence import NetworkEvidence, PackageEvidence
from usaf.models.finding import Finding
from usaf.models.severity import Severity


class SSHBruteForceSurface(CorrelationRule):
    """Detects systems exposed to SSH brute-force attacks.

    Combines findings about SSH configuration (protocol version, root login,
    weak KEX algorithms) with network exposure (port 22 listening on a
    public or all interface).
    """

    id = "SSH-BRUTE"
    name = "SSH Brute-Force Attack Surface"
    description = "Detects SSH configurations that enable remote brute-force attacks"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        ssh_findings = [f for f in findings if f.check_id.startswith("SSH-")]
        net_findings = [
            f for f in findings if f.check_id == "NET-001" and self._is_ssh_port(f)
        ]

        if not ssh_findings or not net_findings:
            return []

        root_login = next(
            (f for f in ssh_findings if "root" in f.title.lower() or "root" in (f.affected_component or "").lower()),
            None,
        )
        old_protocol = next(
            (f for f in ssh_findings if "protocol" in f.title.lower() or "version" in f.title.lower()),
            None,
        )
        weak_kex = next(
            (
                f
                for f in ssh_findings
                if "kex" in f.title.lower() or "algorithm" in f.title.lower() or "cipher" in f.title.lower()
            ),
            None,
        )

        if root_login is None and old_protocol is None and weak_kex is None:
            return []

        details: list[str] = []
        if root_login:
            details.append("root SSH login is permitted")
        if old_protocol:
            details.append("SSH protocol version allows weak protocol negotiation")
        if weak_kex:
            details.append("weak key exchange algorithms are enabled")

        ports_detail = self._describe_ports(net_findings)

        return [
            self._make_finding(
                finding_id="001",
                title="SSH Attack Surface — Remote Brute-Force Possible",
                description=(
                    f"SSH is externally accessible on {ports_detail} with "
                    f"vulnerable configuration: {'; '.join(details)}. "
                    "This creates a remote brute-force attack surface that "
                    "can be exploited without prior access."
                ),
                rationale=(
                    "SSH is the most targeted service on internet-facing systems. "
                    "Combining network exposure with weak SSH configuration "
                    "enables credential stuffing, dictionary attacks, and "
                    "targeted brute-force attacks against privileged accounts."
                ),
                remediation=(
                    "1. Disable root SSH login: set 'PermitRootLogin no' in /etc/ssh/sshd_config\n"
                    "2. Restrict SSH to protocol 2 only\n"
                    "3. Remove weak KEX algorithms (diffie-hellman-group1-sha1, "
                    "diffie-hellman-group14-sha1)\n"
                    "4. Use key-based authentication only: set 'PasswordAuthentication no'\n"
                    "5. If possible, bind SSH to a private/management network only"
                ),
                source_findings=[f for f in [root_login, old_protocol, weak_kex] if f is not None] + net_findings,
                severity=Severity.CRITICAL,
                tags=["ssh", "brute-force", "attack-surface", "remote-exploit"],
                mitre_attack_ids=["T1110", "T1190"],
                cis_benchmarks=["CIS Ubuntu 22.04: 5.2.1", "CIS Ubuntu 22.04: 5.2.2"],
            )
        ]

    @staticmethod
    def _is_ssh_port(finding: Finding) -> bool:
        ev = finding.evidence
        if ev is None:
            return False
        if isinstance(ev, NetworkEvidence) and ev.local_port == 22:
            return True
        if isinstance(ev, NetworkEvidence) and ev.local_port == 22:
            return True
        if hasattr(ev, "local_port") and getattr(ev, "local_port", None) == 22:
            return True
        return False

    @staticmethod
    def _describe_ports(findings: list[Finding]) -> str:
        interfaces: list[str] = []
        for f in findings:
            ev = f.evidence
            if ev is None:
                continue
            addr = getattr(ev, "local_address", None)
            if addr and addr != "0.0.0.0" and addr != "::":
                interfaces.append(addr)
        if not interfaces:
            return "all network interfaces (0.0.0.0)"
        return ", ".join(interfaces)


class SuspiciousPersistence(CorrelationRule):
    """Detects potential persistence mechanisms on the system.

    Combines user account anomalies with unexpected services and
    SSH key changes to identify backdoor or persistence indicators.
    """

    id = "PERSIST-DETECT"
    name = "Suspicious Persistence Detection"
    description = "Detects potential backdoor or persistence mechanisms"
    severity = Severity.HIGH

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        user_anomalies = [
            f for f in findings if f.check_id.startswith("USR-")
        ]
        unknown_services = [
            f for f in findings
            if ("service" in f.check_id.lower() or "systemd" in f.check_id.lower())
            and f.id not in ("SVC-001",)
        ]
        suid_findings = [
            f for f in findings if f.check_id == "PRM-001"
        ]

        is_suspicious = len(user_anomalies) >= 1 and len(unknown_services) >= 1
        has_suid_backdoor = len(suid_findings) >= 2 and len(user_anomalies) >= 1

        if not is_suspicious and not has_suid_backdoor:
            return []

        combined_sources = user_anomalies + unknown_services + (suid_findings if has_suid_backdoor else [])

        return [
            self._make_finding(
                finding_id="001",
                title="Potential Persistence Mechanism Detected",
                description=(
                    f"Found {len(user_anomalies)} user account anomalies and "
                    f"{len(unknown_services)} unknown services"
                    + (f", plus {len(suid_findings)} unexpected SUID binaries"
                       if has_suid_backdoor else "")
                    + ". This pattern is consistent with backdoor or "
                    "persistence mechanism installation."
                ),
                rationale=(
                    "Attackers often create user accounts for persistent access, "
                    "install systemd services for autoruns, and deploy SUID "
                    "backdoors for privilege escalation. The presence of all "
                    "three indicators significantly increases the likelihood "
                    "of an active compromise."
                ),
                remediation=(
                    "1. Review all user accounts: 'cat /etc/passwd | grep /home'\n"
                    "2. Investigate unknown systemd services: 'systemctl list-units --all'\n"
                    "3. Audit SUID binaries: 'find / -perm -4000 -ls'\n"
                    "4. Check SSH authorized_keys for each user\n"
                    "5. Review /var/log/auth.log for unusual authentication patterns"
                ),
                source_findings=combined_sources,
                severity=Severity.HIGH,
                tags=["persistence", "backdoor", "compromise", "tampering"],
                mitre_attack_ids=["T1098", "T1543", "T1548"],
            )
        ]


class UnauthorizedService(CorrelationRule):
    """Detects likely unauthorized services running on the system.

    Combines unexpected listening ports, unknown SUID binaries, and
    unknown systemd services to identify rogue services.
    """

    id = "UNAUTH-SVC"
    name = "Unauthorized Service Detection"
    description = "Detects likely unauthorized or rogue services"
    severity = Severity.HIGH

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        unexpected_ports = [
            f for f in findings
            if f.check_id == "NET-001"
            and getattr(f.evidence, "local_port", None) not in (22, 80, 443, 53, 0, None)
        ]
        unknown_binaries = [
            f for f in findings
            if f.check_id == "PRM-001"
        ]
        service_findings = [
            f for f in findings
            if f.check_id.startswith("SVC-") or f.check_id == "NET-002"
        ]

        if len(unexpected_ports) < 1:
            return []

        suspicious_ports = unexpected_ports[:3]
        combined = suspicious_ports + unknown_binaries[:2] + service_findings[:2]

        port_details = ", ".join(
            f"{getattr(f.evidence, 'local_port', '?')}/{getattr(f.evidence, 'protocol', 'tcp')}"
            for f in suspicious_ports
            if f.evidence
        )

        return [
            self._make_finding(
                finding_id="001",
                title="Likely Unauthorized Service Running",
                description=(
                    f"Found unexpected listening port(s): {port_details}. "
                    + (f"Combined with {len(unknown_binaries)} unknown SUID binaries "
                       if unknown_binaries else "")
                    + (f" and {len(service_findings)} service anomalies. "
                       if service_findings else ". ")
                    + "This indicates a potentially unauthorized service."
                ),
                rationale=(
                    "Unauthorized services are a primary indicator of compromise "
                    "or policy violation. Attackers deploy reverse shells, "
                    "backdoor listeners, and cryptocurrency miners on unusual ports. "
                    "Legitimate services should be documented in the security baseline."
                ),
                remediation=(
                    "1. Identify the process on each unexpected port: "
                    "'ss -tlnp | grep <port>'\n"
                    "2. Verify the binary against package manager: "
                    "'dpkg -S <binary>'\n"
                    "3. Check systemd for unknown services: "
                    "'systemctl list-units --type=service'\n"
                    "4. Review process ancestry in /proc/<pid>/status"
                ),
                source_findings=combined,
                severity=Severity.HIGH,
                tags=["unauthorized-service", "rogue-process", "backdoor"],
                mitre_attack_ids=["T1505", "T1043", "T1059"],
            )
        ]


class DataExfilSurface(CorrelationRule):
    """Detects network indicators consistent with data exfiltration.

    Combines promiscuous mode network interfaces with unexpected
    listening ports or unusual network states to identify potential
    data exfiltration or network sniffing.
    """

    id = "EXFIL-SURFACE"
    name = "Data Exfiltration Surface Detection"
    description = "Detects network sniffing and data exfiltration indicators"
    severity = Severity.MEDIUM

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        promiscuous = [
            f for f in findings
            if f.check_id == "NET-002"
        ]
        unexpected_ports = [
            f for f in findings
            if f.check_id == "NET-001"
            and getattr(f.evidence, "local_port", None) not in (22, 80, 443, 53, 0, None)
        ]
        suid_findings = [
            f for f in findings
            if f.check_id == "PRM-001"
        ]

        if not promiscuous and (len(unexpected_ports) < 2 or not suid_findings):
            return []

        combined = promiscuous + unexpected_ports + suid_findings

        return [
            self._make_finding(
                finding_id="001",
                title="Network Sniffing Indicators Present",
                description=(
                    f"Promiscuous mode detected on {len(promiscuous)} interface(s)"
                    + (f" with {len(unexpected_ports)} unexpected ports and "
                       f"{len(suid_findings)} unknown SUID binaries."
                       if unexpected_ports or suid_findings
                       else ". No other suspicious indicators found.")
                    + " Promiscuous mode interfaces can capture network traffic "
                    "and may indicate packet sniffing activity."
                ),
                rationale=(
                    "Promiscuous mode network interfaces combined with unexpected "
                    "services or SUID binaries is strongly indicative of a "
                    "network sniffer or traffic interceptor. Attackers use "
                    "promiscuous mode to capture credentials, session tokens, "
                    "and sensitive data traversing the network."
                ),
                remediation=(
                    "1. Investigate promiscuous interfaces: 'ip link show'\n"
                    "2. Check for packet capture tools: 'which tcpdump wireshark tshark'\n"
                    "3. Review running processes for sniffing tools\n"
                    "4. Check for kernel module loading: 'lsmod | grep -E \"nf|tap|tun\"'\n"
                    "5. If using Docker, verify container network isolation"
                ),
                source_findings=combined,
                severity=Severity.MEDIUM,
                tags=["exfiltration", "sniffing", "promiscuous", "data-theft"],
                mitre_attack_ids=["T1040", "T1205"],
            )
        ]


class SuidArmingChain(CorrelationRule):
    """Detects privilege escalation chains via SUID + world-writable files.

    Combines world-writable critical files (PRM-002) with unexpected SUID
    binaries (PRM-001). An attacker who can write to a file that is then
    executed by a SUID binary can trivially escalate to root.
    """

    id = "SUID-ARM"
    name = "SUID Privilege Escalation Chain"
    description = "Detects world-writable files combined with SUID binaries enabling privesc"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        ww_findings = [f for f in findings if f.check_id == "PRM-002"]
        suid_findings = [f for f in findings if f.check_id == "PRM-001"]

        if not ww_findings or not suid_findings:
            return []

        ww_paths = [
            getattr(f.evidence, "path", "")
            for f in ww_findings
            if hasattr(f.evidence, "path")
        ]
        suid_paths = [
            getattr(f.evidence, "path", "")
            for f in suid_findings
            if hasattr(f.evidence, "path")
        ]

        return [
            self._make_finding(
                finding_id="001",
                title="Privilege Escalation Chain — SUID + World-Writable Files",
                description=(
                    f"Found {len(ww_findings)} world-writable file(s) "
                    f"({', '.join(ww_paths[:3])}) and {len(suid_findings)} "
                    f"unexpected SUID binary(es) ({', '.join(suid_paths[:3])}). "
                    "A world-writable file that a SUID binary depends on can "
                    "be replaced to execute arbitrary code as root."
                ),
                rationale=(
                    "The combination of SUID binaries and world-writable files "
                    "creates a direct privilege escalation vector. If a SUID binary "
                    "loads a library, reads a config, or executes a helper from a "
                    "world-writable path, any user can replace that resource with "
                    "malicious content and gain root when the SUID binary runs. "
                    "This is a well-known technique used by privilege escalation "
                    "tools such as GTFO Bins."
                ),
                remediation=(
                    "1. Remove world-writable permissions: 'chmod o-w <file>'\n"
                    "2. Audit SUID binaries: 'find / -perm -4000 -ls'\n"
                    "3. Verify all SUID binaries are from official packages\n"
                    "4. Check SUID binary dependencies: 'ldd <binary>'"
                ),
                source_findings=ww_findings + suid_findings,
                severity=Severity.CRITICAL,
                tags=["privilege-escalation", "suid", "world-writable", "privesc-chain"],
                mitre_attack_ids=["T1548.001", "T1574.001", "T1574.002"],
                cis_benchmarks=["CIS Ubuntu 22.04: 1.7", "CIS Ubuntu 22.04: 5.1"],
            )
        ]


class DefenseEvasionIndicators(CorrelationRule):
    """Detects systems where multiple security controls are disabled.

    Combines firewall inactive (FIREWALL-001), disabled auditd (FOR-001),
    disabled AppArmor (SEC-001), and disabled USB storage (USB-001) to
    identify potential defense evasion by an attacker.
    """

    id = "DEF-EVADE"
    name = "Defense Evasion Indicators"
    description = "Detects multiple disabled security controls suggesting defense evasion"
    severity = Severity.HIGH

    REQUIRED_CHECK_IDS = {
        "FIREWALL-001",
        "FOR-001",
        "SEC-001",
        "USB-001",
    }

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        disabled_controls: dict[str, Finding] = {}

        for f in findings:
            check_id = f.check_id
            if check_id in self.REQUIRED_CHECK_IDS:
                disabled_controls[check_id] = f

        if len(disabled_controls) < 2:
            return []

        control_names: list[str] = []
        for cid in ["FIREWALL-001", "FOR-001", "SEC-001", "USB-001"]:
            if cid in disabled_controls:
                name = {
                    "FIREWALL-001": "firewall",
                    "FOR-001": "auditd",
                    "SEC-001": "AppArmor",
                    "USB-001": "USB storage restriction",
                }.get(cid, cid)
                control_names.append(name)

        return [
            self._make_finding(
                finding_id="001",
                title=f"Multiple Security Controls Disabled ({len(disabled_controls)}/{len(self.REQUIRED_CHECK_IDS)})",
                description=(
                    f"Disabled security control(s): {', '.join(control_names)}. "
                    "Having multiple security subsystems disabled simultaneously "
                    "may indicate defense evasion by an attacker who has "
                    "deactivated protections to avoid detection."
                ),
                rationale=(
                    "Attackers routinely disable security controls after gaining "
                    "initial access to avoid detection and maintain persistence. "
                    "Firewall deactivation allows outbound C2 traffic. Auditd "
                    "disabling erases forensic evidence. AppArmor disablement "
                    "removes containment restrictions. When multiple controls "
                    "are disabled, the probability of active compromise increases "
                    "significantly above the baseline of each individual finding."
                ),
                remediation=(
                    "1. Enable firewall: 'ufw enable' or 'systemctl enable --now nftables'\n"
                    "2. Enable auditd: 'systemctl enable --now auditd'\n"
                    "3. Enable AppArmor: 'systemctl enable --now apparmor'\n"
                    "4. Investigate HOW controls were disabled: check auth.log\n"
                    "5. Review recent sudo usage: 'grep sudo /var/log/auth.log'"
                ),
                source_findings=list(disabled_controls.values()),
                severity=Severity.HIGH,
                tags=["defense-evasion", "tampering", "compromise", "hardening"],
                mitre_attack_ids=["T1562.001", "T1562.004", "T1562.006", "T1562.010"],
                cis_benchmarks=["CIS Ubuntu 22.04: 1.4", "CIS Ubuntu 22.04: 3.2"],
            )
        ]


class ExposedVulnerableService(CorrelationRule):
    """Detects vulnerable/risky packages exposed on network ports.

    Combines PKG-001 findings (risky packages like cups, samba, telnet)
    with NET-001 findings (listening ports) to identify services that
    are both installed and network-accessible.
    """

    id = "EXPO-VULN"
    name = "Exposed Vulnerable Service"
    description = "Detects risky packages that are listening on network ports"
    severity = Severity.CRITICAL

    PKG_PORT_MAP: dict[str, set[int]] = {
        "cups": {631},
        "samba": {139, 445},
        "snmpd": {161},
        "telnetd": {23},
        "rsh-server": {513, 514},
    }

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        risky_pkgs: dict[str, Finding] = {}
        for f in findings:
            if f.check_id == "PKG-001":
                ev = f.evidence
                if isinstance(ev, PackageEvidence) and ev.name:
                    risky_pkgs[ev.name] = f

        listening_ports: dict[int, Finding] = {}
        for f in findings:
            if f.check_id == "NET-001":
                port = getattr(f.evidence, "local_port", None)
                if isinstance(port, int):
                    listening_ports[port] = f

        if not risky_pkgs or not listening_ports:
            return []

        exposed: list[dict[str, object]] = []
        for pkg_name, pkg_finding in risky_pkgs.items():
            expected_ports = self.PKG_PORT_MAP.get(pkg_name, set())
            matched_ports = expected_ports & listening_ports.keys()
            for port in matched_ports:
                exposed.append({
                    "package": pkg_name,
                    "port": port,
                    "pkg_finding": pkg_finding,
                    "port_finding": listening_ports[port],
                })

        if not exposed:
            return []

        details = "; ".join(
            f"{e['package']} on port {e['port']}" for e in exposed
        )
        source_findings = []
        for e in exposed:
            if e["pkg_finding"] not in source_findings:
                source_findings.append(e["pkg_finding"])
            if e["port_finding"] not in source_findings:
                source_findings.append(e["port_finding"])

        return [
            self._make_finding(
                finding_id="001",
                title=f"Exposed Vulnerable Service(s): {details}",
                description=(
                    f"Risk package(s) detected listening on network port(s): {details}. "
                    "These services are both installed (potentially with known "
                    "vulnerabilities) and network-accessible, creating a remote "
                    "exploitation surface."
                ),
                rationale=(
                    "A service that is both installed and listening on a network "
                    "port is remotely exploitable. Risky packages such as CUPS, "
                    "Samba, and SNMP have historical CVEs allowing remote code "
                    "execution, credential theft, and information disclosure. "
                    "On internet-facing systems, exposed services are the primary "
                    "initial access vector for attackers."
                ),
                remediation=(
                    "1. Remove unnecessary packages: 'apt purge <package>'\n"
                    "2. If required, bind to localhost only in the service config\n"
                    "3. Add firewall rules to restrict access: 'ufw deny <port>'\n"
                    "4. Ensure the service is patched: 'apt update && apt upgrade'"
                ),
                source_findings=source_findings,
                severity=Severity.CRITICAL,
                tags=["exposed-service", "remote-exploit", "vulnerability", "attack-surface"],
                mitre_attack_ids=["T1190", "T1043", "T1505"],
                cis_benchmarks=["CIS Ubuntu 22.04: 2.1", "CIS Ubuntu 22.04: 4.4"],
            )
        ]
