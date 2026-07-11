from __future__ import annotations

from typing import TypedDict

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
            f for f in findings if f.check_id == "NET-101" and self._is_ssh_port(f)
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
            and f.id not in ("SVC-101",)
        ]
        suid_findings = [
            f for f in findings if f.check_id == "PRM-101"
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
            if f.check_id == "NET-101"
            and getattr(f.evidence, "local_port", None) not in (22, 80, 443, 53, 0, None)
        ]
        unknown_binaries = [
            f for f in findings
            if f.check_id == "PRM-101"
        ]
        service_findings = [
            f for f in findings
            if f.check_id.startswith("SVC-") or f.check_id == "NET-201"
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
            if f.check_id == "NET-201"
        ]
        unexpected_ports = [
            f for f in findings
            if f.check_id == "NET-101"
            and getattr(f.evidence, "local_port", None) not in (22, 80, 443, 53, 0, None)
        ]
        suid_findings = [
            f for f in findings
            if f.check_id == "PRM-101"
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

    Combines world-writable critical files (PRM-201) with unexpected SUID
    binaries (PRM-101). An attacker who can write to a file that is then
    executed by a SUID binary can trivially escalate to root.
    """

    id = "SUID-ARM"
    name = "SUID Privilege Escalation Chain"
    description = "Detects world-writable files combined with SUID binaries enabling privesc"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        ww_findings = [f for f in findings if f.check_id == "PRM-201"]
        suid_findings = [f for f in findings if f.check_id == "PRM-101"]

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

    Combines firewall inactive (FW-101), disabled auditd (FOR-101),
    disabled AppArmor (SEC-101), and disabled USB storage (USB-101) to
    identify potential defense evasion by an attacker.
    """

    id = "DEF-EVADE"
    name = "Defense Evasion Indicators"
    description = "Detects multiple disabled security controls suggesting defense evasion"
    severity = Severity.HIGH

    REQUIRED_CHECK_IDS = {
        "FW-101",
        "FOR-101",
        "SEC-101",
        "USB-101",
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
        for cid in ["FW-101", "FOR-101", "SEC-101", "USB-101"]:
            if cid in disabled_controls:
                name = {
                    "FW-101": "firewall",
                    "FOR-101": "auditd",
                    "SEC-101": "AppArmor",
                    "USB-101": "USB storage restriction",
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

    Combines PKG-101 findings (risky packages like cups, samba, telnet)
    with NET-101 findings (listening ports) to identify services that
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
            if f.check_id == "PKG-101":
                ev = f.evidence
                if isinstance(ev, PackageEvidence) and ev.name:
                    risky_pkgs[ev.name] = f

        listening_ports: dict[int, Finding] = {}
        for f in findings:
            if f.check_id == "NET-101":
                port = getattr(f.evidence, "local_port", None)
                if isinstance(port, int):
                    listening_ports[port] = f

        if not risky_pkgs or not listening_ports:
            return []

        class _ExposedEntry(TypedDict):
            package: str
            port: int
            pkg_finding: Finding
            port_finding: Finding

        exposed: list[_ExposedEntry] = []
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
        source_findings: list[Finding] = []
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


class SupplyChainAttack(CorrelationRule):
    """Detects supply chain attack indicators.

    Combines unknown repositories (PKG-301), unsigned/broken package
    signatures (PKG-202), and modified package files (PKG-201) to
    identify potential software supply chain compromise.
    """

    id = "SUPPLY-CHAIN"
    name = "Supply Chain Attack Detection"
    description = "Detects indicators of software supply chain compromise"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        unknown_repos = [f for f in findings if f.check_id == "PKG-301"]
        broken_sigs = [f for f in findings if f.check_id == "PKG-202"]
        modified_files = [f for f in findings if f.check_id == "PKG-201"]

        if not unknown_repos:
            return []

        if len(unknown_repos) + len(broken_sigs) + len(modified_files) < 2:
            return []

        details: list[str] = []
        if unknown_repos:
            details.append(f"{len(unknown_repos)} unknown repository/repositories")
        if broken_sigs:
            details.append(f"{len(broken_sigs)} broken/missing signature(s)")
        if modified_files:
            details.append(f"{len(modified_files)} modified package file(s)")

        source_findings: list[Finding] = unknown_repos + broken_sigs + modified_files

        return [
            self._make_finding(
                finding_id="001",
                title="Supply Chain Attack Indicators Detected",
                description=(
                    f"Found evidence of possible supply chain compromise: "
                    f"{'; '.join(details)}. "
                    "This pattern indicates the software supply chain may have been "
                    "tampered with or compromised."
                ),
                rationale=(
                    "Supply chain attacks target the software distribution pipeline. "
                    "Unknown repositories can host malicious packages, while unsigned "
                    "packages cannot be verified as authentic. Modified package files "
                    "indicate post-installation tampering. The combination of these "
                    "indicators significantly increases the likelihood of a supply "
                    "chain compromise, where an attacker has inserted malicious code "
                    "into the software update process."
                ),
                remediation=(
                    "1. Remove unknown repositories: 'add-apt-repository --remove <repo>'\n"
                    "2. Reinstall affected packages: 'apt-get --reinstall install <package>'\n"
                    "3. Update GPG keys: 'apt install --reinstall ubuntu-keyring'\n"
                    "4. Scan for malware: 'apt install clamav && freshclam && clamscan -r /'\n"
                    "5. Investigate package origin and authenticity"
                ),
                source_findings=source_findings,
                severity=Severity.CRITICAL,
                tags=["supply-chain", "tampering", "compromise"],
                mitre_attack_ids=["T1195", "T1195.001", "T1554"],
                cis_benchmarks=["CIS Ubuntu 22.04: 2.1", "CIS Ubuntu 22.04: 2.2", "CIS Ubuntu 22.04: 2.3"],
            )
        ]


class BootIntegrityFailure(CorrelationRule):
    """Detects boot integrity failures.

    Combines Secure Boot disabled (BOOT-101), unsigned kernels (BOOT-501),
    and no GRUB password (BOOT-401) to identify systems vulnerable to
    boot-level attacks.
    """

    id = "BOOT-FAIL"
    name = "Boot Integrity Failure Chain"
    description = "Detects multiple boot security controls disabled"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        sb_disabled = [f for f in findings if f.check_id == "BOOT-101"]
        no_grub_pw = [f for f in findings if f.check_id == "BOOT-401"]
        unsigned_kernels = [f for f in findings if f.check_id == "BOOT-501"]

        if len(sb_disabled) + len(no_grub_pw) + len(unsigned_kernels) < 2:
            return []

        details: list[str] = []
        if sb_disabled:
            details.append("Secure Boot disabled")
        if no_grub_pw:
            details.append("no GRUB password")
        if unsigned_kernels:
            details.append("unsigned kernel(s)")

        source_findings = sb_disabled + no_grub_pw + unsigned_kernels

        return [
            self._make_finding(
                finding_id="001",
                title=f"Boot Security Chain Broken ({len(source_findings)} controls failed)",
                description=(
                    f"Multiple boot security controls are disabled or misconfigured: "
                    f"{'; '.join(details)}. "
                    "This significantly weakens boot integrity and allows bootkit installation."
                ),
                rationale=(
                    "Boot-level attacks are among the most dangerous because they "
                    "persist across OS reinstalls and can bypass full-disk encryption. "
                    "Secure Boot prevents unsigned bootloaders, a GRUB password prevents "
                    "unauthorized boot parameter changes, and signed kernels ensure "
                    "kernel authenticity. When multiple boot controls are missing, the "
                    "system is vulnerable to bootkits (BlackLotus, BootHole) that install "
                    "before the OS loads."
                ),
                remediation=(
                    "1. Enable Secure Boot in UEFI settings\n"
                    "2. Set a GRUB password: 'grub-mkpasswd-pbkdf2' and configure\n"
                    "3. Install signed kernels: 'apt install linux-image-generic-signed'\n"
                    "4. Verify: 'mokutil --sb-state && sbverify --list /boot/vmlinuz-*'\n"
                    "5. Review UEFI boot entries: 'efibootmgr -v'"
                ),
                source_findings=source_findings,
                severity=Severity.CRITICAL,
                tags=["boot", "secure-boot", "integrity", "bootkit"],
                mitre_attack_ids=["T1542", "T1542.001", "T1542.003"],
                cis_benchmarks=["CIS Ubuntu 22.04: 1.6", "CIS Ubuntu 22.04: 1.7"],
            )
        ]


class DNSHijacking(CorrelationRule):
    """Detects DNS hijacking indicators.

    Combines unexpected DNS servers (NET-301), modified /etc/hosts (NET-302),
    and disabled DNSSEC (NET-501) to identify potential DNS hijacking.
    """

    id = "DNS-HIJACK"
    name = "DNS Hijacking Detection"
    description = "Detects indicators of DNS manipulation or hijacking"
    severity = Severity.HIGH

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        unexpected_dns = [f for f in findings if f.check_id == "NET-301"]
        modified_hosts = [f for f in findings if f.check_id == "NET-302"]
        no_dnssec = [f for f in findings if f.check_id == "NET-501"]

        if not unexpected_dns and not modified_hosts:
            return []

        if len(unexpected_dns) + len(modified_hosts) + len(no_dnssec) < 2:
            return []

        details: list[str] = []
        if unexpected_dns:
            details.append(f"{len(unexpected_dns)} unexpected DNS server(s)")
        if modified_hosts:
            details.append(f"{len(modified_hosts)} suspicious hosts entry/entries")
        if no_dnssec:
            details.append("DNSSEC validation disabled")

        source_findings = unexpected_dns + modified_hosts + no_dnssec

        return [
            self._make_finding(
                finding_id="001",
                title="DNS Hijacking Indicators Detected",
                description=(
                    f"Found evidence consistent with DNS manipulation: "
                    f"{'; '.join(details)}. "
                    "This pattern suggests DNS traffic may be intercepted or redirected."
                ),
                rationale=(
                    "DNS hijacking enables attackers to redirect traffic to malicious "
                    "servers, capture credentials through fake login pages, and "
                    "intercept email. Unexpected DNS servers may be rogue resolvers, "
                    "modified hosts entries can override legitimate DNS responses, "
                    "and disabled DNSSEC removes the cryptographic verification that "
                    "ensures DNS responses are authentic. When combined, these indicators "
                    "strongly suggest DNS manipulation."
                ),
                remediation=(
                    "1. Check /etc/resolv.conf and systemd-resolved config\n"
                    "2. Enable DNSSEC: 'resolvectl dnssec yes'\n"
                    "3. Fix /etc/hosts entries: remove unauthorized mappings\n"
                    "4. Review DNS server configuration: only use trusted resolvers\n"
                    "5. Check for DNS changes in auth.log: 'grep -i dns /var/log/auth.log'"
                ),
                source_findings=source_findings,
                severity=Severity.HIGH,
                tags=["dns", "hijacking", "redirection", "tampering"],
                mitre_attack_ids=["T1553", "T1553.001", "T1553.002"],
                cis_benchmarks=["CIS Ubuntu 22.04: 4.3", "CIS Ubuntu 22.04: 4.4", "CIS Ubuntu 22.04: 4.5"],
            )
        ]


class RogueServiceDeployment(CorrelationRule):
    """Detects rogue service deployment on the system.

    Combines unknown binary services (SVC-202), unexpected enabled
    services (SVC-102), and unexpected listening ports (SVC-302)
    to identify potential backdoor or rogue service installation.
    """

    id = "ROGUE-SVC"
    name = "Rogue Service Deployment Detection"
    description = "Detects indicators of unauthorized service deployment"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        unknown_binary_svcs = [f for f in findings if f.check_id == "SVC-202"]
        unexpected_enabled = [f for f in findings if f.check_id == "SVC-102"]
        unexpected_listening = [f for f in findings if f.check_id == "SVC-302"]

        if not unknown_binary_svcs and not unexpected_enabled:
            return []

        details: list[str] = []
        if unknown_binary_svcs:
            details.append(f"{len(unknown_binary_svcs)} service(s) from unknown binaries")
        if unexpected_enabled:
            details.append(f"{len(unexpected_enabled)} unexpected enabled service(s)")
        if unexpected_listening:
            details.append(f"{len(unexpected_listening)} unexpected listening service(s)")

        source_findings: list[Finding] = []
        source_findings.extend(unknown_binary_svcs)
        source_findings.extend(unexpected_enabled)
        source_findings.extend(unexpected_listening[:2])

        return [
            self._make_finding(
                finding_id="001",
                title="Rogue Service Deployment Indicators Detected",
                description=(
                    f"Found evidence consistent with rogue service deployment: "
                    f"{'; '.join(details)}. "
                    "This pattern indicates an unauthorized service may have been "
                    "installed on the system."
                ),
                rationale=(
                    "Attackers commonly deploy backdoor services to maintain persistent "
                    "access. A service from an unknown binary that is enabled and listening "
                    "on a network port is a strong indicator of compromise. Legitimate "
                    "services are installed via package manager, have known binaries, "
                    "and are documented in the system baseline."
                ),
                remediation=(
                    "1. Investigate each unknown service: 'systemctl cat <service>'\n"
                    "2. Check binary origin: 'dpkg -S <binary>'\n"
                    "3. Disable unauthorized services: 'systemctl disable --now <service>'\n"
                    "4. Remove unknown binaries: 'rm <binary>' after investigation\n"
                    "5. Audit for other persistence mechanisms: cron, ssh keys, timers"
                ),
                source_findings=source_findings,
                severity=Severity.CRITICAL,
                tags=["rogue-service", "backdoor", "persistence", "compromise"],
                mitre_attack_ids=["T1543", "T1543.002", "T1505", "T1505.001"],
            )
        ]


class FileIntegrityBreach(CorrelationRule):
    """Detects file integrity breach indicators.

    Combines orphaned files (FS-403), unexpected symlinks (FS-301),
    modified systemd units (SVC-402), and deleted running binaries
    (FS-202) to identify potential file integrity compromise.
    """

    id = "FILE-INTEGRITY"
    name = "File Integrity Breach Detection"
    description = "Detects indicators of filesystem integrity compromise"
    severity = Severity.HIGH

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        orphaned = [f for f in findings if f.check_id == "FS-403"]
        symlinks = [f for f in findings if f.check_id == "FS-301"]
        modified_units = [f for f in findings if f.check_id == "SVC-402"]
        deleted_bins = [f for f in findings if f.check_id == "FS-202"]
        unexpected_etc = [f for f in findings if f.check_id == "FS-101"]

        combined_count = len(orphaned) + len(symlinks) + len(modified_units) + len(deleted_bins) + len(unexpected_etc)
        if combined_count < 2:
            return []

        details: list[str] = []
        if orphaned:
            details.append(f"{len(orphaned)} orphaned file(s)")
        if symlinks:
            details.append(f"{len(symlinks)} unexpected symlink(s)")
        if modified_units:
            details.append(f"{len(modified_units)} modified systemd unit(s)")
        if deleted_bins:
            details.append(f"{len(deleted_bins)} deleted running binary(/ies)")
        if unexpected_etc:
            details.append(f"{len(unexpected_etc)} unexpected file(s) in /etc")

        source_findings: list[Finding] = []
        source_findings.extend(orphaned[:3])
        source_findings.extend(symlinks[:3])
        source_findings.extend(modified_units[:3])
        source_findings.extend(deleted_bins[:3])
        source_findings.extend(unexpected_etc[:3])

        return [
            self._make_finding(
                finding_id="001",
                title="File Integrity Breach Indicators Detected",
                description=(
                    f"Found evidence of filesystem integrity compromise: "
                    f"{'; '.join(details)}. "
                    "This pattern indicates the filesystem may have been tampered with."
                ),
                rationale=(
                    "File integrity breaches are a serious security indicator. Orphaned files "
                    "not owned by any package may be malware droppings. Unexpected symlinks "
                    "can redirect execution to malicious code. Modified systemd units suggest "
                    "persistence installation. Deleted running binaries are a classic "
                    "malware cleanup technique. When multiple indicators are present, the "
                    "likelihood of active compromise is significantly elevated."
                ),
                remediation=(
                    "1. Investigate all orphaned files: identify source and purpose\n"
                    "2. Review unexpected symlinks: 'ls -la /etc/ | grep ^l'\n"
                    "3. Audit systemd unit changes: 'systemctl status <unit>'\n"
                    "4. Check for rootkits: 'apt install rkhunter && rkhunter --check'\n"
                    "5. Review auth logs for unauthorized access: 'last -10'"
                ),
                source_findings=source_findings,
                severity=Severity.HIGH,
                tags=["file-integrity", "tampering", "compromise", "persistence"],
                mitre_attack_ids=["T1070", "T1070.004", "T1565", "T1565.001", "T1505"],
            )
        ]
