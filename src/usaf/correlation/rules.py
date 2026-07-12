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
        local_port = getattr(ev, "local_port", None)
        if local_port == 22:
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

        total_indicators = len(unknown_repos) + len(broken_sigs) + len(modified_files)
        if total_indicators < 2:
            return []
        if not unknown_repos and len(broken_sigs) + len(modified_files) < 2:
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

        indicator_count = len(unknown_binary_svcs) + len(unexpected_enabled) + len(unexpected_listening)
        if indicator_count < 2:
            return []

        sev = Severity.CRITICAL if indicator_count >= 3 else Severity.HIGH

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
                severity=sev,
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

        # Require at least 2 DIFFERENT check types to avoid a single
        # noisy check (e.g. FS-403 with 4000+ findings) always firing
        categories = set()
        if orphaned:
            categories.add("FS-403")
        if symlinks:
            categories.add("FS-301")
        if modified_units:
            categories.add("SVC-402")
        if deleted_bins:
            categories.add("FS-202")
        if unexpected_etc:
            categories.add("FS-101")
        if len(categories) < 2:
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


class ContainerEscapePath(CorrelationRule):
    id = "CORR-401"
    name = "Container Escape Path"
    description = "Detects container configurations that enable escape to the host"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        docker_socket = [f for f in findings if f.check_id == "CTN-101"]
        suid_bins = [f for f in findings if f.check_id == "PRM-101"]
        root_svcs = [f for f in findings if f.check_id == "SVC-201"]

        if not docker_socket:
            return []

        indicators: list[str] = []
        source_findings: list[Finding] = list(docker_socket[:1])

        if suid_bins:
            indicators.append(f"{len(suid_bins)} SUID binary finding(s)")
            source_findings.append(suid_bins[0])
        if root_svcs:
            indicators.append(f"{len(root_svcs)} service(s) running as root")
            source_findings.append(root_svcs[0])

        if not indicators:
            return []

        sev = Severity.CRITICAL if suid_bins else Severity.HIGH

        return [
            self._make_finding(
                finding_id="001",
                title="Container Escape Path Detected",
                description=(
                    f"Docker socket is exposed with {len(indicators)} additional escape "
                    f"indicator(s): {'; '.join(indicators)}"
                ),
                rationale=(
                    "An exposed Docker socket allows containers to interact with the "
                    "host Docker daemon. Combined with SUID binaries or root services, "
                    "this creates a viable container escape path."
                ),
                remediation=(
                    "1. Restrict Docker socket access to trusted users only\n"
                    "2. Use rootless Docker or Podman\n"
                    "3. Remove unnecessary SUID binaries\n"
                    "4. Run containers with minimal privileges"
                ),
                source_findings=source_findings,
                severity=sev,
                tags=["container-escape", "docker", "privilege-escalation"],
                mitre_attack_ids=["T1611", "T1548", "T1548.001"],
            )
        ]


class CredentialCompromise(CorrelationRule):
    id = "CORR-402"
    name = "Credential Compromise"
    description = "Detects systems with multiple exposed credential types"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        cloud_creds = [f for f in findings if f.check_id in ("SECR-101", "SECR-102")]
        ssh_keys = [f for f in findings if f.check_id in ("SECR-301", "SECR-302")]
        app_creds = [f for f in findings if f.check_id in ("SECR-201", "SECR-202", "SECR-203", "SECR-401")]

        if not cloud_creds and not ssh_keys and not app_creds:
            return []

        categories_affected = sum(1 for g in [cloud_creds, ssh_keys, app_creds] if g)
        if categories_affected < 2:
            return []

        details: list[str] = []
        source_findings: list[Finding] = []
        if cloud_creds:
            details.append(f"{len(cloud_creds)} cloud credential exposure(s)")
            source_findings.append(cloud_creds[0])
        if ssh_keys:
            details.append(f"{len(ssh_keys)} SSH key issue(s)")
            source_findings.append(ssh_keys[0])
        if app_creds:
            details.append(f"{len(app_creds)} application credential exposure(s)")
            source_findings.append(app_creds[0])

        sev = Severity.CRITICAL if cloud_creds else Severity.HIGH
        return [
            self._make_finding(
                finding_id="001",
                title="Multiple Credential Types Exposed",
                description=(
                    f"System has {categories_affected} different credential categories "
                    f"exposed: {'; '.join(details)}"
                ),
                rationale=(
                    "Multiple credential types exposed on the same system indicates "
                    "poor secrets management and significantly increases breach risk."
                ),
                remediation=(
                    "1. Remove all credentials from files and use a secrets manager\n"
                    "2. Rotate all exposed credentials immediately\n"
                    "3. Audit file permissions on all credential files"
                ),
                source_findings=source_findings,
                severity=sev,
                tags=["credentials", "secrets", "compromise", "cloud"],
                mitre_attack_ids=["T1552", "T1552.001", "T1552.004", "T1525"],
            )
        ]


class ActiveBreachIndicators(CorrelationRule):
    id = "CORR-403"
    name = "Active Breach Indicators"
    description = "Detects patterns consistent with an active security breach"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        log_gaps = [f for f in findings if f.check_id in ("LOG-301", "LOG-302") and f.severity.value in ("HIGH", "CRITICAL")]
        auth_failures = [f for f in findings if f.check_id in ("LOG-401", "LOG-402")]
        new_svcs = [f for f in findings if f.check_id == "SVC-401"]
        failed_svcs = [f for f in findings if f.check_id == "SVC-301"]

        indicators: list[str] = []
        source_findings: list[Finding] = []
        total_signals = 0

        for group, label in [(log_gaps, "log gap/tamper"), (auth_failures, "auth failure"),
                             (new_svcs, "newly installed service"), (failed_svcs, "failed service")]:
            if group:
                indicators.append(f"{len(group)} {label}(s)")
                source_findings.append(group[0])
                total_signals += 1

        if total_signals < 2:
            return []

        return [
            self._make_finding(
                finding_id="001",
                title="Active Breach Indicators Detected",
                description=(
                    f"Found {total_signals} breach indicator(s): {'; '.join(indicators)}. "
                    "This pattern is consistent with an active or recent security breach."
                ),
                rationale=(
                    "Log gaps with authentication failures, new services, or failed services "
                    "form a pattern consistent with an active breach."
                ),
                remediation=(
                    "1. IMMEDIATE: Isolate the affected system from the network\n"
                    "2. Collect forensic memory and disk images\n"
                    "3. Investigate all new services and recent logins\n"
                    "4. Check for unauthorized user accounts and SSH keys\n"
                    "5. Rotate all credentials used from this system"
                ),
                source_findings=source_findings,
                severity=Severity.CRITICAL,
                tags=["active-breach", "compromise", "incident-response", "forensics"],
                mitre_attack_ids=["T1070", "T1110", "T1505", "T1543", "T1562"],
            )
        ]


class CloudCompromiseRule(CorrelationRule):
    id = "CORR-601"
    name = "Cloud Credential Exposure with Metadata Access"
    description = "Detects cloud credential exposure combined with accessible metadata API"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        cloud_creds = [
            f for f in findings
            if f.check_id in ("CLD-301", "CLD-101", "CLD-102")
        ]
        metadata_access = [
            f for f in findings
            if f.check_id == "CLD-101"
        ]
        net_exposure = [
            f for f in findings
            if f.check_id in ("NET-101", "NET-201")
        ]

        has_creds = any(f.check_id == "CLD-301" for f in cloud_creds)
        has_metadata = bool(metadata_access)
        has_network = bool(net_exposure)

        if not (has_creds and has_metadata):
            return []

        source_findings = cloud_creds
        if has_network:
            source_findings.extend(net_exposure[:2])

        details: list[str] = []
        cred_count = len([f for f in cloud_creds if f.check_id == "CLD-301"])
        details.append(f"{cred_count} cloud credential finding(s)")
        details.append("IMDS accessible" if has_metadata else "IMDS unknown")

        return [
            self._make_finding(
                finding_id="001",
                title="Cloud Instance Compromise — Credentials + Metadata Access",
                description=(
                    f"Cloud IAM credentials are present on the filesystem and the metadata "
                    f"service is accessible. Indicators: {'; '.join(details)}. "
                    f"Network exposure: {'yes' if has_network else 'no'}. "
                    "This combination allows an attacker with local access to exfiltrate "
                    "cloud credentials and use them from any machine."
                ),
                rationale=(
                    "When cloud IAM credentials are stored on the filesystem AND the metadata "
                    "service (IMDS) is accessible, an attacker who gains local access can: "
                    "(1) steal long-lived credentials from disk, (2) request short-lived "
                    "credentials from IMDS, and (3) use both to maintain persistent cloud access. "
                    "This is the primary attack path for cloud instance compromise."
                ),
                remediation=(
                    "1. Remove long-lived cloud credentials from the filesystem\n"
                    "2. Enforce IMDSv2 to protect metadata service access\n"
                    "3. Use IAM roles instead of access keys for EC2/GCE/Azure VMs\n"
                    "4. Rotate all exposed credentials immediately\n"
                    "5. Audit IAM policies for over-permissive roles"
                ),
                source_findings=source_findings,
                severity=Severity.CRITICAL,
                tags=["cloud", "compromise", "credentials", "imds", "instance-compromise"],
                mitre_attack_ids=["T1552.005", "T1613", "T1525"],
            )
        ]


class ComplianceGapRule(CorrelationRule):
    id = "CORR-602"
    name = "Critical Compliance Gap"
    description = "Detects systems with critical compliance gaps: multiple CIS failures, firewall disabled, auditd off"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        cis_failures = [
            f for f in findings
            if f.check_id.startswith("CMP-20") or f.check_id == "CMP-301"
        ]
        firewall_issues = [
            f for f in findings
            if f.check_id == "FW-101"
        ]
        audit_issues = [
            f for f in findings
            if f.check_id in ("FOR-101", "LOG-501")
        ]

        if not cis_failures and not firewall_issues and not audit_issues:
            return []

        source_findings: list[Finding] = []
        total_cis = len(cis_failures)
        total_fw = len(firewall_issues)
        total_audit = len(audit_issues)

        if total_cis > 0:
            source_findings.extend(cis_failures[:3])
        if total_fw > 0:
            source_findings.append(firewall_issues[0])
        if total_audit > 0:
            source_findings.append(audit_issues[0])

        threshold = 10
        if total_cis >= threshold or (total_cis >= 5 and (total_fw > 0 or total_audit > 0)):
            details: list[str] = []
            if total_cis >= threshold:
                details.append(f"{total_cis}+ CIS compliance failure(s)")
            if total_fw > 0:
                details.append("firewall is disabled")
            if total_audit > 0:
                details.append("auditd is off or has gaps")

            return [
                self._make_finding(
                    finding_id="001",
                    title="Critical Compliance Gap Detected",
                    description=(
                        f"System has critical compliance gaps: {'; '.join(details)}. "
                        "This represents a systemic security control failure requiring "
                        "immediate remediation."
                    ),
                    rationale=(
                        "When multiple compliance frameworks are failing on the same system, "
                        "especially with fundamental controls like firewall and auditd disabled, "
                        "the system is operating without basic security controls. This creates "
                        "a critical risk of undetected compromise."
                    ),
                    remediation=(
                        "1. Enable firewall: 'ufw enable' or 'systemctl enable --now nftables'\n"
                        "2. Enable auditd: 'systemctl enable --now auditd'\n"
                        "3. Address the most critical CIS/STIG failures first\n"
                        "4. Run 'usaf scan --compliance' to track remediation progress\n"
                        "5. Establish a compliance remediation plan"
                    ),
                    source_findings=source_findings,
                    severity=Severity.CRITICAL,
                    tags=["compliance", "critical-gap", "remediation", "firewall", "audit"],
                    mitre_attack_ids=["T1562.001", "T1562.006"],
                )
            ]

        return []


class PriorityRemediationRule(CorrelationRule):
    id = "CORR-603"
    name = "Priority Remediation — Multi-Framework Control Failures"
    description = "Detects compliance controls failing across multiple frameworks, indicating priority remediation targets"
    severity = Severity.HIGH

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        compliance_findings = [
            f for f in findings
            if f.check_id.startswith("CMP-")
        ]

        if len(compliance_findings) < 3:
            return []

        control_map: dict[str, list[Finding]] = {}
        for f in compliance_findings:
            for tag in f.tags:
                if "compliance" in tag and tag not in ("compliance",):
                    if tag not in control_map:
                        control_map[tag] = []
                    control_map[tag].append(f)

        for f in compliance_findings:
            for control_id in f.cis_benchmarks:
                if control_id not in control_map:
                    control_map[control_id] = []
                control_map[control_id].append(f)

        multi_framework = {
            ctrl: findings_list
            for ctrl, findings_list in control_map.items()
            if len({f.check_id for f in findings_list}) >= 2
        }

        if not multi_framework:
            return []

        top_controls = sorted(
            multi_framework.items(),
            key=lambda x: len(x[1]),
            reverse=True,
        )[:3]

        source_findings: list[Finding] = []
        details: list[str] = []
        for ctrl, findings_list in top_controls:
            frameworks = {f.check_id for f in findings_list}
            details.append(
                f"'{ctrl}' failing in {len(frameworks)} framework(s)"
            )
            source_findings.extend(findings_list[:2])

        return [
            self._make_finding(
                finding_id="001",
                title="Priority Remediation — Multi-Framework Control Failures",
                description=(
                    f"Found {len(multi_framework)} control(s) failing across multiple "
                    f"compliance frameworks: {'; '.join(details)}. "
                    "These controls should be prioritized for remediation to improve "
                    "compliance posture across all frameworks simultaneously."
                ),
                rationale=(
                    "When the same security control fails across multiple compliance "
                    "frameworks (e.g., CIS, PCI DSS, HIPAA), it represents a fundamental "
                    "security gap that affects all compliance postures. Fixing these "
                    "shared controls provides the highest return on remediation effort."
                ),
                remediation=(
                    "1. Review the multi-framework failing controls listed above\n"
                    "2. Apply remediation steps for each affected control\n"
                    "3. Run 'usaf scan --compliance' to verify fix\n"
                    "4. Update security policies to prevent regression"
                ),
                source_findings=source_findings,
                severity=Severity.HIGH,
                tags=["compliance", "remediation", "priority", "multi-framework"],
                mitre_attack_ids=["T1562"],
            )
        ]


class ExposedAttackSurface(CorrelationRule):
    id = "CORR-404"
    name = "Exposed Attack Surface"
    description = "Detects systems with broad exposed attack surface and weak defenses"
    severity = Severity.HIGH

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        listening_ports = [f for f in findings if f.check_id == "NET-101"]
        weak_tls = [f for f in findings if f.check_id in ("SECR-501", "SECR-502")]
        no_audit = [f for f in findings if f.check_id in ("FOR-101", "LOG-501")]
        firewall_down = [f for f in findings if f.check_id == "FW-101"]

        indicators: list[str] = []
        source_findings: list[Finding] = []
        total_signals = 0

        for group, label in [(listening_ports, "listening service"), (weak_tls, "TLS certificate issue"),
                             (no_audit, "audit/logging gap"), (firewall_down, "firewall down")]:
            if group:
                indicators.append(f"{len(group)} {label}(s)" if group != firewall_down or len(group) != 1 else "Firewall is not active")
                source_findings.append(group[0])
                total_signals += 1

        if total_signals < 2:
            return []

        return [
            self._make_finding(
                finding_id="001",
                title="Exposed Attack Surface Detected",
                description=(
                    f"System has {total_signals} attack surface indicators: "
                    f"{'; '.join(indicators)}"
                ),
                rationale=(
                    "Systems with many listening services, weak TLS certificates, "
                    "missing audit coverage, and no firewall present a large attack surface."
                ),
                remediation=(
                    "1. Audit all listening services and disable unnecessary ones\n"
                    "2. Replace self-signed/expired certificates with valid CA certs\n"
                    "3. Enable auditd with comprehensive rules\n"
                    "4. Enable and configure the firewall (UFW or nftables)"
                ),
                source_findings=source_findings,
                severity=Severity.HIGH,
                tags=["attack-surface", "exposure", "hardening", "defense-in-depth"],
                mitre_attack_ids=["T1040", "T1046", "T1588.003", "T1562"],
            )
        ]


class SudoPrivilegeAbusePath(CorrelationRule):
    """Detects sudo configurations that enable unconstrained privilege escalation.

    Combines findings about weak sudo configuration — no password required,
    infinite timestamp timeout, missing logging — into a single high-severity
    correlation that indicates a clear privilege escalation path.
    """

    id = "CORR-405"
    name = "Sudo Privilege Escalation Path"
    description = "Detects sudo configurations that enable unconstrained privilege escalation"
    severity = Severity.CRITICAL

    def evaluate(self, findings: list[Finding]) -> list[CorrelatedFinding]:
        no_password = [f for f in findings if f.check_id == "USR-402"]
        no_timeout = [f for f in findings if f.check_id == "USR-403"]
        no_logging = [f for f in findings if f.check_id == "USR-404"]
        broad_sudo = [f for f in findings if f.check_id == "USR-401"]

        signals: list[str] = []
        source_findings: list[Finding] = []
        total = 0

        if no_password:
            signals.append("sudo password authentication disabled globally")
            source_findings.append(no_password[0])
            total += 2

        if no_timeout and any("never" in (f.title or "") for f in no_timeout):
            signals.append("sudo timestamp never expires")
            source_findings.append(no_timeout[0])
            total += 1
        elif no_timeout:
            signals.append("sudo timestamp timeout excessive")
            source_findings.append(no_timeout[0])
            total += 1

        if no_logging:
            signals.append("sudo command logging not configured")
            source_findings.append(no_logging[0])
            total += 2

        if broad_sudo:
            has_all = any("ALL" in (f.detected_value or "") for f in broad_sudo)
            if has_all:
                signals.append("users have unrestricted ALL sudo access")
                source_findings.append(broad_sudo[0])
                total += 1

        if total < 2:
            return []

        return [
            self._make_finding(
                finding_id="001",
                title="Sudo Privilege Escalation Path Detected",
                description=(
                    f"Sudo is misconfigured in {len(signals)} way(s): "
                    f"{'; '.join(signals)}. An attacker who compromises any sudo "
                    "user gains unrestricted root access with no audit trail."
                ),
                rationale=(
                    "Sudo is the primary mechanism for privilege escalation on Linux. "
                    "When password authentication is disabled, timestamp never expires, "
                    "logging is off, and users have broad ALL access, any compromised "
                    "sudo user immediately yields full root access with no forensic trail. "
                    "This combination of misconfigurations represents a critical security gap."
                ),
                remediation=(
                    "1. Require sudo password: remove '!authenticate' from sudoers\n"
                    "2. Set reasonable timestamp_timeout (5-15 minutes)\n"
                    "3. Enable sudo logging: 'Defaults log_input, log_output'\n"
                    "4. Restrict sudo commands: replace ALL with specific needed commands\n"
                    "Use 'visudo' to edit /etc/sudoers."
                ),
                source_findings=source_findings,
                severity=Severity.CRITICAL,
                tags=["sudo", "privilege-escalation", "defense-in-depth", "critical"],
                mitre_attack_ids=["T1548.003"],
            )
        ]
