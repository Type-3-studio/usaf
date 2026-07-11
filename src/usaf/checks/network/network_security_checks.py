from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import NetworkEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

KNOWN_DNS_SERVERS = {
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "8.8.8.8": "Google",
    "8.8.4.4": "Google",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "127.0.0.53": "systemd-resolved (stub)",
    "127.0.0.1": "Local resolver",
    "::1": "Local resolver",
}

EXPECTED_RESOLV_TARGETS = {
    "/run/systemd/resolve/stub-resolv.conf",
    "/run/systemd/resolve/resolv.conf",
    "/lib/systemd/resolv.conf",
    "/usr/lib/systemd/resolv.conf",
}

WEAK_NET_SYSCTL = {
    "net.ipv4.conf.all.accept_source_route": {
        "expected": "0",
        "description": "Source route packet acceptance",
    },
    "net.ipv4.conf.default.accept_source_route": {
        "expected": "0",
        "description": "Default source route packet acceptance",
    },
    "net.ipv4.conf.all.accept_redirects": {
        "expected": "0",
        "description": "ICMP redirect acceptance",
    },
    "net.ipv4.conf.default.accept_redirects": {
        "expected": "0",
        "description": "Default ICMP redirect acceptance",
    },
    "net.ipv4.conf.all.secure_redirects": {
        "expected": "0",
        "description": "Secure ICMP redirect acceptance",
    },
    "net.ipv4.conf.default.secure_redirects": {
        "expected": "0",
        "description": "Default secure ICMP redirect acceptance",
    },
    "net.ipv4.ip_forward": {
        "expected": "0",
        "description": "IP forwarding",
    },
    "net.ipv4.tcp_syncookies": {
        "expected": "1",
        "description": "TCP SYN cookies",
    },
    "net.ipv4.conf.all.rp_filter": {
        "expected": "1",
        "description": "Reverse path filtering (all)",
    },
    "net.ipv4.conf.default.rp_filter": {
        "expected": "1",
        "description": "Reverse path filtering (default)",
    },
    "net.ipv4.conf.all.log_martians": {
        "expected": "1",
        "description": "Martian packet logging (all)",
    },
    "net.ipv4.conf.default.log_martians": {
        "expected": "1",
        "description": "Martian packet logging (default)",
    },
    "net.ipv4.icmp_echo_ignore_broadcasts": {
        "expected": "1",
        "description": "ICMP broadcast echo ignore",
    },
    "net.ipv4.icmp_ignore_bogus_error_responses": {
        "expected": "1",
        "description": "Bogus ICMP error response ignore",
    },
    "net.ipv4.tcp_rfc1337": {
        "expected": "1",
        "description": "TCP TIME-WAIT assassination protection",
    },
}

IPV6_SYSCTL = {
    "net.ipv6.conf.all.accept_ra": {
        "expected": "0",
        "description": "IPv6 router advertisement acceptance",
    },
    "net.ipv6.conf.all.accept_redirects": {
        "expected": "0",
        "description": "IPv6 ICMP redirect acceptance",
    },
    "net.ipv6.conf.all.disable_ipv6": {
        "expected": "1",
        "description": "IPv6 disabled",
    },
}


@register_check
class UnexpectedDNSServersCheck(AuditCheck):
    """Check for unexpected DNS server configurations."""

    id = "NET-301"
    name = "Unexpected DNS Servers"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks that DNS servers in resolv.conf are expected"
    depends = ["dns"]
    tags = ["network", "dns", "security"]

    def _run_check(self, collectors: dict) -> list:
        dns_data = self._get_data(collectors, "dns")
        findings = []

        resolv_conf = dns_data.get("resolv_conf", {})
        symlink_target = resolv_conf.get("symlink_target")
        nameservers = resolv_conf.get("nameservers", [])

        resolved_target = str(Path("/etc/resolv.conf").resolve()) if symlink_target else ""
        if resolved_target and resolved_target not in EXPECTED_RESOLV_TARGETS:
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected /etc/resolv.conf symlink target: {symlink_target}",
                    description=(
                        f"/etc/resolv.conf points to '{symlink_target}' which is not a "
                        "standard resolver configuration target."
                    ),
                    rationale=(
                        "Unexpected resolv.conf targets may indicate DNS hijacking or "
                        "a misconfigured resolver. Attackers who control DNS can redirect "
                        "traffic to malicious servers, enabling phishing, credential theft, "
                        "and traffic interception."
                    ),
                    remediation=(
                        "Restore the expected resolver configuration: "
                        "'ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf'. "
                        "Investigate why the symlink was changed."
                    ),
                    evidence=RegistryEvidence(
                        key="/etc/resolv.conf symlink",
                        value=symlink_target,
                        expected=" /run/systemd/resolve/stub-resolv.conf",
                        source="/etc/resolv.conf",
                    ),
                    detected_value=f"Symlink target: {symlink_target}",
                    expected_value="Standard resolv.conf target",
                    affected_component="/etc/resolv.conf",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1553", "T1562"],
                    tags=["dns", "tampering"],
                )
            )

        for ns in nameservers:
            if ns not in KNOWN_DNS_SERVERS:
                findings.append(
                    self.finding(
                        finding_id="002",
                        title=f"Unexpected DNS server: {ns}",
                        description=(
                            f"DNS server {ns} is configured in /etc/resolv.conf "
                            "but is not a known public or local resolver."
                        ),
                        rationale=(
                            "Unknown DNS servers may be malicious resolvers that log "
                            "or manipulate DNS queries. Attackers use rogue DNS servers "
                            "for phishing, DNS poisoning, and traffic redirection. "
                            "Verify that all configured DNS servers are authorized."
                        ),
                        remediation=(
                            f"Verify the DNS server {ns} is authorized. If not, "
                            "update /etc/resolv.conf or systemd-resolved configuration. "
                            "Ensure DNSSEC validation is enabled."
                        ),
                        evidence=NetworkEvidence(
                            protocol="DNS",
                            local_address=ns,
                            local_port=53,
                        ),
                        detected_value=f"DNS server: {ns}",
                        expected_value="Known/authorized DNS server",
                        affected_component=f"DNS: {ns}",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.4,
                        mitre_attack_ids=["T1553", "T1552"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 4.4"],
                        tags=["dns", "resolution"],
                    )
                )

        return findings


@register_check
class ModifiedHostsFileCheck(AuditCheck):
    """Check for unexpected or modified entries in /etc/hosts."""

    id = "NET-302"
    name = "Modified /etc/hosts File"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks /etc/hosts for suspicious or unauthorized entries"
    depends = ["dns"]
    tags = ["network", "dns", "hosts"]

    KNOWN_HOSTS = {"127.0.0.1", "127.0.1.1", "::1", "127.0.0.53"}
    KNOWN_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters"}

    def _run_check(self, collectors: dict) -> list:
        dns_data = self._get_data(collectors, "dns")
        findings = []

        hosts = dns_data.get("hosts", {})
        entries = hosts.get("entries", [])

        for entry in entries:
            parts = entry.split()
            if len(parts) < 2:
                continue
            ip = parts[0]

            if ip in self.KNOWN_HOSTS:
                continue

            hostnames = parts[1:]
            for hostname in hostnames:
                if hostname.endswith(".local"):
                    continue
                if hostname in self.KNOWN_HOSTNAMES:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Unexpected hosts entry: {ip} -> {hostname}",
                        description=(
                            f"/etc/hosts maps {ip} to '{hostname}'. "
                            "This entry is not a standard localhost mapping."
                        ),
                        rationale=(
                            "Unauthorized /etc/hosts entries can redirect traffic to "
                            "malicious servers, bypass DNS for phishing, or map common "
                            "typosquatted domains to attacker-controlled IPs. Attackers "
                            "use hosts file manipulation for persistence and traffic redirection."
                        ),
                        remediation=(
                            f"Verify the {ip} -> {hostname} mapping is authorized. "
                            "If not, remove the line from /etc/hosts. "
                            "Check that the file is not world-writable: 'ls -la /etc/hosts'."
                        ),
                        evidence=RegistryEvidence(
                            key="/etc/hosts",
                            value=f"{ip} {hostname}",
                            expected="Only standard localhost entries",
                            source="/etc/hosts",
                        ),
                        detected_value=f"Non-standard hosts entry: {ip} {hostname}",
                        expected_value="Only standard entries in /etc/hosts",
                        affected_component=f"hosts: {ip} -> {hostname}",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.4,
                        mitre_attack_ids=["T1553", "T1562"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 4.3"],
                        tags=["hosts", "dns", "tampering"],
                    )
                )

        return findings


@register_check
class WeakSysctlNetworkCheck(AuditCheck):
    """Check for weak network-related kernel parameters."""

    id = "NET-401"
    name = "Weak Network Kernel Parameters"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks for network kernel parameters that weaken security"
    depends = ["kernel_params"]
    tags = ["network", "kernel", "hardening"]

    def _run_check(self, collectors: dict) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings = []

        for key, config in WEAK_NET_SYSCTL.items():
            actual = params.get(key, "")
            expected = config["expected"]
            description = config["description"]

            if actual != expected:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Weak network sysctl: {key} = {actual}",
                        description=(
                            f"Kernel parameter {key} is set to '{actual}' "
                            f"(expected '{expected}'). Controls: {description}."
                        ),
                        rationale=(
                            f"Weak {description} settings can enable network-based attacks. "
                            f"Setting {key} to '{expected}' is recommended by CIS benchmarks "
                            "and security best practices to prevent common network attacks."
                        ),
                        remediation=(
                            f"Set {key}={expected}: "
                            f"'sysctl -w {key}={expected}'. "
                            f"Make permanent in /etc/sysctl.d/ or /etc/sysctl.conf."
                        ),
                        evidence=RegistryEvidence(
                            key=f"/proc/sys/{key.replace('.', '/')}",
                            value=str(actual),
                            expected=expected,
                            source="/proc/sys",
                        ),
                        detected_value=f"{key}={actual}",
                        expected_value=f"{key}={expected}",
                        affected_component=f"sysctl: {key}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1562", "T1046"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 4.1"],
                        tags=["network", "kernel", "sysctl", "hardening"],
                    )
                )

        return findings


@register_check
class IPv6HardeningCheck(AuditCheck):
    """Check IPv6 kernel hardening configuration."""

    id = "NET-402"
    name = "IPv6 Hardening"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks for IPv6 kernel hardening parameters"
    depends = ["kernel_params"]
    tags = ["network", "ipv6", "hardening"]

    def _run_check(self, collectors: dict) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings = []

        for key, config in IPV6_SYSCTL.items():
            actual = params.get(key, "")
            expected = config["expected"]
            description = config["description"]

            if actual != expected:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"IPv6 not hardened: {key} = {actual}",
                        description=(
                            f"IPv6 kernel parameter {key} is set to '{actual}' "
                            f"(expected '{expected}'). Controls: {description}."
                        ),
                        rationale=(
                            "IPv6 stacking is enabled on Linux by default even if "
                            "no IPv6 addresses are configured. Attackers can use IPv6 "
                            "to bypass IPv4 firewall rules, perform neighbor discovery "
                            "spoofing, or exfiltrate data over IPv6 tunnels. Proper "
                            "IPv6 hardening or disabling reduces the attack surface."
                        ),
                        remediation=(
                            f"Set {key}={expected}: "
                            f"'sysctl -w {key}={expected}'. "
                            f"Make permanent: add '{key}={expected}' to /etc/sysctl.d/."
                        ),
                        evidence=RegistryEvidence(
                            key=f"/proc/sys/{key.replace('.', '/')}",
                            value=str(actual),
                            expected=expected,
                            source="/proc/sys",
                        ),
                        detected_value=f"{key}={actual}",
                        expected_value=f"{key}={expected}",
                        affected_component=f"sysctl: {key}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1562", "T1046"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 4.2"],
                        tags=["ipv6", "kernel", "sysctl", "hardening"],
                    )
                )

        return findings


@register_check
class DNSSECValidationCheck(AuditCheck):
    """Check if DNSSEC validation is enabled."""

    id = "NET-501"
    name = "DNSSEC Validation"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks if DNSSEC validation is enabled for DNS resolution"
    depends = ["dns"]
    tags = ["network", "dns", "dnssec"]

    def _run_check(self, collectors: dict) -> list:
        dns_data = self._get_data(collectors, "dns")
        findings = []

        dnssec = dns_data.get("dnssec", {})
        dnssec_status = dnssec.get("dnssec", "")
        dnssec_supported = dnssec.get("supported", False)

        if not dnssec_supported:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="DNSSEC status unavailable",
                    description=(
                        "Could not determine DNSSEC validation status. "
                        "systemd-resolved may not be running or resolvectl is unavailable."
                    ),
                    rationale=(
                        "Without DNSSEC validation, DNS responses can be forged. "
                        "Attackers can perform DNS cache poisoning, man-in-the-middle "
                        "attacks, and redirect traffic to malicious hosts. DNSSEC "
                        "verifies that DNS responses are authentic and unmodified."
                    ),
                    remediation=(
                        "Enable systemd-resolved: 'systemctl enable --now systemd-resolved'. "
                        "Enable DNSSEC: 'resolvectl dnssec yes'."
                    ),
                    evidence=RegistryEvidence(
                        key="systemd-resolved DNSSEC",
                        value="Unavailable",
                        expected="DNSSEC validation enabled",
                        source="resolvectl dnssec",
                    ),
                    detected_value="DNSSEC status unavailable",
                    expected_value="DNSSEC validation enabled",
                    affected_component="DNS resolution",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1553"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 4.5"],
                    tags=["dns", "dnssec", "validation"],
                )
            )
        elif "no" in dnssec_status.lower() or "off" in dnssec_status.lower():
            findings.append(
                self.finding(
                    finding_id="002",
                    title="DNSSEC validation is disabled",
                    description=(
                        f"DNSSEC validation is currently: {dnssec_status}. "
                        "DNS responses are not cryptographically verified."
                    ),
                    rationale=(
                        "DNSSEC disabled means DNS responses are accepted without "
                        "cryptographic verification. An attacker who can intercept "
                        "DNS queries (e.g., on a compromised network, via ARP spoofing, "
                        "or through a rogue DNS server) can return forged DNS responses "
                        "that will be accepted by the resolver."
                    ),
                    remediation=(
                        "Enable DNSSEC: 'resolvectl dnssec yes'. "
                        "Make permanent in /etc/systemd/resolved.conf: "
                        "DNSSEC=yes."
                    ),
                    evidence=RegistryEvidence(
                        key="systemd-resolved DNSSEC",
                        value=dnssec_status,
                        expected="yes",
                        source="resolvectl dnssec",
                    ),
                    detected_value=f"DNSSEC: {dnssec_status}",
                    expected_value="DNSSEC: yes",
                    affected_component="DNS resolution",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1553"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 4.5"],
                    tags=["dns", "dnssec", "validation"],
                    )
            )

        return findings
