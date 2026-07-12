from __future__ import annotations

import os
import stat
from collections import Counter
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import NetworkEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

PRIVILEGED_PORTS_MAX = 1023
EPHEMERAL_PORT_START = 32768
EPHEMERAL_PORT_END = 60999


@register_check
class ListeningAllInterfacesCheck(AuditCheck):
    id = "NET-701"
    name = "Services Listening on All Interfaces"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects services listening on 0.0.0.0 or :: (all interfaces)"
    depends = ["sockets"]
    tags = ["network", "ports", "exposure", "hardening"]
    max_findings = 50

    ALLOWED_ALL_INTERFACES: set[int] = {22, 80, 443}

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")
        seen: set[tuple[str, int]] = set()

        for proto in ("tcp", "tcp6", "udp", "udp6"):
            for entry in sock_data.get(proto, []):
                local = entry.get("local_address", "")
                port = int(entry.get("local_port", 0))
                state = entry.get("state", "")

                if local not in ("0.0.0.0", "::", "00000000:00000000"):
                    continue
                if port < 1:
                    continue
                if (proto, port) in seen:
                    continue
                seen.add((proto, port))

                if port in self.ALLOWED_ALL_INTERFACES:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Service on port {port} listens on all interfaces",
                        description=f"Port {port}/{proto} is bound to 0.0.0.0/::, accessible from any network.",
                        rationale="Services bound to all interfaces are reachable from any network. They should be restricted to specific IPs or localhost unless explicitly required.",
                        remediation=f"Bind service on port {port} to specific IP or 127.0.0.1. Check service config for 'bind' or 'listen' directives.",
                        evidence=NetworkEvidence(protocol=proto, local_address=local, local_port=port, state=state),
                        detected_value=f"Port {port} on 0.0.0.0",
                        expected_value="Bound to specific interface or localhost",
                        affected_component=f"port:{port}/{proto}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1046"],
                        tags=["network", "ports", "exposure", "hardening"],
                    )
                )
        return findings


@register_check
class UnixSocketPermissionsCheck(AuditCheck):
    id = "NET-702"
    name = "World-Writable UNIX Sockets"
    category = CheckCategory.NETWORK
    severity = Severity.HIGH
    description = "Detects world-writable UNIX sockets that allow any process to communicate"
    depends = ["sockets"]
    tags = ["network", "unix", "sockets", "permissions"]
    max_findings = 50

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")

        for entry in sock_data.get("unix", []):
            path = str(entry.get("local_address", "") or "")
            if not path.startswith("/"):
                continue
            try:
                st = os.stat(path)
                if not (st.st_mode & stat.S_IWOTH):
                    continue
            except OSError:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"World-writable UNIX socket: {path}",
                    description=f"UNIX socket '{path}' is world-writable. Any process can send data to it.",
                    rationale="World-writable UNIX sockets allow any process on the system to communicate with the listening service. This can enable privilege escalation and data injection.",
                    remediation=f"Restrict permissions: 'chmod 755 {path}' or set socket permissions in the application config.",
                    evidence=RegistryEvidence(key=f"socket.{path}.world_writable", value="true", expected="false", source=path),
                    detected_value=f"World-writable: {path}",
                    expected_value="Restricted UNIX socket permissions",
                    affected_component=path,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1055"],
                    tags=["network", "unix", "sockets", "permissions"],
                )
            )
        return findings


@register_check
class LocalhostOnlyServicesCheck(AuditCheck):
    id = "NET-703"
    name = "Loopback-Only Services"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Detects services that are only listening on localhost but should be available on the network"
    depends = ["sockets"]
    tags = ["network", "ports", "loopback"]
    max_findings = 50

    KNOWN_LOOPBACK_PORTS: set[int] = {631, 9050, 6379, 27017, 5432, 3306}

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")

        for proto in ("tcp", "tcp6"):
            for entry in sock_data.get(proto, []):
                local = entry.get("local_address", "")
                port = int(entry.get("local_port", 0))
                state = entry.get("state", "")
                if state != "LISTEN" if proto.startswith("tcp") else True:
                    pass
                if port in self.KNOWN_LOOPBACK_PORTS and local in ("127.0.0.1", "::1", "0100007F:00000000"):
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Loopback-only service on port {port}",
                            description=f"Port {port} is only listening on localhost. If remote access is needed, it's misconfigured.",
                            rationale="Services restricted to localhost may be intentionally locked down. Verify this is intentional, as some services (e.g., CUPS, Redis) default to localhost but may need network access.",
                            remediation="If remote access is needed, bind to 0.0.0.0 with firewall restrictions. If intentional, no action needed.",
                            evidence=NetworkEvidence(protocol=proto, local_address=local, local_port=port, state=state),
                            detected_value=f"Port {port} only on localhost",
                            expected_value="N/A (informational)",
                            affected_component=f"port:{port}",
                            confidence=Confidence.LOW,
                            false_positive_probability=0.6,
                            mitre_attack_ids=["T1046"],
                            tags=["network", "ports", "loopback"],
                        )
                    )
        return findings


@register_check
class ExposedUdpServicesCheck(AuditCheck):
    id = "NET-704"
    name = "Exposed UDP Services"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects UDP services listening on all interfaces"
    depends = ["sockets"]
    tags = ["network", "udp", "exposure"]
    max_findings = 50

    UDP_KNOWN_PORTS: dict[int, str] = {
        53: "DNS",
        67: "DHCP", 68: "DHCP",
        123: "NTP", 161: "SNMP", 162: "SNMP-trap",
        514: "syslog", 520: "RIP",
        1900: "UPnP", 5353: "mDNS",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")

        for proto in ("udp", "udp6"):
            for entry in sock_data.get(proto, []):
                local = entry.get("local_address", "")
                port = int(entry.get("local_port", 0))

                if port < 1:
                    continue
                if local not in ("0.0.0.0", "::", "00000000:00000000"):
                    continue

                service = self.UDP_KNOWN_PORTS.get(port, f"unknown port {port}")

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"UDP service exposed: {service}",
                        description=f"UDP port {port} ({service}) is listening on all interfaces. UDP is connectionless and harder to firewall.",
                        rationale="UDP services on all interfaces are easily discoverable via port scanning. Many UDP protocols are amplification vectors for DDoS attacks (NTP, DNS, SNMP).",
                        remediation=f"Bind {service} to specific interface or use firewall to restrict access. Consider disabling if not needed: 'systemctl stop <service>'.",
                        evidence=NetworkEvidence(protocol="UDP", local_address=local, local_port=port),
                        detected_value=f"UDP port {port} exposed",
                        expected_value="Not exposed or firewalled",
                        affected_component=f"udp:{port}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1046"],
                        tags=["network", "udp", "exposure"],
                    )
                )
        return findings


@register_check
class NonRootPrivilegedPortsCheck(AuditCheck):
    id = "NET-705"
    name = "Non-Root Privileged Ports"
    category = CheckCategory.NETWORK
    severity = Severity.HIGH
    description = "Detects services on privileged ports (<1024) not running as root"
    depends = ["sockets"]
    tags = ["network", "ports", "permissions", "hardening"]
    max_findings = 50

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")

        for proto in ("tcp", "tcp6", "udp", "udp6"):
            for entry in sock_data.get(proto, []):
                local = entry.get("local_address", "")
                port = int(entry.get("local_port", 0))
                uid = entry.get("uid")
                state = entry.get("state", "")

                if port < 1 or port > PRIVILEGED_PORTS_MAX:
                    continue
                if uid is not None and uid == 0:
                    continue
                if uid is None:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Non-root process on privileged port {port}",
                        description=f"Port {port} (<1024) is bound by uid {uid}, not root. Privileged ports require root by default.",
                        rationale="Privileged ports (<1024) should only be bound by root processes. Non-root ownership may indicate misconfiguration, capability grants (CAP_NET_BIND_SERVICE), or unauthorized services.",
                        remediation=f"Verify the service on port {port}. Ensure it's authorized to use CAP_NET_BIND_SERVICE or run as root with proper privileges.",
                        evidence=NetworkEvidence(protocol=proto, local_address=local, local_port=port, uid=uid, state=state),
                        detected_value=f"Port {port} owned by uid {uid}",
                        expected_value="Port owned by root (uid 0)",
                        affected_component=f"port:{port}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1046"],
                        tags=["network", "ports", "permissions", "hardening"],
                    )
                )
        return findings


@register_check
class TcpTimeWaitServicesCheck(AuditCheck):
    id = "NET-706"
    name = "Services in TIME_WAIT"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Detects TCP connections stuck in TIME_WAIT or CLOSE_WAIT states"
    depends = ["sockets"]
    tags = ["network", "tcp", "connections", "monitoring"]
    max_findings = 50

    ABNORMAL_STATES: set[str] = {"TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2", "LAST_ACK"}

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")

        state_counts: Counter = Counter()
        state_ports: dict[str, set[int]] = {}

        for proto in ("tcp", "tcp6"):
            for entry in sock_data.get(proto, []):
                state = entry.get("state", "")
                port = int(entry.get("local_port", 0))
                if state in self.ABNORMAL_STATES:
                    state_counts[state] += 1
                    if state not in state_ports:
                        state_ports[state] = set()
                    state_ports[state].add(port)

        for state, count in state_counts.items():
            if count < 50:
                continue
            ports = sorted(state_ports.get(state, set()))[:10]
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"High {state} connections: {count}",
                    description=f"There are {count} connections in {state} state on ports {ports}. This may indicate connection leaks or network issues.",
                    rationale=f"Excessive {state} connections can exhaust the ephemeral port range and prevent new outbound connections. CLOSE_WAIT storms often indicate application bugs.",
                    remediation=f"Check for connection leaks: 'ss -tan state {state.lower().replace('_', '-')}'. Restart affected services if needed.",
                    evidence=RegistryEvidence(key=f"netstat.{state}", value=str(count), expected=f"<50 ({state})", source="/proc/net/tcp"),
                    detected_value=f"{count} {state} connections",
                    expected_value=f"Fewer than 50 {state} connections",
                    affected_component=f"TCP {state}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1046"],
                    tags=["network", "tcp", "connections", "monitoring"],
                )
            )
        return findings


@register_check
class DuplicateListeningPortsCheck(AuditCheck):
    id = "NET-707"
    name = "Duplicate Listening Ports"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects multiple services listening on the same port across protocols"
    depends = ["sockets"]
    tags = ["network", "ports", "misconfiguration"]
    max_findings = 50

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sock_data = self._get_data(collectors, "sockets")

        port_addresses: dict[int, set[str]] = {}

        for proto in ("tcp", "tcp6", "udp", "udp6"):
            for entry in sock_data.get(proto, []):
                local = entry.get("local_address", "")
                port = int(entry.get("local_port", 0))
                state = entry.get("state", "")

                if port < 1 or state == "":
                    continue
                if port not in port_addresses:
                    port_addresses[port] = set()
                port_addresses[port].add(local)

        for port, addresses in port_addresses.items():
            if len(addresses) < 2:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Port {port} bound to multiple addresses",
                    description=f"Port {port} is listening on {len(addresses)} different addresses: {', '.join(sorted(addresses))}.",
                    rationale="A single port bound to multiple interfaces may indicate duplicate service instances, container port mappings, or misconfiguration. This can cause traffic routing confusion.",
                    remediation=f"Review services on port {port}: 'ss -tlnp sport = :{port}'. Consolidate to single bind address if possible.",
                    evidence=RegistryEvidence(key=f"port.{port}.addresses", value=", ".join(sorted(addresses)), expected="single address", source="/proc/net"),
                    detected_value=f"Port {port} on {len(addresses)} addresses",
                    expected_value="Each port on single address",
                    affected_component=f"port:{port}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.4,
                    mitre_attack_ids=["T1046"],
                    tags=["network", "ports", "misconfiguration"],
                )
            )
        return findings


@register_check
class EphemeralPortExhaustionCheck(AuditCheck):
    id = "NET-708"
    name = "Ephemeral Port Range Monitoring"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Checks for potential ephemeral port exhaustion"
    depends = ["kernel_params"]
    tags = ["network", "ports", "availability"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        params = self._get_data(collectors, "kernel_params")
        ip_local_port_range = params.get("net.ipv4.ip_local_port_range", "")

        if not ip_local_port_range:
            return findings

        parts = ip_local_port_range.split()
        if len(parts) < 2:
            return findings

        try:
            low = int(parts[0])
            high = int(parts[1])
        except (ValueError, TypeError):
            return findings

        total_ports = high - low
        if total_ports >= 16000:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Small ephemeral port range",
                description=f"Ephemeral port range is {low}-{high} ({total_ports} ports). Minimum recommended is ~16000 ports.",
                rationale="A small ephemeral port range can be exhausted quickly under high connection rates, causing outbound connection failures.",
                remediation=f"Increase range: 'sysctl -w net.ipv4.ip_local_port_range=\"{low} {low + 16000}\"'.",
                evidence=RegistryEvidence(key="net.ipv4.ip_local_port_range", value=ip_local_port_range, expected=">= 16000 ports", source="/proc/sys/net/ipv4/ip_local_port_range"),
                detected_value=f"{total_ports} ephemeral ports",
                expected_value="16000+ ephemeral ports",
                affected_component="Network stack",
                confidence=Confidence.LOW,
                false_positive_probability=0.4,
                mitre_attack_ids=["T1499"],
                tags=["network", "ports", "availability"],
            )
        )
        return findings


@register_check
class InterfacePromiscuousCheck(AuditCheck):
    id = "NET-709"
    name = "Promiscuous Interface Check"
    category = CheckCategory.NETWORK
    severity = Severity.HIGH
    description = "Detects network interfaces in promiscuous mode (potential packet sniffing)"
    depends = ["interfaces"]
    tags = ["network", "interfaces", "monitoring", "forensics"]

    ALLOWED_PROMISCUOUS: set[str] = {
        "docker0",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        iface_data = self._get_data(collectors, "interfaces")

        for iface in iface_data.get("interfaces", []):
            name = iface.get("name", "")
            promisc = iface.get("promisc", False)

            if not promisc:
                continue
            if name in self.ALLOWED_PROMISCUOUS:
                continue

            findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Promiscuous interface: {name}",
                            description=f"Interface '{name}' is in promiscuous mode. This may indicate packet sniffing or unauthorized monitoring.",
                            rationale="Promiscuous mode allows the interface to capture all network traffic, not just its own. While some tools (tcpdump, Wireshark) require it, unexpected promiscuous interfaces can indicate a compromised system running a packet sniffer.",
                            remediation=f"Disable promiscuous mode: 'ip link set {name} promisc off'. Investigate which process enabled it: 'tcpdump -i {name}' or check for sniffing tools.",
                            evidence=RegistryEvidence(key=f"interface.{name}.promisc", value="true", expected="false", source="sysfs"),
                    detected_value=f"Interface {name} in promiscuous mode",
                    expected_value="No promiscuous interfaces",
                    affected_component=f"interface:{name}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.15,
                    mitre_attack_ids=["T1046", "T1205"],
                    tags=["network", "interfaces", "monitoring", "forensics"],
                )
            )
        return findings


@register_check
class DnsResolverConfigCheck(AuditCheck):
    id = "NET-710"
    name = "DNS Resolver Configuration"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks DNS resolver configuration for consistency between resolv.conf and systemd-resolved"
    depends = ["dns"]
    tags = ["network", "dns", "resolution", "consistency"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        dns_data = self._get_data(collectors, "dns")

        resolv_servers = set(dns_data.get("resolv_conf", {}).get("nameservers", []))
        resolved_servers = set(dns_data.get("resolved_status", {}).get("current_dns", []))
        resolved_running = dns_data.get("resolved_status", {}).get("running", False)

        if not resolved_running:
            return findings
        if not resolv_servers and not resolved_servers:
            return findings
        if resolv_servers == resolved_servers:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="DNS configuration mismatch",
                description=(
                    f"resolv.conf has DNS servers: {', '.join(resolv_servers) or '(none)'}. "
                    f"systemd-resolved has: {', '.join(resolved_servers) or '(none)'}."
                ),
                rationale="Mismatch between resolv.conf and systemd-resolved can cause inconsistent DNS resolution, DNS leak, or resolution failures depending on which resolver nsswitch uses.",
                remediation="Align DNS configuration: 'resolvectl dns <iface> <server>'. Or update /etc/resolv.conf manually.",
                evidence=RegistryEvidence(
                    key="dns.config_mismatch",
                    value=f"resolv.conf: {resolv_servers} / resolved: {resolved_servers}",
                    expected="Consistent DNS configuration",
                    source="/etc/resolv.conf + resolvectl",
                ),
                detected_value="resolv.conf != systemd-resolved",
                expected_value="resolv.conf matches resolved",
                affected_component="DNS resolver",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.2,
                mitre_attack_ids=["T1046"],
                tags=["network", "dns", "resolution", "consistency"],
            )
        )
        return findings
