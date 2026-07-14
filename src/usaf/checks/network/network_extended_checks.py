from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import NetworkEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

ADMIN_PORTS: dict[int, str] = {
    2375: "Docker (unencrypted)",
    2376: "Docker (TLS)",
    6443: "Kubernetes API",
    10250: "Kubelet API",
    10255: "Kubelet (read-only)",
    8001: "Kubernetes Dashboard",
    8888: "Kubernetes Dashboard",
    9090: "Prometheus/Cluster API",
    3000: "Grafana/Dashboard",
    5601: "Kibana",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    5432: "PostgreSQL",
    3306: "MySQL",
    6379: "Redis",
    27017: "MongoDB",
}


@register_check
class AdminPortsExposedCheck(AuditCheck):
    id = "NET-104"
    name = "Admin/Management Ports Exposed"
    category = CheckCategory.NETWORK
    severity = Severity.HIGH
    description = "Detects administrative and management ports exposed on all interfaces"
    depends = ["sockets"]
    tags = ["network", "ports", "attack-surface"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sockets_data = self._get_data(collectors, "sockets")
        findings: list = []

        for proto in ("tcp", "tcp6"):
            for sock in sockets_data.get(proto, []):
                if sock.get("state") not in ("LISTEN", None):
                    continue
                port = sock.get("local_port", 0)
                addr = sock.get("local_address", "")
                if not isinstance(port, int) or not isinstance(addr, str):
                    continue
                if port not in ADMIN_PORTS:
                    continue
                if addr in ("0.0.0.0", "::", "") or addr.startswith("0."):
                    svc = ADMIN_PORTS[port]
                    findings.append(self.finding(
                        finding_id="001",
                        title=f"{svc} exposed on all interfaces (port {port})",
                        description=f"{svc} (port {port}) listening on {addr}",
                        rationale=f"{svc} exposed on all interfaces is accessible from any network reachable to the host, expanding attack surface.",
                        remediation=f"Bind {svc} to localhost or use firewall rules.",
                        evidence=NetworkEvidence(
                            protocol=sock.get("protocol", proto),
                            local_address=addr, local_port=port, state="LISTEN",
                        ),
                        detected_value=f"{svc} on {addr}:{port}",
                        expected_value=f"{svc} bound to 127.0.0.1",
                        affected_component=f"port {port}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1046", "T1190"],
                        tags=["network", "exposed-service"],
                    ))
        return findings


@register_check
class LoopbackCheck(AuditCheck):
    id = "NET-205"
    name = "Loopback Interface Status"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks the loopback interface is operational"
    depends = ["interfaces"]
    tags = ["network", "interfaces", "stability"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        ifaces_data = self._get_data(collectors, "interfaces")
        findings: list = []
        lo_found = False

        for iface in ifaces_data.get("interfaces", []):
            if iface.get("name") == "lo":
                lo_found = True
                if iface.get("state") != "up":
                    findings.append(self.finding(
                        finding_id="001", title="Loopback interface is not up",
                        description=f"Loopback 'lo' is in state '{iface.get('state')}', expected 'up'",
                        rationale="The loopback interface is essential for local IPC and networking.",
                        remediation="Bring lo up: 'ip link set lo up'",
                        evidence=NetworkEvidence(
                            protocol="LOOPBACK", local_address="lo",
                            local_port=0, remote_address=f"state={iface.get('state')}",
                        ),
                        detected_value=f"lo: {iface.get('state')}",
                        expected_value="lo: up",
                        affected_component="interface/lo",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.0,
                        tags=["network", "interfaces"],
                    ))

        if not lo_found:
            findings.append(self.finding(
                finding_id="002", title="Loopback interface not found",
                description="No 'lo' interface found in interface list",
                rationale="The loopback interface must exist for proper system operation.",
                remediation="Check network configuration: 'ip link show lo'",
                evidence=NetworkEvidence(
                    protocol="LOOPBACK", local_address="unknown",
                    local_port=0, remote_address="not found",
                ),
                detected_value="lo not present",
                expected_value="lo interface present and up",
                affected_component="network stack",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                tags=["network", "interfaces"],
            ))

        return findings


@register_check
class WirelessInterfaceCheck(AuditCheck):
    id = "NET-504"
    name = "Wireless Interfaces on Server"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects wireless network interfaces on server systems"
    depends = ["interfaces"]
    tags = ["network", "wireless", "attack-surface"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        ifaces_data = self._get_data(collectors, "interfaces")
        findings: list = []

        for iface in ifaces_data.get("interfaces", []):
            name: str = iface.get("name", "")
            flags: list[str] = iface.get("flags", [])
            if name.startswith(("wl", "wlan", "wlp")):
                findings.append(self.finding(
                    finding_id="001", title=f"Wireless interface active: {name}",
                    description=f"Wireless interface '{name}' is present on this system",
                    rationale="Wireless interfaces extend the attack surface and may allow close-proximity attacks. Server systems typically do not need WiFi.",
                    remediation=f"Disable WiFi: 'ip link set {name} down' or remove the hardware.",
                    evidence=NetworkEvidence(
                        protocol="WIRELESS", local_address=name,
                        local_port=0, remote_address=f"flags={','.join(flags)}",
                    ),
                    detected_value=f"Wireless: {name}",
                    expected_value="No wireless interfaces",
                    affected_component=f"interface/{name}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1557"],
                    tags=["network", "wireless", "attack-surface"],
                ))

        return findings


@register_check
class EphemeralPortListeningCheck(AuditCheck):
    id = "NET-505"
    name = "Services on Ephemeral Ports"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects services listening on ephemeral port ranges (49152+)"
    depends = ["sockets"]
    tags = ["network", "ports", "monitoring"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sockets_data = self._get_data(collectors, "sockets")
        findings: list = []

        for proto in ("tcp", "tcp6", "udp", "udp6"):
            for sock in sockets_data.get(proto, []):
                if sock.get("state") not in ("LISTEN", None):
                    continue
                port = sock.get("local_port", 0)
                addr = sock.get("local_address", "")
                if not isinstance(port, int) or not isinstance(addr, str):
                    continue
                if port >= 49152 and port <= 65535:
                    proto_label = sock.get("protocol", proto)
                    findings.append(self.finding(
                        finding_id="001",
                        title=f"Service listening on ephemeral port {port}",
                        description=f"{proto_label} service on {addr}:{port} is in the ephemeral port range",
                        rationale="Services should not listen on ephemeral port ranges (49152-65535). Ephemeral ports are for outbound connections. A listening service here may bypass firewall rules.",
                        remediation="Configure the service to use a static port below 49152.",
                        evidence=NetworkEvidence(
                            protocol=proto_label, local_address=addr,
                            local_port=port, state=sock.get("state"),
                        ),
                        detected_value=f"{addr}:{port} (ephemeral range)",
                        expected_value="Listening ports below 49152",
                        affected_component=f"port {port}",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.3,
                        tags=["network", "ports", "anomaly"],
                    ))

        return findings


@register_check
class SingleDNSServerCheck(AuditCheck):
    id = "NET-604"
    name = "Single DNS Nameserver"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Detects when only one DNS nameserver is configured"
    depends = ["dns"]
    tags = ["network", "dns", "redundancy"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        dns_data = self._get_data(collectors, "dns")
        findings: list = []
        rc: dict[str, Any] = dns_data.get("resolv_conf", {})
        nameservers: list[str] = rc.get("nameservers", [])

        if len(nameservers) == 1:
            findings.append(self.finding(
                finding_id="001", title="Single DNS nameserver configured",
                description=f"Only one DNS nameserver configured: {nameservers[0]}",
                rationale="A single DNS server creates a single point of failure. If it becomes unreachable, DNS resolution fails, affecting all network-dependent services.",
                remediation="Add a secondary nameserver in /etc/resolv.conf or via systemd-resolved.",
                evidence=RegistryEvidence(
                    key="resolv_conf.nameservers",
                    value=", ".join(nameservers),
                    expected="At least 2 nameservers",
                    source="/etc/resolv.conf",
                ),
                detected_value=f"1 server: {nameservers[0]}",
                expected_value="2+ nameservers",
                affected_component="DNS resolution",
                confidence=Confidence.LOW,
                false_positive_probability=0.2,
                tags=["network", "dns", "redundancy"],
            ))

        return findings


@register_check
class NoDNSConfiguredCheck(AuditCheck):
    id = "NET-605"
    name = "No DNS Servers Configured"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects systems with no DNS nameservers configured"
    depends = ["dns"]
    tags = ["network", "dns", "configuration"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        dns_data = self._get_data(collectors, "dns")
        findings: list = []
        rc: dict[str, Any] = dns_data.get("resolv_conf", {})
        resolved: dict[str, Any] = dns_data.get("resolved_status", {})
        nameservers: list[str] = rc.get("nameservers", [])
        resolved_dns: list[str] = resolved.get("dns_servers", [])

        if not nameservers and not resolved_dns:
            findings.append(self.finding(
                finding_id="001", title="No DNS servers configured",
                description="No nameservers found in /etc/resolv.conf or systemd-resolved",
                rationale="Without DNS resolution, the system cannot resolve hostnames, breaking package updates, authentication, and most network services.",
                remediation="Configure DNS: add nameserver entries to /etc/resolv.conf or configure systemd-resolved.",
                evidence=RegistryEvidence(
                    key="resolv_conf.nameservers",
                    value="none",
                    expected="At least 1 nameserver",
                    source="/etc/resolv.conf",
                ),
                detected_value="No DNS servers",
                expected_value="At least 1 DNS server",
                affected_component="DNS resolution",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                tags=["network", "dns", "configuration"],
            ))

        return findings


@register_check
class NonStandardSSHPortCheck(AuditCheck):
    id = "NET-606"
    name = "Non-Standard SSH Port Exposed"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Detects SSH listening on a non-standard port exposed to all interfaces"
    depends = ["sockets"]
    tags = ["network", "ssh", "ports"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sockets_data = self._get_data(collectors, "sockets")
        findings: list = []

        for proto in ("tcp", "tcp6"):
            for sock in sockets_data.get(proto, []):
                if sock.get("state") not in ("LISTEN", None):
                    continue
                port = sock.get("local_port", 0)
                addr = sock.get("local_address", "")
                if not isinstance(port, int) or not isinstance(addr, str):
                    continue
                if port != 22:
                    continue
                if addr in ("0.0.0.0", "::", ""):
                    findings.append(self.finding(
                        finding_id="001", title="SSH exposed on standard port 22",
                        description=f"SSH is listening on port 22 on {addr}",
                        rationale="SSH on the default port (22) is scanned constantly. Using a non-standard port reduces automated attack noise.",
                        remediation="Consider moving SSH to a non-standard port >1024 and using firewall rules.",
                        evidence=NetworkEvidence(
                            protocol=sock.get("protocol", proto),
                            local_address=addr, local_port=port, state="LISTEN",
                        ),
                        detected_value=f"SSH on {addr}:22",
                        expected_value="SSH on non-standard port or firewalled",
                        affected_component="SSH port",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.5,
                        mitre_attack_ids=["T1046"],
                        tags=["network", "ssh"],
                    ))

        return findings


@register_check
class UnusedInterfacesCheck(AuditCheck):
    id = "NET-607"
    name = "Interfaces Down or Disabled"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Detects network interfaces that are down"
    depends = ["interfaces"]
    tags = ["network", "interfaces", "configuration"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        ifaces_data = self._get_data(collectors, "interfaces")
        findings: list = []

        for iface in ifaces_data.get("interfaces", []):
            name: str = iface.get("name", "")
            state: str = iface.get("state", "")
            if name == "lo":
                continue
            if state == "down":
                findings.append(self.finding(
                    finding_id="001", title=f"Interface '{name}' is down",
                    description=f"Network interface '{name}' is in 'down' state",
                    rationale="Interfaces left in 'down' state may indicate configuration issues or unused hardware that should be disconnected.",
                    remediation=f"If unused: physically disconnect. If needed: 'ip link set {name} up'.",
                    evidence=NetworkEvidence(
                        protocol="ETHERNET", local_address=name,
                        local_port=0, remote_address=f"state={state}",
                    ),
                    detected_value=f"{name}: down",
                    expected_value="Interfaces should be up or physically removed",
                    affected_component=f"interface/{name}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.2,
                    tags=["network", "interfaces", "configuration"],
                ))

        return findings
