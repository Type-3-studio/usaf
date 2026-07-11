from __future__ import annotations

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import NetworkEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


KNOWN_SAFE_PORTS: dict[int, str] = {
    22: "SSH",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    993: "IMAPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


@register_check
class UnexpectedListeningPortsCheck(AuditCheck):
    """Check for unexpected listening ports that could indicate unauthorized services."""

    id = "NET-001"
    name = "Unexpected Listening Ports"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Identifies listening ports not associated with expected services"
    depends = ["sockets"]
    tags = ["network", "listening-ports", "attack-surface"]

    def _run_check(self, collectors: dict) -> list:
        sockets_data = self._get_data(collectors, "sockets")
        findings = []

        all_listeners: list[dict] = []
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            for sock in sockets_data.get(proto, []):
                if sock.get("state") in ("LISTEN", None):
                    all_listeners.append(sock)

        localhost_only = ["127.0.0.1", "::1", "127.0.0.53", "127.0.0.11"]

        for sock in all_listeners:
            port = sock.get("local_port", 0)
            addr = sock.get("local_address", "")

            if not isinstance(port, int) or not isinstance(addr, str):
                continue

            if port < 1024:
                continue

            if addr in localhost_only or addr.startswith("127."):
                continue

            if port in KNOWN_SAFE_PORTS:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unexpected non-local listening port: {port}/{sock.get('protocol', '?')}",
                    description=(
                        f"Port {port}/{sock.get('protocol', '?')} is listening on {addr} "
                        f"and not associated with a known safe service"
                    ),
                    rationale=(
                        "Listening ports expand the network attack surface. Every open port represents "
                        "a potential entry point for attackers. Unexpected ports may indicate "
                        "unauthorized services, malware (e.g., backdoors, coin miners listening for "
                        "commands), or misconfigured applications. Each port should be documented "
                        "and justified."
                    ),
                    remediation=(
                        f"Investigate why port {port} is listening on {addr}. "
                        "If unauthorized, stop and disable the associated service. "
                        "If legitimate but not needed on all interfaces, bind to 127.0.0.1. "
                        "Document the service in your asset inventory."
                    ),
                    evidence=NetworkEvidence(
                        protocol=str(sock.get("protocol", "")),
                        local_address=addr,
                        local_port=port,
                        state=sock.get("state") or "LISTEN",
                    ),
                    detected_value=f"Port {port} listening on {addr}",
                    expected_value="Only known/authorized ports",
                    affected_component=f"Port {port}/{sock.get('protocol', '')}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    tags=["attack-surface", "listening-ports"],
                )
            )

        return findings


@register_check
class PromiscuousModeCheck(AuditCheck):
    """Check for network interfaces in promiscuous mode."""

    id = "NET-002"
    name = "Promiscuous Mode Interfaces"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects network interfaces running in promiscuous mode"
    depends = ["interfaces"]
    tags = ["network", "sniffing", "monitoring"]

    def _run_check(self, collectors: dict) -> list:
        interfaces_data = self._get_data(collectors, "interfaces")
        findings = []

        for iface in interfaces_data.get("interfaces", []):
            if iface.get("promisc"):
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Interface '{iface['name']}' is in promiscuous mode",
                        description=(
                            f"Network interface '{iface['name']}' is capturing "
                            f"all network traffic passing through it"
                        ),
                        rationale=(
                            "Promiscuous mode causes a network interface to capture all packets "
                            "on the network segment, not just those addressed to it. This is a "
                            "strong indicator of packet sniffing. While legitimate (e.g., IDS/IPS, "
                            "network monitoring tools), it can also indicate an attacker capturing "
                            "credentials and traffic on the network."
                        ),
                        remediation=(
                            f"Verify that interface '{iface['name']}' is intended to run in promiscuous "
                            f"mode. If not, disable promiscuous mode: 'ip link set {iface['name']} "
                            f"promisc off'."
                        ),
                        evidence=NetworkEvidence(
                            protocol="ETHERNET",
                            local_address=iface.get("mac", ""),
                            local_port=0,
                            state="PROMISC",
                        ),
                        detected_value=f"Interface {iface['name']} is promiscuous",
                        expected_value="Interface is not promiscuous",
                        affected_component=f"Interface: {iface['name']}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1040"],
                        tags=["network-sniffing", "monitoring"],
                    )
                )

        return findings
