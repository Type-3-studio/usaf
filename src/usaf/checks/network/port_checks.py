from __future__ import annotations

import os
from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import NetworkEvidence, ProcessEvidence
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

    id = "NET-101"
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
class ProcessToPortMappingCheck(AuditCheck):
    id = "NET-550"
    name = "Listening Port to Process Mapping"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Maps each listening port to the process that owns it"
    depends = ["sockets"]
    tags = ["network", "listening-ports", "processes", "forensics"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []
        sockets_data = self._get_data(collectors, "sockets")
        inode_map = self._build_socket_inode_map()

        all_listeners: list[dict] = []
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            for sock in sockets_data.get(proto, []):
                if sock.get("state") in ("LISTEN", None):
                    all_listeners.append(sock)

        for sock in all_listeners:
            inode = sock.get("inode")
            port = sock.get("local_port", 0)
            addr = sock.get("local_address", "")
            protocol = sock.get("protocol", "?")

            proc_info = inode_map.get(inode)
            proc_name = proc_info["name"] if proc_info else "unknown"
            proc_pid = proc_info["pid"] if proc_info else 0

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Listening port {port}/{protocol} → {proc_name} (PID {proc_pid})",
                    description=(
                        f"Port {port}/{protocol} on {addr} is owned by process "
                        f"'{proc_name}' (PID {proc_pid}). "
                        f"{'No process found — socket may be orphaned' if not proc_info else ''}"
                    ),
                    rationale=(
                        "Every listening port should be attributable to a known, authorized process. "
                        "Unknown or unexpected process-to-port associations can indicate backdoors, "
                        "coin miners, reverse shells, or unauthorized services. If a listening socket "
                        "has no owning process (orphaned), it suggests a kernel-level or container "
                        "network namespace issue."
                    ),
                    remediation=(
                        f"Investigate PID {proc_pid} ('{proc_name}') on port {port}. "
                        "Verify it's an authorized service. "
                        "Check binary: 'ls -la /proc/{proc_pid}/exe'. "
                        "If unauthorized: 'systemctl stop <service>' or 'kill {proc_pid}'."
                    ),
                    evidence=NetworkEvidence(
                        protocol=protocol,
                        local_address=addr,
                        local_port=port,
                        state=sock.get("state") or "LISTEN",
                        pid=proc_pid,
                        process_name=proc_name,
                        inode=inode,
                    ),
                    detected_value=f"Port {port}: process '{proc_name}' (PID {proc_pid})",
                    expected_value="Attributable to known authorized process",
                    affected_component=f"Port {port}/{protocol}",
                    confidence=Confidence.HIGH if proc_info else Confidence.LOW,
                    false_positive_probability=0.05 if proc_info else 0.5,
                    mitre_attack_ids=["T1043", "T1505"],
                    tags=["network", "process-mapping", "forensics"],
                )
            )

        return findings

    @staticmethod
    def _build_socket_inode_map() -> dict[int, dict]:
        proc = Path("/proc")
        inode_map: dict[int, dict] = {}
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            pid = entry.name
            fd_dir = entry / "fd"
            if not fd_dir.is_dir():
                continue
            try:
                for fd_entry in fd_dir.iterdir():
                    try:
                        link = os.readlink(str(fd_entry))
                    except OSError:
                        continue
                    if link.startswith("socket:["):
                        try:
                            inode = int(link[8:-1])
                        except ValueError:
                            continue
                        if inode not in inode_map:
                            try:
                                comm = (entry / "comm").read_text().strip()
                            except OSError:
                                comm = "?"
                            inode_map[inode] = {"pid": int(pid), "name": comm}
            except (OSError, PermissionError):
                continue
        return inode_map


@register_check
class PromiscuousModeCheck(AuditCheck):
    """Check for network interfaces in promiscuous mode."""

    id = "NET-201"
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
