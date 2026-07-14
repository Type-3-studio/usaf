from __future__ import annotations

import datetime
import subprocess
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, NetworkEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

SENSITIVE_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    50070: "HDFS",
}


@register_check
class ExposedSensitivePortsCheck(AuditCheck):
    id = "NET-102"
    name = "Sensitive Services Exposed on All Interfaces"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects sensitive services listening on all network interfaces (0.0.0.0)"
    depends = ["sockets"]
    tags = ["network", "ports", "attack-surface"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sockets_data = self._get_data(collectors, "sockets")
        findings: list = []

        for proto in ("tcp", "tcp6"):
            for sock in sockets_data.get(proto, []):
                if sock.get("state") not in ("LISTEN", None):
                    continue
                port: Any = sock.get("local_port", 0)
                addr: Any = sock.get("local_address", "")
                if not isinstance(port, int) or not isinstance(addr, str):
                    continue
                if port not in SENSITIVE_PORTS:
                    continue
                if addr in ("0.0.0.0", "::", "") or addr.startswith("0."):
                    svc_name = SENSITIVE_PORTS[port]
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"{svc_name} exposed on all interfaces (port {port})",
                            description=(
                                f"{svc_name} (port {port}) is listening on {addr}, "
                                f"accessible from all network interfaces"
                            ),
                            rationale=(
                                f"{svc_name} on port {port} listening on all interfaces "
                                f"is accessible from any reachable network. This expands "
                                f"the attack surface significantly. Services should bind "
                                f"to specific interfaces (e.g., localhost) unless "
                                f"remote access is explicitly required."
                            ),
                            remediation=(
                                f"Bind {svc_name} to localhost: "
                                f"update the service configuration to bind "
                                f"to 127.0.0.1 instead of 0.0.0.0"
                            ),
                            evidence=NetworkEvidence(
                                protocol=sock.get("protocol", proto),
                                local_address=addr,
                                local_port=port,
                                state="LISTEN",
                            ),
                            detected_value=f"{svc_name} on {addr}:{port}",
                            expected_value=f"{svc_name} bound to 127.0.0.1",
                            affected_component=f"port {port} ({svc_name})",
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.05,
                            mitre_attack_ids=["T1046", "T1190"],
                            tags=["network", "exposed-service"],
                        )
                    )

        return findings


@register_check
class InterfaceCarrierCheck(AuditCheck):
    id = "NET-202"
    name = "Interfaces Up Without Carrier"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Detects network interfaces that are up but have no carrier"
    depends = ["interfaces"]
    tags = ["network", "interfaces", "monitoring"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        ifaces_data = self._get_data(collectors, "interfaces")
        findings: list = []

        for iface in ifaces_data.get("interfaces", []):
            name: str = iface.get("name", "")
            state: str = iface.get("state", "")
            carrier: bool = iface.get("carrier", False)
            if state == "up" and not carrier:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Interface {name} is up but has no carrier",
                        description=(
                            f"Interface '{name}' is in state '{state}' "
                            f"but carrier is {'down' if not carrier else 'up'}"
                        ),
                        rationale=(
                            "An interface that is administratively 'up' but has no "
                            "carrier indicates a configuration issue — the interface "
                            "is enabled but not physically connected. This may "
                            "indicate a dangling interface or misconfiguration."
                        ),
                        remediation=(
                            f"Check physical connection for '{name}'. "
                            f"If unused, disable it: 'ip link set {name} down'"
                        ),
                        evidence=NetworkEvidence(
                            protocol="ETHERNET",
                            local_address=name,
                            local_port=0,
                            remote_address=f"state={state}",
                        ),
                        detected_value=f"Interface {name}: state={state}, carrier={'up' if carrier else 'down'}",
                        expected_value="Interfaces with carrier OR interfaces down",
                        affected_component=f"interface/{name}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        tags=["network", "interfaces"],
                    )
                )

        return findings


@register_check
class AllMultiInterfacesCheck(AuditCheck):
    id = "NET-203"
    name = "Interfaces in ALLMULTI Mode"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects network interfaces in ALLMULTI mode which may indicate packet sniffing"
    depends = ["interfaces"]
    tags = ["network", "interfaces", "sniffing"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        ifaces_data = self._get_data(collectors, "interfaces")
        findings: list = []

        for iface in ifaces_data.get("interfaces", []):
            flags: list[str] = iface.get("flags", [])
            if "ALLMULTI" in flags and "PROMISC" not in flags:
                name: str = iface.get("name", "")
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Interface {name} in ALLMULTI mode",
                        description=f"Interface '{name}' has ALLMULTI flag set without PROMISC",
                        rationale=(
                            "ALLMULTI mode causes the interface to receive all multicast "
                            "traffic. While less intrusive than PROMISC, it may indicate "
                            "packet sniffing (e.g., by an attacker or monitoring tool) "
                            "or a misconfigured service."
                        ),
                        remediation=(
                            f"Disable ALLMULTI: 'ip link set {name} allmulti off'. "
                            f"Verify which service enabled it: 'ip link show {name}'"
                        ),
                        evidence=NetworkEvidence(
                            protocol="ETHERNET",
                            local_address=name,
                            local_port=0,
                            remote_address=f"flags={','.join(flags)}",
                        ),
                        detected_value=f"ALLMULTI on {name}",
                        expected_value="No ALLMULTI interfaces",
                        affected_component=f"interface/{name}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1040"],
                        tags=["network", "sniffing"],
                    )
                )

        return findings


@register_check
class AvahiMDNSCheck(AuditCheck):
    id = "NET-303"
    name = "mDNS/Avahi Service Exposure"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects running Avahi mDNS service which exposes host information on the local network"
    depends = ["dns"]
    tags = ["network", "mdns", "avahi", "discovery"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        dns_data = self._get_data(collectors, "dns")
        findings: list = []
        mdns: dict[str, Any] = dns_data.get("mdns", {})

        if mdns.get("avahi_running", False):
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Avahi mDNS service is running",
                    description=(
                        "Avahi daemon (mDNS) is running, broadcasting host "
                        "information on the local network"
                    ),
                    rationale=(
                        "mDNS (Avahi) broadcasts hostname and service information "
                        "to the local network, allowing network discovery without "
                        "authentication. This leaks system information and enables "
                        "network reconnaissance. It is typically unnecessary on "
                        "server environments."
                    ),
                    remediation=(
                        "Disable Avahi: 'systemctl stop avahi-daemon' "
                        "and 'systemctl disable avahi-daemon'. "
                        "Remove the package: 'apt remove avahi-daemon'."
                    ),
                    evidence=RegistryEvidence(
                        key="avahi-daemon",
                        value="running",
                        expected="stopped/not installed",
                        source="systemctl / D-Bus",
                    ),
                    detected_value="Avahi daemon running",
                    expected_value="Avahi daemon not running / not installed",
                    affected_component="avahi-daemon",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1595", "T1046"],
                    tags=["network", "mdns", "discovery"],
                )
            )

        return findings


@register_check
class DNSSearchDomainCheck(AuditCheck):
    id = "NET-304"
    name = "DNS Search Domain Information Leak"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Detects internal domain names in DNS search path"
    depends = ["dns"]
    tags = ["network", "dns", "information-disclosure"]

    _internal_tlds: set[str] = {
        ".local", ".internal", ".corp", ".private",
        ".lan", ".intranet", ".home", ".office",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        dns_data = self._get_data(collectors, "dns")
        findings: list = []
        search_domains: list[str] = []

        rc: dict[str, Any] = dns_data.get("resolv_conf", {})
        search_domains.extend(rc.get("search_domains", []))

        internal_domains = [
            sd for sd in search_domains
            if any(tld in sd for tld in self._internal_tlds)
        ]

        if internal_domains:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Internal domain names in DNS search path",
                    description=(
                        f"DNS search domains contain internal TLDs: "
                        f"{', '.join(internal_domains)}"
                    ),
                    rationale=(
                        "Internal domain names in the DNS search path are "
                        "appended to unqualified hostnames during resolution. "
                        "This leaks internal naming conventions and domain "
                        "structure to anyone who can trigger a DNS lookup."
                    ),
                    remediation=(
                        "Remove internal domain names from the search path "
                        "in /etc/resolv.conf or set a fully qualified domain "
                        "name. Use the 'ndots' option to control search behavior."
                    ),
                    evidence=RegistryEvidence(
                        key="search_domains",
                        value=", ".join(internal_domains),
                        expected="No internal TLDs in search path",
                        source="/etc/resolv.conf",
                    ),
                    detected_value=", ".join(internal_domains),
                    expected_value="No internal domain names",
                    affected_component="DNS resolution",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1590"],
                    tags=["network", "dns", "information-disclosure"],
                )
            )

        return findings


@register_check
class UntrustedCACheck(AuditCheck):
    id = "NET-601"
    name = "Untrusted CA Certificates"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects potentially untrusted or unusual CA certificates in the system store"
    depends = ["certificates"]
    tags = ["tls", "certificates", "pki"]

    _known_ca_patterns: set[str] = {
        "digicert", "comodo", "godaddy", "letsencrypt", "globalsign",
        "entrust", "verisign", "geotrust", "thawte", "sectigo",
        "identrust", "network solutions", "buypass", "certum",
        "quovadis", "secomea", "ssl.com", "trustcor", "d-trust",
        "deutsche telekom", "swisscom", "firmaprofesional",
        "camerfirma", "chambers of commerce", "cn=root ca",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cert_data = self._get_data(collectors, "certificates")
        findings: list = []
        ca_bundles: list[dict[str, Any]] = cert_data.get("ca_bundles", [])

        pem_files: list[dict[str, Any]] = cert_data.get("system_certs", {}).get("pem_files", [])
        all_certs = ca_bundles + pem_files

        cert_names: set[str] = set()
        for c in all_certs:
            if isinstance(c, dict):
                name: str = c.get("name", "")
                if name:
                    cert_names.add(name.lower())

        for name in sorted(cert_names):
            if any(pattern in name for pattern in self._known_ca_patterns):
                continue
            if name.endswith((".pem", ".crt", ".der")):
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Potentially untrusted CA certificate: {name}",
                        description=f"Certificate file '{name}' may not be from a well-known CA",
                        rationale=(
                            "System CA trust stores should only contain certificates "
                            "from recognized Certificate Authorities. Unknown or "
                            "self-signed CA certificates may indicate shadow IT, "
                            "corporate proxy interception, or unauthorized trust "
                            "injection."
                        ),
                        remediation=(
                            f"Review '{name}' in /etc/ssl/certs/. "
                            f"Remove if unauthorized: "
                            f"'sudo rm /etc/ssl/certs/{name}' "
                            f"then 'sudo update-ca-certificates --fresh'"
                        ),
                        evidence=FileEvidence(
                            path=f"/etc/ssl/certs/{name}",
                            content=f"Unrecognized CA certificate: {name}",
                        ),
                        detected_value=name,
                        expected_value="Only well-known CA certificates",
                        affected_component=f"/etc/ssl/certs/{name}",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.4,
                        mitre_attack_ids=["T1553.004"],
                        tags=["tls", "certificates", "pki"],
                    )
                )

        return findings


@register_check
class ExpiringCertificatesCheck(AuditCheck):
    id = "NET-602"
    name = "Expiring TLS Certificates"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Detects system CA certificates that are expiring within 60 days"
    depends = ["certificates"]
    tags = ["tls", "certificates", "pki", "monitoring"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cert_data = self._get_data(collectors, "certificates")
        findings: list = []
        now = datetime.datetime.now(datetime.UTC)
        threshold = now + datetime.timedelta(days=60)

        ca_bundles: list[dict[str, Any]] = cert_data.get("ca_bundles", [])
        seen: set[str] = set()

        for entry in ca_bundles:
            path: str = entry.get("path", "")
            if not path or path in seen:
                continue
            seen.add(path)

            expires = self._get_expiry(path)
            if expires is None:
                continue

            if expires < now:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Certificate already expired: {path}",
                        description=(
                            f"Certificate at {path} expired on "
                            f"{expires.strftime('%Y-%m-%d')}"
                        ),
                        rationale=(
                            "Expired certificates will cause TLS verification "
                            "failures, breaking HTTPS connections and other "
                            "TLS-dependent services."
                        ),
                        remediation=(
                            f"Renew or remove the expired certificate at {path}. "
                            f"Then run 'sudo update-ca-certificates --fresh'."
                        ),
                        evidence=FileEvidence(
                            path=path,
                            content=f"Expired: {expires.strftime('%Y-%m-%d')}",
                        ),
                        detected_value=f"Expired {expires.strftime('%Y-%m-%d')}",
                        expected_value="Certificate not expired",
                        affected_component=path,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.0,
                        mitre_attack_ids=["T1553.004", "T1608"],
                        tags=["tls", "certificates", "expiry"],
                    )
                )
            elif expires < threshold:
                findings.append(
                    self.finding(
                        finding_id="002",
                        title=f"Certificate expiring soon: {path}",
                        description=(
                            f"Certificate at {path} expires on "
                            f"{expires.strftime('%Y-%m-%d')} "
                            f"({(expires - now).days} days)"
                        ),
                        rationale=(
                            "Certificates expiring within 60 days should be "
                            "renewed proactively to avoid service disruption."
                        ),
                        remediation=(
                            f"Renew the certificate at {path} before "
                            f"{expires.strftime('%Y-%m-%d')}."
                        ),
                        evidence=FileEvidence(
                            path=path,
                            content=f"Expires: {expires.strftime('%Y-%m-%d')} ({ (expires - now).days} days)",
                        ),
                        detected_value=f"Expires {expires.strftime('%Y-%m-%d')}",
                        expected_value="Certificate expiry > 60 days away",
                        affected_component=path,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.0,
                        mitre_attack_ids=["T1553.004"],
                        tags=["tls", "certificates", "expiry"],
                    )
                )

        return findings

    @staticmethod
    def _get_expiry(path: str) -> datetime.datetime | None:
        try:
            r = subprocess.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", path],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode != 0:
                return None
            for line in r.stdout.splitlines():
                if line.startswith("notAfter="):
                    date_str = line[len("notAfter="):]
                    return datetime.datetime.strptime(
                        date_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.UTC)
        except (OSError, subprocess.SubprocessError, ValueError):
            return None
        return None


@register_check
class CertStoreIntegrityCheck(AuditCheck):
    id = "NET-603"
    name = "Certificate Store Integrity"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Detects issues in the certificate store such as broken symlinks"
    depends = ["certificates"]
    tags = ["tls", "certificates", "integrity"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cert_data = self._get_data(collectors, "certificates")
        findings: list = []

        system_certs: dict[str, Any] = cert_data.get("system_certs", {})
        broken_links: list[str] = system_certs.get("broken_links", [])

        for link in broken_links:
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Broken symlink in certificate store: {link}",
                    description=(
                        f"Broken symlink at {link} points to a non-existent file"
                    ),
                    rationale=(
                        "Broken symlinks in the certificate store indicate a "
                        "corrupted CA trust configuration. This may cause "
                        "TLS verification failures or unexpected behavior."
                    ),
                    remediation=(
                        f"Remove the broken symlink: 'sudo rm {link}'. "
                        f"Then 'sudo update-ca-certificates --fresh'."
                    ),
                    evidence=FileEvidence(
                        path=link,
                        content="Broken symlink",
                    ),
                    detected_value=f"Broken symlink: {link}",
                    expected_value="No broken symlinks",
                    affected_component=link,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    tags=["tls", "certificates", "integrity"],
                )
            )

        cert_count: dict[str, Any] = cert_data.get("cert_count", {})
        total_certs: int = cert_count.get("total_certs", 0)
        if total_certs == 0:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="No certificates found in system store",
                    description="The system CA certificate bundle contains no certificates",
                    rationale=(
                        "An empty CA certificate store means no remote TLS "
                        "connections can be verified. This will break HTTPS, "
                        "APT updates, and most secure network communications."
                    ),
                    remediation=(
                        "Reinstall CA certificates: "
                        "'sudo apt install --reinstall ca-certificates'"
                    ),
                    evidence=RegistryEvidence(
                        key="cert_count.total_certs",
                        value="0",
                        expected="> 0",
                        source="/etc/ssl/certs/ca-certificates.crt",
                    ),
                    detected_value="0 certificates",
                    expected_value="> 0 certificates",
                    affected_component="CA certificate store",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    tags=["tls", "certificates", "integrity"],
                )
            )

        return findings
