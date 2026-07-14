from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

WEAK_MACS: list[str] = [
    "hmac-md5", "hmac-md5-96", "hmac-ripemd160",
    "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com",
]

WEAK_HOST_KEY_TYPES: list[str] = [
    "ssh-dss", "ssh-rsa",
]


def _get_directives(collectors: dict[str, Any]) -> dict[str, str]:
    """Extract sshd_config directives from the ssh_config collector."""
    ssh_data: dict | None = collectors.get("ssh_config")
    if not ssh_data:
        return {}
    sshd: dict | None = ssh_data.get("sshd_config")
    if not sshd:
        return {}
    directives: dict[str, str] = sshd.get("directives") or {}
    return directives


def _get_sshd_directive(key: str, directives: dict[str, str]) -> str | None:
    val = directives.get(key.lower())
    return val.strip().lower() if val else None


def _get_sshd_directive_value(key: str, directives: dict[str, str]) -> str | None:
    val = directives.get(key.lower())
    return val.strip() if val else None


@register_check
class SshMacAlgorithmsCheck(AuditCheck):
    id = "SSH-601"
    name = "SSH MAC Algorithms"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that weak MAC algorithms are not enabled in SSH"
    depends = ["ssh_config"]
    tags = ["ssh", "algorithms", "mac", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = _get_directives(collectors)
        macs = _get_sshd_directive_value("MACs", directives)

        if macs is None:
            return findings

        macs_lower = macs.lower()
        weak_found = [m for m in WEAK_MACS if m in macs_lower]

        if not weak_found:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Weak MAC algorithms enabled",
                description=f"Weak MACs found in sshd_config: {', '.join(weak_found)}.",
                rationale="Weak MAC algorithms like hmac-md5 and hmac-sha1 are vulnerable to collision attacks. SSH connections using these MACs can have their integrity compromised.",
                remediation="Remove weak MACs from /etc/ssh/sshd_config. Use only: hmac-sha2-256, hmac-sha2-512, umac-128@openssh.com.",
                evidence=RegistryEvidence(key="sshd.MACs", value=macs, expected="no weak MACs", source="/etc/ssh/sshd_config"),
                detected_value=f"Weak MACs: {', '.join(weak_found)}",
                expected_value="Only strong MAC algorithms",
                affected_component="SSH configuration",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                mitre_attack_ids=["T1046"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.2.14"],
                tags=["ssh", "algorithms", "mac", "hardening"],
            )
        )
        return findings


@register_check
class SshHostKeySizeCheck(AuditCheck):
    id = "SSH-602"
    name = "SSH Host Key Strength"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that SSH host keys meet minimum size requirements"
    depends = ["ssh_config"]
    tags = ["ssh", "host-keys", "cryptography", "hardening"]

    MIN_RSA_BITS = 3072
    MIN_ECDSA_BITS = 256

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ssh_data = self._get_data(collectors, "ssh_config")
        host_keys = ssh_data.get("host_keys", [])

        for key in host_keys:
            key_type = key.get("type", "")
            key_size = key.get("size", 0)
            key_path = key.get("path", "")

            if "rsa" in key_type.lower() and key_size < self.MIN_RSA_BITS:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Weak RSA host key: {key_size} bits",
                        description=f"RSA host key '{key_path}' is only {key_size} bits (minimum {self.MIN_RSA_BITS}).",
                        rationale="RSA keys under 3072 bits are susceptible to factoring attacks. NIST and CIS recommend minimum 3072-bit RSA keys.",
                        remediation=f"Generate new host key: 'rm {key_path} && ssh-keygen -t rsa -b {self.MIN_RSA_BITS} -f {key_path.replace('.pub', '')}'.",
                        evidence=RegistryEvidence(key=f"ssh.hostkey.{key_type}", value=str(key_size), expected=f">={self.MIN_RSA_BITS}", source=key_path),
                        detected_value=f"{key_size}-bit {key_type}",
                        expected_value=f"{self.MIN_RSA_BITS}+ bits",
                        affected_component=key_path,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1046"],
                        tags=["ssh", "host-keys", "cryptography", "hardening"],
                    )
                )
        return findings


@register_check
class SshAgentForwardingCheck(AuditCheck):
    id = "SSH-603"
    name = "SSH Agent Forwarding"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that SSH agent forwarding is disabled"
    depends = ["ssh_config"]
    tags = ["ssh", "forwarding", "authentication", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = _get_directives(collectors)
        val = _get_sshd_directive("AllowAgentForwarding", directives)

        if val is None or val == "yes":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH agent forwarding is allowed",
                    description=f"AllowAgentForwarding {'not set (defaults to yes)' if val is None else 'yes'}. This should be disabled.",
                    rationale="SSH agent forwarding allows remote servers to use the local SSH agent. If the remote server is compromised, the attacker can use the forwarded agent to authenticate to other systems.",
                    remediation="Set 'AllowAgentForwarding no' in /etc/ssh/sshd_config and restart sshd.",
                    evidence=RegistryEvidence(key="sshd.AllowAgentForwarding", value=val or "yes (default)", expected="no", source="/etc/ssh/sshd_config"),
                    detected_value=f"AllowAgentForwarding={val or 'yes'}",
                    expected_value="AllowAgentForwarding no",
                    affected_component="SSH configuration",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1563"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.15"],
                    tags=["ssh", "forwarding", "authentication", "hardening"],
                )
            )
        return findings


@register_check
class SshPubkeyAuthOnlyCheck(AuditCheck):
    id = "SSH-604"
    name = "SSH Public Key Authentication"
    category = CheckCategory.SYSTEM
    severity = Severity.HIGH
    description = "Checks that SSH is configured to require public key authentication and disable passwords"
    depends = ["ssh_config"]
    tags = ["ssh", "authentication", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = _get_directives(collectors)
        pubkey = _get_sshd_directive("PubkeyAuthentication", directives)
        password = _get_sshd_directive("PasswordAuthentication", directives)

        pubkey_val = "yes (default)" if pubkey is None else pubkey

        password_val = "yes (default)" if password is None else password

        issues: list[str] = []
        if pubkey is None or pubkey != "yes":
            issues.append(f"PubkeyAuthentication={pubkey_val}")
        if password is None or password != "no":
            issues.append(f"PasswordAuthentication={password_val}")

        if not issues:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="SSH password authentication not disabled",
                description=f"Issues: {'; '.join(issues)}. Public key authentication should be required.",
                rationale="Password authentication is vulnerable to brute-force and credential stuffing attacks. Public key authentication provides stronger security and should be the only allowed method.",
                remediation="Set in /etc/ssh/sshd_config: 'PubkeyAuthentication yes' and 'PasswordAuthentication no'.",
                evidence=RegistryEvidence(key="sshd.authentication", value="; ".join(issues), expected="PubkeyAuthentication yes, PasswordAuthentication no", source="/etc/ssh/sshd_config"),
                detected_value="; ".join(issues),
                expected_value="PubkeyAuthentication yes, PasswordAuthentication no",
                affected_component="SSH configuration",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                mitre_attack_ids=["T1110"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.2.3"],
                tags=["ssh", "authentication", "hardening"],
            )
        )
        return findings


@register_check
class SshPortCheck(AuditCheck):
    id = "SSH-605"
    name = "SSH Port Configuration"
    category = CheckCategory.SYSTEM
    severity = Severity.LOW
    description = "Checks SSH listening port configuration"
    depends = ["ssh_config"]
    tags = ["ssh", "port", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = _get_directives(collectors)
        port = _get_sshd_directive_value("Port", directives)

        if port is None or port == "22":
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title=f"SSH listening on non-standard port {port}",
                description=f"SSH is configured on port {port} instead of the default 22.",
                rationale="Using a non-standard SSH port can reduce automated scanning noise but does not provide real security. Port scanning easily discovers alternative ports. Focus on key-based auth and firewall rules instead.",
                remediation="Consider whether the non-standard port provides value. Ensure firewall rules are in place regardless of port.",
                evidence=RegistryEvidence(key="sshd.Port", value=port, expected="22 or firewalled", source="/etc/ssh/sshd_config"),
                detected_value=f"SSH port: {port}",
                expected_value="22 (with firewall)",
                affected_component="SSH configuration",
                confidence=Confidence.LOW,
                false_positive_probability=0.6,
                mitre_attack_ids=["T1046"],
                tags=["ssh", "port", "hardening"],
            )
        )
        return findings


@register_check
class SshClientAliveCountMaxCheck(AuditCheck):
    id = "SSH-606"
    name = "SSH Session Termination"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that SSH sessions are properly terminated after inactivity"
    depends = ["ssh_config"]
    tags = ["ssh", "session", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = _get_directives(collectors)
        alive_interval = _get_sshd_directive_value("ClientAliveInterval", directives)
        alive_count_max = _get_sshd_directive_value("ClientAliveCountMax", directives)

        if alive_interval is None or alive_count_max is None:
            return findings

        try:
            interval = int(alive_interval)
            count_max = int(alive_count_max)
        except (ValueError, TypeError):
            return findings

        max_idle = interval * count_max

        if max_idle <= 900:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="SSH session timeout too long",
                description=f"ClientAliveInterval={alive_interval}s, ClientAliveCountMax={alive_count_max}. Max idle time before disconnect: {max_idle}s ({max_idle/60:.0f}min).",
                rationale="Long SSH session timeouts leave authenticated sessions open, increasing the risk of unauthorized access if a user walks away from an active session.",
                remediation="Set ClientAliveInterval 300 and ClientAliveCountMax 3 in /etc/ssh/sshd_config.",
                evidence=RegistryEvidence(key="sshd.session_timeout", value=f"{max_idle}s", expected="<900s", source="/etc/ssh/sshd_config"),
                detected_value=f"Max idle: {max_idle}s",
                expected_value="Max idle < 900s (15 minutes)",
                affected_component="SSH configuration",
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1046"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.2.19"],
                tags=["ssh", "session", "hardening"],
            )
        )
        return findings
