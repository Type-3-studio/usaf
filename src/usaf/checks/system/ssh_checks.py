from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class SSHProtocolCheck(AuditCheck):
    """Check that SSH only allows protocol version 2."""

    id = "SSH-001"
    name = "SSH Protocol Version"
    category = CheckCategory.SYSTEM
    severity = Severity.HIGH
    description = "Checks that SSH is configured to only accept protocol version 2 connections"
    depends = []
    tags = ["ssh", "authentication", "cryptography"]

    def _run_check(self, collectors: dict) -> list:
        findings = []
        config = self._parse_ssh_config()

        if not config:
            return findings

        protocol_line = config.get("Protocol")
        if protocol_line and protocol_line.strip() != "2":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH allows protocol version 1",
                    description=f"SSH Protocol is set to {protocol_line!r}, expected '2'",
                    rationale=(
                        "SSH protocol version 1 has known cryptographic weaknesses including "
                        "insertion attacks, CRC compensation attacks, and lack of strong integrity "
                        "checking. Version 1 should never be used. All modern SSH clients and servers "
                        "support protocol version 2."
                    ),
                    remediation=(
                        "Set 'Protocol 2' in /etc/ssh/sshd_config. "
                        "Remove or comment out any 'Protocol 1' or 'Protocol 2,1' lines."
                    ),
                    evidence=RegistryEvidence(
                        key="Protocol",
                        value=protocol_line.strip(),
                        expected="2",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value=protocol_line.strip(),
                    expected_value="2",
                    affected_component="/etc/ssh/sshd_config",
                    reference="https://www.openssh.com/txt/release-2.1",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1110"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.2"],
                    tags=["ssh-hardening"],
                )
            )

        return findings

    def _parse_ssh_config(self) -> dict[str, str]:
        config_paths = [
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config",
        ]
        config: dict[str, str] = {}
        for path_str in config_paths:
            path = Path(path_str)
            if not path.exists():
                continue
            try:
                for line in path.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if " " in line:
                        key, _, value = line.partition(" ")
                        config[key] = value
            except OSError:
                continue
        return config


@register_check
class SSHRootLoginCheck(AuditCheck):
    """Check SSH root login configuration."""

    id = "SSH-002"
    name = "SSH Root Login"
    category = CheckCategory.SYSTEM
    severity = Severity.HIGH
    description = "Checks that SSH root login is disabled or restricted to key-only"
    depends = []
    tags = ["ssh", "authentication", "privilege-escalation"]

    def _run_check(self, collectors: dict) -> list:
        findings = []
        config = self._parse_ssh_config()
        if not config:
            return findings

        permit_root = config.get("PermitRootLogin", "").strip().lower()

        dangerous_values = {"yes", "without-password", "prohibit-password"}
        if permit_root in dangerous_values:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH root login is permitted",
                    description=f"PermitRootLogin is set to {permit_root!r}",
                    rationale=(
                        "Allowing direct root login via SSH eliminates audit trail separation between "
                        "users and increases the attack surface for brute-force attacks. Best practice "
                        "is to disable root login entirely and use sudo for privilege escalation. "
                        "If root login is absolutely required, it should use forced key-based "
                        "authentication only, not passwords."
                    ),
                    remediation=(
                        "Set 'PermitRootLogin no' in /etc/ssh/sshd_config. "
                        "If root access is needed, administrators should SSH as a regular user and use sudo."
                    ),
                    evidence=RegistryEvidence(
                        key="PermitRootLogin",
                        value=permit_root,
                        expected="no",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value=permit_root,
                    expected_value="no",
                    affected_component="/etc/ssh/sshd_config",
                    reference="https://www.ssh.com/academy/ssh/sshd_config",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1110", "T1078"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.6"],
                    tags=["ssh-hardening", "privilege-escalation"],
                )
            )

        return findings

    def _parse_ssh_config(self) -> dict[str, str]:
        path = Path("/etc/ssh/sshd_config")
        config: dict[str, str] = {}
        if not path.exists():
            return config
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if " " in line:
                    key, _, value = line.partition(" ")
                    config[key] = value
        except OSError:
            pass
        return config


@register_check
class SSHKeyExchangeCheck(AuditCheck):
    """Check that SSH uses secure key exchange algorithms."""

    id = "SSH-003"
    name = "SSH Key Exchange Algorithms"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that SSH uses modern, secure key exchange algorithms"
    depends = []
    tags = ["ssh", "cryptography", "tls"]

    def _run_check(self, collectors: dict) -> list:
        findings = []
        config = self._parse_ssh_config()
        if not config:
            return findings

        kex_line = config.get("KexAlgorithms", "")
        weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1",
                     "diffie-hellman-group14-sha1"]

        if kex_line:
            configured_kex = kex_line.strip().split(",")
            found_weak = [k for k in configured_kex if k in weak_kex]
            if found_weak:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title="Weak SSH key exchange algorithms enabled",
                        description=f"Weak KEX algorithms found: {', '.join(found_weak)}",
                        rationale=(
                            "SHA-1 based key exchange algorithms have known collision attacks and "
                            "are considered cryptographically broken for security-sensitive applications. "
                            "These should be replaced with Curve25519-based or at minimum "
                            "diffie-hellman-group-exchange-sha256."
                        ),
                        remediation=(
                            "In /etc/ssh/sshd_config, set: "
                            "KexAlgorithms curve25519-sha256,diffie-hellman-group-exchange-sha256"
                        ),
                        evidence=RegistryEvidence(
                            key="KexAlgorithms",
                            value=kex_line.strip(),
                            expected="curve25519-sha256,...",
                            source="/etc/ssh/sshd_config",
                        ),
                        detected_value=", ".join(found_weak),
                        expected_value="No SHA-1-based KEX algorithms",
                        affected_component="/etc/ssh/sshd_config",
                        reference="https://www.openssh.com/txt/release-7.2",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        cis_benchmarks=["CIS Ubuntu 20.04: 5.2.12"],
                        tags=["ssh-hardening", "cryptography"],
                    )
                )

        return findings

    def _parse_ssh_config(self) -> dict[str, str]:
        path = Path("/etc/ssh/sshd_config")
        config: dict[str, str] = {}
        if not path.exists():
            return config
        try:
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if " " in line:
                    key, _, value = line.partition(" ")
                    config[key] = value
        except OSError:
            pass
        return config
