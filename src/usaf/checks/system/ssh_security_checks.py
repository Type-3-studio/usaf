from __future__ import annotations

from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

WEAK_CIPHERS = {
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "blowfish-cbc", "cast128-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "none",
}


@register_check
class SSHMaxAuthTriesCheck(AuditCheck):
    id = "SSH-103"
    name = "SSH MaxAuthTries"
    category = CheckCategory.SYSTEM
    severity = Severity.HIGH
    description = "Checks that SSH MaxAuthTries is set to 4 or lower to limit brute force attempts"
    depends = ["ssh_config"]
    tags = ["ssh", "authentication", "brute-force", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = self._get_directives(collectors)
        if directives is None:
            return findings

        raw = directives.get("maxauthtries", "")
        try:
            value = int(raw)
        except (ValueError, TypeError):
            return findings

        if value > 4:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH MaxAuthTries permits excessive authentication attempts",
                    description=f"MaxAuthTries is set to {value}, expected 4 or lower",
                    rationale=(
                        "MaxAuthTries controls the maximum number of authentication attempts "
                        "per connection. A high value allows attackers to brute force passwords "
                        "without reconnecting, reducing the cost of attack. Setting to 4 or lower "
                        "limits exposure without breaking legitimate use."
                    ),
                    remediation="Set 'MaxAuthTries 4' in /etc/ssh/sshd_config and restart sshd",
                    evidence=RegistryEvidence(
                        key="MaxAuthTries",
                        value=str(value),
                        expected="4",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value=str(value),
                    expected_value="4",
                    affected_component="/etc/ssh/sshd_config",
                    reference="https://www.cisecurity.org/benchmark/ubuntu_linux",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.5"],
                    mitre_attack_ids=["T1110"],
                    tags=["ssh-hardening", "brute-force"],
                )
            )

        return findings

    def _get_directives(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        ssh_data: Any = collectors.get("ssh_config")
        if not ssh_data:
            return None
        sshd_config: Any = ssh_data.get("sshd_config")
        if not sshd_config:
            return None
        directives: dict[str, Any] | None = sshd_config.get("directives")
        return directives


@register_check
class SSHEmptyPasswordsCheck(AuditCheck):
    id = "SSH-104"
    name = "SSH Empty Passwords"
    category = CheckCategory.SYSTEM
    severity = Severity.CRITICAL
    description = "Checks that SSH does not permit empty passwords"
    depends = ["ssh_config"]
    tags = ["ssh", "authentication", "passwords"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = self._get_directives(collectors)
        if directives is None:
            return findings

        value = directives.get("permitemptypasswords", "").strip().lower()
        if value == "yes":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH permits empty passwords",
                    description="PermitEmptyPasswords is set to 'yes'",
                    rationale=(
                        "Allowing empty passwords eliminates authentication entirely — "
                        "anyone who knows the username can log in without a credential. "
                        "This is one of the most critical SSH misconfigurations."
                    ),
                    remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config and restart sshd",
                    evidence=RegistryEvidence(
                        key="PermitEmptyPasswords",
                        value=value,
                        expected="no",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value=value,
                    expected_value="no",
                    affected_component="/etc/ssh/sshd_config",
                    reference="https://www.ssh.com/academy/ssh/sshd_config",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.9"],
                    mitre_attack_ids=["T1110", "T1078"],
                    tags=["ssh-hardening", "authentication"],
                )
            )

        return findings

    def _get_directives(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        ssh_data: Any = collectors.get("ssh_config")
        if not ssh_data:
            return None
        sshd_config: Any = ssh_data.get("sshd_config")
        if not sshd_config:
            return None
        directives: dict[str, Any] | None = sshd_config.get("directives")
        return directives


@register_check
class SSHClientAliveCheck(AuditCheck):
    id = "SSH-105"
    name = "SSH Client Alive / Idle Timeout"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that SSH idle timeout is configured via ClientAliveInterval and ClientAliveCountMax"
    depends = ["ssh_config"]
    tags = ["ssh", "session", "timeout", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = self._get_directives(collectors)
        if directives is None:
            return findings

        interval_raw = directives.get("clientaliveinterval", "").strip()
        count_raw = directives.get("clientalivecountmax", "").strip()

        if not interval_raw or not count_raw:
            missing = []
            if not interval_raw:
                missing.append("ClientAliveInterval")
            if not count_raw:
                missing.append("ClientAliveCountMax")
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH idle timeout not fully configured",
                    description=f"Missing SSH timeout settings: {', '.join(missing)}",
                    rationale=(
                        "Without an idle timeout, abandoned SSH sessions remain open indefinitely. "
                        "This increases the risk of unauthorized access via unlocked terminals, "
                        "session hijacking, and resource exhaustion. "
                        "ClientAliveInterval sends keepalive probes; ClientAliveCountMax determines "
                        "how many failed probes before disconnection."
                    ),
                    remediation=(
                        "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 0' "
                        "in /etc/ssh/sshd_config and restart sshd"
                    ),
                    evidence=RegistryEvidence(
                        key="ClientAliveInterval / ClientAliveCountMax",
                        value=f"Interval={interval_raw!r}, CountMax={count_raw!r}",
                        expected="ClientAliveInterval 300, ClientAliveCountMax 0",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value=f"Interval={interval_raw or 'not set'}, CountMax={count_raw or 'not set'}",
                    expected_value="ClientAliveInterval=300, ClientAliveCountMax=0",
                    affected_component="/etc/ssh/sshd_config",
                    reference="https://www.cisecurity.org/benchmark/ubuntu_linux",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.19", "CIS Ubuntu 20.04: 5.2.20"],
                    mitre_attack_ids=["T1078"],
                    tags=["ssh-hardening", "session-management"],
                )
            )

        return findings

    def _get_directives(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        ssh_data: Any = collectors.get("ssh_config")
        if not ssh_data:
            return None
        sshd_config: Any = ssh_data.get("sshd_config")
        if not sshd_config:
            return None
        directives: dict[str, Any] | None = sshd_config.get("directives")
        return directives


@register_check
class SSHBannerCheck(AuditCheck):
    id = "SSH-106"
    name = "SSH Banner"
    category = CheckCategory.SYSTEM
    severity = Severity.LOW
    description = "Checks that an SSH legal banner is configured"
    depends = ["ssh_config"]
    tags = ["ssh", "compliance", "legal"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = self._get_directives(collectors)
        if directives is None:
            return findings

        banner_path = directives.get("banner", "").strip()

        if not banner_path:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH banner not configured",
                    description="No Banner directive found in sshd_config",
                    rationale=(
                        "A legal banner provides warning to unauthorized users before login, "
                        "establishing the legal basis for monitoring. Required for PCI DSS, "
                        "SOC 2, and many compliance frameworks."
                    ),
                    remediation=(
                        "Create a banner file (e.g., /etc/ssh/banner) with an authorized "
                        "warning message, then set 'Banner /etc/ssh/banner' in sshd_config"
                    ),
                    evidence=RegistryEvidence(
                        key="Banner",
                        value="not set",
                        expected="/etc/ssh/banner or similar",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value="not set",
                    expected_value="path to banner file",
                    affected_component="/etc/ssh/sshd_config",
                    reference="https://www.cisecurity.org/benchmark/ubuntu_linux",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.16"],
                    tags=["ssh-hardening", "compliance"],
                )
            )
        elif not Path(banner_path).exists():
            findings.append(
                self.finding(
                    finding_id="002",
                    title="SSH banner file does not exist",
                    description=f"Banner is set to {banner_path!r} but the file does not exist",
                    rationale=(
                        "A configured banner that points to a non-existent file results in "
                        "an empty banner. This defeats the purpose of legal warning display."
                    ),
                    remediation=f"Create the banner file at {banner_path} with an authorized warning message",
                    evidence=RegistryEvidence(
                        key="Banner",
                        value=banner_path,
                        expected="existing file path",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value=banner_path,
                    expected_value="path to an existing file",
                    affected_component=banner_path,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.16"],
                    tags=["ssh-hardening", "compliance"],
                )
            )

        return findings

    def _get_directives(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        ssh_data: Any = collectors.get("ssh_config")
        if not ssh_data:
            return None
        sshd_config: Any = ssh_data.get("sshd_config")
        if not sshd_config:
            return None
        directives: dict[str, Any] | None = sshd_config.get("directives")
        return directives


@register_check
class SSHPermitUserEnvironmentCheck(AuditCheck):
    id = "SSH-107"
    name = "SSH PermitUserEnvironment"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that SSH PermitUserEnvironment is disabled"
    depends = ["ssh_config"]
    tags = ["ssh", "environment", "privilege-escalation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = self._get_directives(collectors)
        if directives is None:
            return findings

        value = directives.get("permituserenvironment", "").strip().lower()
        if value == "yes":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH PermitUserEnvironment is enabled",
                    description="PermitUserEnvironment is set to 'yes', allowing users to inject environment variables",
                    rationale=(
                        "PermitUserEnvironment allows users to set environment variables via "
                        "~/.ssh/environment or the Environment= directive in authorized_keys. "
                        "Attackers can use this to manipulate LD_PRELOAD, PATH, or other "
                        "variables to execute arbitrary code or escalate privileges."
                    ),
                    remediation="Set 'PermitUserEnvironment no' in /etc/ssh/sshd_config and restart sshd",
                    evidence=RegistryEvidence(
                        key="PermitUserEnvironment",
                        value=value,
                        expected="no",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value=value,
                    expected_value="no",
                    affected_component="/etc/ssh/sshd_config",
                    reference="https://www.cisecurity.org/benchmark/ubuntu_linux",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.13"],
                    mitre_attack_ids=["T1574.001"],
                    tags=["ssh-hardening", "privilege-escalation"],
                )
            )

        return findings

    def _get_directives(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        ssh_data: Any = collectors.get("ssh_config")
        if not ssh_data:
            return None
        sshd_config: Any = ssh_data.get("sshd_config")
        if not sshd_config:
            return None
        directives: dict[str, Any] | None = sshd_config.get("directives")
        return directives


@register_check
class SSHMaxStartupsCheck(AuditCheck):
    id = "SSH-108"
    name = "SSH MaxStartups"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that SSH MaxStartups is configured to limit connection rate"
    depends = ["ssh_config"]
    tags = ["ssh", "dos", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = self._get_directives(collectors)
        if directives is None:
            return findings

        value = directives.get("maxstartups", "").strip()
        if not value:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH MaxStartups not configured",
                    description="MaxStartups is not set; defaults to 10:30:100",
                    rationale=(
                        "MaxStartups controls the maximum number of concurrent unauthenticated "
                        "connections. Without explicit configuration, the default "
                        "10:30:100 may be too permissive for high-security environments, "
                        "allowing attackers to establish many parallel brute-force connections."
                    ),
                    remediation=(
                        "Set 'MaxStartups 10:30:60' or stricter in /etc/ssh/sshd_config and restart sshd. "
                        "For high-security environments: 'MaxStartups 5:30:30'"
                    ),
                    evidence=RegistryEvidence(
                        key="MaxStartups",
                        value="not set (default: 10:30:100)",
                        expected="configured value (e.g., 10:30:60)",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value="not set",
                    expected_value="explicit MaxStartups configuration",
                    affected_component="/etc/ssh/sshd_config",
                    reference="https://www.ssh.com/academy/ssh/sshd_config",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1110"],
                    tags=["ssh-hardening", "dos-prevention"],
                )
            )

        return findings

    def _get_directives(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        ssh_data: Any = collectors.get("ssh_config")
        if not ssh_data:
            return None
        sshd_config: Any = ssh_data.get("sshd_config")
        if not sshd_config:
            return None
        directives: dict[str, Any] | None = sshd_config.get("directives")
        return directives


@register_check
class SSHHostbasedAuthCheck(AuditCheck):
    id = "SSH-109"
    name = "SSH HostbasedAuthentication"
    category = CheckCategory.SYSTEM
    severity = Severity.HIGH
    description = "Checks that SSH HostbasedAuthentication is disabled"
    depends = ["ssh_config"]
    tags = ["ssh", "authentication", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = self._get_directives(collectors)
        if directives is None:
            return findings

        value = directives.get("hostbasedauthentication", "").strip().lower()
        if value == "yes":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="SSH HostbasedAuthentication is enabled",
                    description="HostbasedAuthentication is set to 'yes'",
                    rationale=(
                        "Host-based authentication relies on the source host's identity rather "
                        "than user credentials. It is inherently weaker than public-key "
                        "authentication because a compromised host can authenticate as any user. "
                        "It should only be used in tightly controlled environments."
                    ),
                    remediation="Set 'HostbasedAuthentication no' in /etc/ssh/sshd_config and restart sshd",
                    evidence=RegistryEvidence(
                        key="HostbasedAuthentication",
                        value=value,
                        expected="no",
                        source="/etc/ssh/sshd_config",
                    ),
                    detected_value=value,
                    expected_value="no",
                    affected_component="/etc/ssh/sshd_config",
                    reference="https://www.cisecurity.org/benchmark/ubuntu_linux",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.2.10"],
                    mitre_attack_ids=["T1078"],
                    tags=["ssh-hardening", "authentication"],
                )
            )

        return findings

    def _get_directives(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        ssh_data: Any = collectors.get("ssh_config")
        if not ssh_data:
            return None
        sshd_config: Any = ssh_data.get("sshd_config")
        if not sshd_config:
            return None
        directives: dict[str, Any] | None = sshd_config.get("directives")
        return directives


@register_check
class SSHCiphersCheck(AuditCheck):
    id = "SSH-202"
    name = "SSH Cipher Algorithms"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that SSH uses only strong cipher algorithms"
    depends = ["ssh_config"]
    tags = ["ssh", "cryptography", "ciphers"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        directives = self._get_directives(collectors)
        if directives is None:
            return findings

        ciphers_line = directives.get("ciphers", "").strip()
        if ciphers_line:
            configured = [c.strip() for c in ciphers_line.split(",")]
            found_weak = [c for c in configured if c in WEAK_CIPHERS]
            if found_weak:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title="Weak SSH cipher algorithms enabled",
                        description=f"Weak ciphers found: {', '.join(found_weak)}",
                        rationale=(
                            "CBC-mode ciphers are vulnerable to padding oracle attacks. "
                            "Arcfour (RC4) is a broken stream cipher with known biases. "
                            "The 'none' cipher disables encryption entirely. "
                            "Only CTR or GCM mode ciphers (AES-GCM, ChaCha20) should be used."
                        ),
                        remediation=(
                            "Remove weak ciphers from /etc/ssh/sshd_config. "
                            "Recommended: 'Ciphers chacha20-poly1305@openssh.com,"
                            "aes256-gcm@openssh.com,aes128-gcm@openssh.com'"
                        ),
                        evidence=RegistryEvidence(
                            key="Ciphers",
                            value=ciphers_line,
                            expected="strong ciphers only (no CBC, no RC4, no none)",
                            source="/etc/ssh/sshd_config",
                        ),
                        detected_value=", ".join(found_weak),
                        expected_value="No weak ciphers (chacha20-poly1305, aes*-gcm recommended)",
                        affected_component="/etc/ssh/sshd_config",
                        reference="https://www.cisecurity.org/benchmark/ubuntu_linux",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        cis_benchmarks=["CIS Ubuntu 20.04: 5.2.14"],
                        mitre_attack_ids=["T1190", "T1573"],
                        tags=["ssh-hardening", "cryptography"],
                    )
                )

        return findings

    def _get_directives(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        ssh_data: Any = collectors.get("ssh_config")
        if not ssh_data:
            return None
        sshd_config: Any = ssh_data.get("sshd_config")
        if not sshd_config:
            return None
        directives: dict[str, Any] | None = sshd_config.get("directives")
        return directives


@register_check
class SSHHostKeyTypeCheck(AuditCheck):
    id = "SSH-301"
    name = "SSH Host Key Type"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks that SSH host keys use strong algorithms"
    depends = ["ssh_config"]
    tags = ["ssh", "cryptography", "keys"]
    def _run_check(self, collectors: dict[str, Any]) -> list:
        ssh_data: Any = collectors.get("ssh_config")
        findings: list = []
        host_keys = ssh_data.get("host_keys", []) if ssh_data else []
        for key in host_keys:
            if key.get("public", False):
                continue
            kt = key.get("type", "").lower()
            path = key.get("path", "")
            if kt == "dsa":
                findings.append(self.finding(
                    finding_id="001", title=f"Deprecated DSA host key: {path}",
                    description=f"Host key at {path} uses deprecated DSA",
                    rationale="DSA is deprecated in OpenSSH 9.x.",
                    remediation=f"Generate Ed25519: ssh-keygen -t ed25519 -f {path}",
                    evidence=RegistryEvidence(key="host_key_type", value=kt, expected="ed25519/rsa", source=path),
                    detected_value=f"DSA: {path}", expected_value="Ed25519/RSA 2048+",
                    affected_component=path, confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1552.004"], tags=["ssh", "keys"],
                ))
        return findings


@register_check
class SSHAuthorizedKeysPermsCheck(AuditCheck):
    id = "SSH-302"
    name = "SSH Authorized Keys Permissions"
    category = CheckCategory.SYSTEM
    severity = Severity.HIGH
    description = "Checks authorized_keys have restricted permissions"
    depends = ["ssh_config"]
    tags = ["ssh", "keys", "permissions"]
    def _run_check(self, collectors: dict[str, Any]) -> list:
        ssh_data: Any = collectors.get("ssh_config")
        findings: list = []
        auth_dirs = ssh_data.get("authorized_keys_dirs", []) if ssh_data else []
        for entry in auth_dirs:
            perms = entry.get("permissions", "")
            user = entry.get("user", "")
            path = entry.get("path", "")
            if "0o600" in perms:
                continue
            findings.append(self.finding(
                finding_id="001", title=f"Weak authorized_keys for {user}",
                description=f"authorized_keys for '{user}' at {path} has perms {perms}",
                rationale="Must be owner-readable only.",
                remediation=f"chmod 600 {path}",
                evidence=RegistryEvidence(key=f"authk/{user}", value=perms, expected="0o600", source=path),
                detected_value=perms, expected_value="0o600",
                affected_component=path, confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1098"], tags=["ssh", "keys"],
            ))
        return findings


@register_check
class SSHLogLevelCheck(AuditCheck):
    id = "SSH-401"
    name = "SSH LogLevel"
    category = CheckCategory.SYSTEM
    severity = Severity.LOW
    description = "Checks SSH LogLevel is VERBOSE or INFO"
    depends = ["ssh_config"]
    tags = ["ssh", "logging"]
    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        d = self._get_d(collectors)
        if d is None:
            return findings
        v = d.get("loglevel", "").strip().lower()
        if v and v not in ("verbose", "info"):
            findings.append(self.finding(
                finding_id="001", title=f"SSH LogLevel is {v}",
                description=f"LogLevel is '{v}', expected VERBOSE or INFO",
                rationale="VERBOSE logs login attempts for audit trails.",
                remediation="Set 'LogLevel VERBOSE' in sshd_config",
                evidence=RegistryEvidence(key="LogLevel", value=v, expected="VERBOSE", source="/etc/ssh/sshd_config"),
                detected_value=v, expected_value="VERBOSE or INFO",
                affected_component="/etc/ssh/sshd_config", confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                tags=["ssh", "logging"],
            ))
        return findings
    def _get_d(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        s: Any = collectors.get("ssh_config")
        return None if not s else (s.get("sshd_config") or {}).get("directives")


@register_check
class SSHX11ForwardingCheck(AuditCheck):
    id = "SSH-501"
    name = "SSH X11Forwarding"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks SSH X11 forwarding is disabled"
    depends = ["ssh_config"]
    tags = ["ssh", "network", "hardening"]
    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        d = self._get_d(collectors)
        if d is None:
            return findings
        v = d.get("x11forwarding", "").strip().lower()
        if v == "yes":
            findings.append(self.finding(
                finding_id="001", title="SSH X11Forwarding enabled",
                description="X11Forwarding is 'yes'",
                rationale="X11 forwarding risks remote code exec via X11 display.",
                remediation="Set 'X11Forwarding no' in sshd_config",
                evidence=RegistryEvidence(key="X11Forwarding", value=v, expected="no", source="/etc/ssh/sshd_config"),
                detected_value=v, expected_value="no",
                affected_component="/etc/ssh/sshd_config", confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1571"], tags=["ssh", "network", "hardening"],
            ))
        return findings
    def _get_d(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        s: Any = collectors.get("ssh_config")
        return None if not s else (s.get("sshd_config") or {}).get("directives")


@register_check
class SSHTcpForwardingCheck(AuditCheck):
    id = "SSH-502"
    name = "SSH AllowTcpForwarding"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks SSH TCP forwarding is disabled"
    depends = ["ssh_config"]
    tags = ["ssh", "network", "hardening"]
    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        d = self._get_d(collectors)
        if d is None:
            return findings
        v = d.get("allowtcpforwarding", "").strip().lower()
        if v == "yes":
            findings.append(self.finding(
                finding_id="001", title="SSH AllowTcpForwarding enabled",
                description="AllowTcpForwarding is 'yes'",
                rationale="TCP forwarding bypasses firewalls. Disable on bastions.",
                remediation="Set 'AllowTcpForwarding no' in sshd_config",
                evidence=RegistryEvidence(key="AllowTcpForwarding", value=v, expected="no", source="/etc/ssh/sshd_config"),
                detected_value=v, expected_value="no",
                affected_component="/etc/ssh/sshd_config", confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1572"], tags=["ssh", "network", "hardening"],
            ))
        return findings
    def _get_d(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        s: Any = collectors.get("ssh_config")
        return None if not s else (s.get("sshd_config") or {}).get("directives")


@register_check
class SSHCompressionCheck(AuditCheck):
    id = "SSH-503"
    name = "SSH Compression"
    category = CheckCategory.SYSTEM
    severity = Severity.LOW
    description = "Checks SSH compression is not enabled"
    depends = ["ssh_config"]
    tags = ["ssh", "hardening"]
    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        d = self._get_d(collectors)
        if d is None:
            return findings
        v = d.get("compression", "").strip().lower()
        if v == "yes":
            findings.append(self.finding(
                finding_id="001", title="SSH Compression enabled",
                description="Compression is 'yes'",
                rationale="Compression can leak info via CRIME-style side channels.",
                remediation="Set 'Compression no' or 'Compression delayed' in sshd_config",
                evidence=RegistryEvidence(key="Compression", value=v, expected="no", source="/etc/ssh/sshd_config"),
                detected_value=v, expected_value="no",
                affected_component="/etc/ssh/sshd_config", confidence=Confidence.MEDIUM,
                false_positive_probability=0.1,
                tags=["ssh", "hardening"],
            ))
        return findings
    def _get_d(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        s: Any = collectors.get("ssh_config")
        return None if not s else (s.get("sshd_config") or {}).get("directives")


@register_check
class SSHPermitTunnelCheck(AuditCheck):
    id = "SSH-504"
    name = "SSH PermitTunnel"
    category = CheckCategory.SYSTEM
    severity = Severity.MEDIUM
    description = "Checks SSH tunnel device forwarding is disabled"
    depends = ["ssh_config"]
    tags = ["ssh", "network", "hardening"]
    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        d = self._get_d(collectors)
        if d is None:
            return findings
        v = d.get("permittunnel", "").strip().lower()
        if v not in ("", "no"):
            findings.append(self.finding(
                finding_id="001", title=f"SSH PermitTunnel enabled: {v}",
                description=f"PermitTunnel is '{v}'",
                rationale="Tunnel forwarding can bypass network controls.",
                remediation="Set 'PermitTunnel no' in sshd_config",
                evidence=RegistryEvidence(key="PermitTunnel", value=v, expected="no", source="/etc/ssh/sshd_config"),
                detected_value=v, expected_value="no",
                affected_component="/etc/ssh/sshd_config", confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                tags=["ssh", "network", "hardening"],
            ))
        return findings
    def _get_d(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        s: Any = collectors.get("ssh_config")
        return None if not s else (s.get("sshd_config") or {}).get("directives")


@register_check
class SSHGSSAPICheck(AuditCheck):
    id = "SSH-505"
    name = "SSH GSSAPIAuthentication"
    category = CheckCategory.SYSTEM
    severity = Severity.LOW
    description = "Checks GSSAPI auth disabled unless Kerberos needed"
    depends = ["ssh_config"]
    tags = ["ssh", "authentication", "kerberos"]
    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        d = self._get_d(collectors)
        if d is None:
            return findings
        v = d.get("gssapiauthentication", "").strip().lower()
        if v == "yes":
            findings.append(self.finding(
                finding_id="001", title="SSH GSSAPIAuthentication enabled",
                description="GSSAPIAuthentication is 'yes'",
                rationale="Disable if Kerberos not needed to reduce attack surface.",
                remediation="Set 'GSSAPIAuthentication no' in sshd_config",
                evidence=RegistryEvidence(key="GSSAPIAuthentication", value=v, expected="no", source="/etc/ssh/sshd_config"),
                detected_value=v, expected_value="no",
                affected_component="/etc/ssh/sshd_config", confidence=Confidence.LOW,
                false_positive_probability=0.3,
                tags=["ssh", "authentication", "kerberos"],
            ))
        return findings
    def _get_d(self, collectors: dict[str, Any]) -> dict[str, Any] | None:
        s: Any = collectors.get("ssh_config")
        return None if not s else (s.get("sshd_config") or {}).get("directives")
