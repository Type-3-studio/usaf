from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class ExposedSSHPrivateKeysCheck(AuditCheck):
    id = "SECR-301"
    name = "Exposed SSH Private Keys"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects SSH private keys with world-readable permissions or in unexpected locations"
    depends = ["ssh_config"]
    tags = ["secrets", "ssh", "keys", "credentials"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ssh_data = self._get_data(collectors, "ssh_config")
        host_keys = ssh_data.get("host_keys", [])

        for key in host_keys:
            if key.get("public", False):
                continue
            path = key.get("path", "")
            key_type = key.get("type", "unknown")
            size = key.get("size", 0)
            perm_str = self._get_permission(path)

            if perm_str and perm_str not in ("0o600", "0o700", "0o400", "0o500", "0o000"):
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"SSH private key has weak permissions: {path}",
                        description=f"SSH private key '{path}' ({key_type}, {size} bytes) has permissions "
                        f"{perm_str}. Private keys must be readable only by the owner.",
                        rationale="SSH private keys with weak permissions can be read by other users "
                        "on the system, enabling lateral movement, privilege escalation, "
                        "and access to connected systems.",
                        remediation=f"Fix permissions: chmod 600 '{path}'. "
                        f"If the key was exposed, rotate it on all systems where it was used.",
                        evidence=FileEvidence(
                            path=path,
                            permission=perm_str,
                            size=size,
                            content=f"Key type: {key_type}",
                        ),
                        detected_value=f"Permissions: {perm_str}",
                        expected_value="Permissions: 600 (owner read/write only)",
                        affected_component=path,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.02,
                        mitre_attack_ids=["T1552.004", "T1558.001"],
                        tags=["ssh", "private-key", "credentials", "privilege-escalation"],
                    )
                )

            name = key.get("name", "").lower()
            if key_type == "dsa" or name.endswith("_dsa_key") or name.endswith("_dsa_key.pub"):
                findings.append(
                    self.finding(
                        finding_id="002",
                        title=f"Deprecated DSA SSH key in use: {path}",
                        description=f"SSH key '{path}' uses the DSA algorithm, which is deprecated "
                        f"and considered insecure ({size} bytes).",
                        rationale="DSA SSH keys are deprecated due to known weaknesses. "
                        "OpenSSH 9.x has disabled DSA by default.",
                        remediation=f"Generate a new Ed25519 key: ssh-keygen -t ed25519 -f '{path.replace('_dsa', '_ed25519')}'"
                        f". Replace the public key on all target systems.",
                        evidence=FileEvidence(
                            path=path,
                            content=f"Key type: DSA, size: {size} bytes",
                            permission=self._get_permission(path),
                        ),
                        detected_value="DSA key in use",
                        expected_value="Ed25519 or RSA (2048+ bit) key",
                        affected_component=path,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.01,
                        mitre_attack_ids=["T1552.004"],
                        tags=["ssh", "deprecated-algorithm", "dsa"],
                    )
                )
        return findings

    @staticmethod
    def _get_permission(path: str) -> str | None:
        import os
        try:
            mode = os.stat(path).st_mode
            return oct(mode & 0o7777)
        except OSError:
            return None
