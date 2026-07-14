from __future__ import annotations

import base64
import os
from struct import unpack
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class WeakSSHKeysCheck(AuditCheck):
    id = "SECR-302"
    name = "Weak SSH Key Algorithms and Sizes"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Identifies SSH keys using weak or deprecated algorithms (DSA, 1024-bit RSA)"
    depends = ["ssh_config"]
    tags = ["secrets", "ssh", "keys", "cryptography"]

    _WEAK_TYPES = {"dsa"}
    _MIN_RSA_BITS = 2048

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ssh_data = self._get_data(collectors, "ssh_config")
        host_keys = ssh_data.get("host_keys", [])

        for key in host_keys:
            path = key.get("path", "")
            key_type = key.get("type", "unknown")
            size = key.get("size", 0)
            name = key.get("name", "").lower()

            if key_type in self._WEAK_TYPES:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Weak SSH key algorithm: {name}",
                        description=f"SSH host key '{path}' uses the {key_type.upper()} algorithm, "
                        f"which is deprecated and insecure ({size} bytes).",
                        rationale=f"{key_type.upper()} is deprecated in OpenSSH due to fundamental "
                        f"cryptographic weaknesses. Attackers can forge {key_type.upper()} signatures.",
                        remediation=f"Generate a stronger Ed25519 key: "
                        f"ssh-keygen -t ed25519 -f {path.replace(name, name.replace(key_type, 'ed25519'))}. "
                        f"Update sshd_config HostKey directive and remove the weak key.",
                        evidence=FileEvidence(
                            path=path,
                            content=f"Key type: {key_type}, size: {size} bytes",
                            permission=oct(os.stat(path).st_mode) if os.path.isfile(path) else None,
                        ),
                        detected_value=f"{key_type.upper()} SSH key",
                        expected_value="Ed25519 or RSA 2048+ bit key",
                        affected_component=path,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.01,
                        mitre_attack_ids=["T1552.004"],
                        tags=["ssh", "weak-keys", "cryptography"],
                    )
                )

            if key_type == "rsa" and size > 0 and os.path.isfile(path):
                bits = self._get_rsa_key_size(path)
                if bits is not None and bits < self._MIN_RSA_BITS:
                    findings.append(
                        self.finding(
                            finding_id="002",
                            title=f"Weak RSA key size: {bits} bits",
                            description=f"SSH host key '{path}' uses RSA with only {bits} bits. "
                            f"Minimum recommended is {self._MIN_RSA_BITS} bits.",
                            rationale=f"RSA keys with fewer than {self._MIN_RSA_BITS} bits can be factored "
                            f"by determined attackers using modern hardware and algorithms.",
                            remediation=f"Generate a new Ed25519 key or RSA {self._MIN_RSA_BITS}+ bit key: "
                            f"ssh-keygen -t ed25519 -f {path.replace(key.get('name', ''), 'ssh_host_ed25519_key')}. "
                            f"Update sshd_config and remove the weak key.",
                            evidence=FileEvidence(
                                path=path,
                                content=f"RSA key size: {bits} bits",
                                permission=oct(os.stat(path).st_mode) if os.path.isfile(path) else None,
                            ),
                            detected_value=f"RSA {bits}-bit key",
                            expected_value=f"RSA {self._MIN_RSA_BITS}+ bit or Ed25519 key",
                            affected_component=path,
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.05,
                            mitre_attack_ids=["T1552.004"],
                            tags=["ssh", "weak-keys", "rsa", "cryptography"],
                        )
                    )
        return findings

    @staticmethod
    def _get_rsa_key_size(path: str) -> int | None:
        try:
            with open(path) as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if line.startswith("-----BEGIN") and "PRIVATE KEY" in line:
                        continue
                    if line.startswith("AAAA"):
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                decoded = base64.b64decode(parts[1])
                                pos = 0
                                while pos < len(decoded):
                                    if pos + 4 > len(decoded):
                                        break
                                    chunk_len = unpack(">I", decoded[pos:pos + 4])[0]
                                    pos += 4
                                    if pos + chunk_len > len(decoded):
                                        break
                                    pos += chunk_len
                                return 0
                            except Exception:
                                pass
                    break
        except (OSError, UnicodeDecodeError):
            pass

        try:
            result = os.popen(f"ssh-keygen -l -f '{path}' 2>/dev/null").read()
            if result:
                parts = result.strip().split()
                if len(parts) >= 1:
                    try:
                        return int(parts[0])
                    except ValueError:
                        pass
        except Exception:
            pass
        return None
