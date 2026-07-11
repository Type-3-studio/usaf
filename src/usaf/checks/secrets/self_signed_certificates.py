from __future__ import annotations

import re
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class SelfSignedCertificatesCheck(AuditCheck):
    id = "SECR-502"
    name = "Self-Signed TLS/SSL Certificates"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Detects self-signed certificates in the system certificate store or config dirs"
    depends = ["certificates"]
    tags = ["secrets", "certificates", "tls", "self-signed"]

    _SYSTEM_CA_PREFIXES: tuple[str, ...] = (
        "/etc/ssl/certs/",
        "/usr/share/ca-certificates/",
    )

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        cert_data = self._get_data(collectors, "certificates")
        all_certs: list[str] = []

        for bundle in cert_data.get("ca_bundles", []):
            all_certs.append(bundle.get("path", ""))

        for pem in cert_data.get("system_certs", {}).get("pem_files", []):
            all_certs.append(pem.get("path", ""))

        seen_paths: set[str] = set()
        for cpath in all_certs:
            if cpath in seen_paths:
                continue
            seen_paths.add(cpath)
            if not cpath:
                continue
            if cpath.startswith(self._SYSTEM_CA_PREFIXES):
                continue
            result = self._check_self_signed(cpath)
            if result is not None:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Self-signed certificate: {cpath}",
                        description=f"Certificate '{cpath}' is self-signed (issuer == subject: {result}). "
                        "Self-signed certificates cannot be verified by clients and indicate "
                        "either a development/staging environment or a man-in-the-middle proxy.",
                        rationale="Self-signed certificates provide encryption but no authentication. "
                        "In production, they enable man-in-the-middle attacks since clients "
                        "cannot verify the server identity. They are acceptable in dev/test "
                        "but should be flagged for review in production environments.",
                        remediation="Replace the self-signed certificate with one from a trusted CA "
                        f"(e.g., Let's Encrypt via certbot). Certificate: {cpath}",
                        evidence=FileEvidence(
                            path=cpath,
                            content=f"Subject/Issuer: {result}",
                        ),
                        detected_value="Self-signed certificate detected",
                        expected_value="CA-signed certificate",
                        affected_component=cpath,
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1588.003", "T1574"],
                        tags=["certificates", "tls", "self-signed", "dev-prod"],
                    )
                )
        return findings

    @staticmethod
    def _check_self_signed(path: str) -> str | None:
        import subprocess
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", path, "-noout", "-subject", "-issuer"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return None
            output = result.stdout.strip()
            subject = ""
            issuer = ""
            for line in output.splitlines():
                if line.startswith("subject="):
                    subject = line[8:]
                elif line.startswith("issuer="):
                    issuer = line[7:]
            if subject and subject == issuer:
                return subject
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None
