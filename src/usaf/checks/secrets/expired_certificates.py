from __future__ import annotations

import datetime
import re
import subprocess
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class ExpiredCertificatesCheck(AuditCheck):
    id = "SECR-501"
    name = "Expired TLS/SSL Certificates"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Detects expired TLS/SSL certificates in the system certificate store"
    depends = ["certificates"]
    tags = ["secrets", "certificates", "tls", "expiry"]

    _PEM_START = re.compile(r"-----BEGIN CERTIFICATE-----")
    _PEM_END = re.compile(r"-----END CERTIFICATE-----")

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
            expired = self._check_expired(cpath)
            if expired is not None:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Expired certificate: {cpath}",
                        description=f"Certificate '{cpath}' expired on {expired['not_after']}. "
                        f"Issuer: {expired['issuer']}, Subject: {expired['subject']}",
                        rationale="Expired certificates cause TLS connection failures, "
                        "service disruptions, and may indicate neglected infrastructure. "
                        "Services using expired certs cannot be verified by clients.",
                        remediation=f"Renew the certificate for '{expired['subject']}'. "
                        f"If using Let's Encrypt: certbot renew. "
                        f"If using a commercial CA: regenerate CSR and reissue. "
                        f"Certificate: {cpath}",
                        evidence=FileEvidence(
                            path=cpath,
                            content=f"Issuer: {expired['issuer']}, "
                            f"Subject: {expired['subject']}, "
                            f"Expired: {expired['not_after']}",
                        ),
                        detected_value=f"Expired since {expired['not_after']}",
                        expected_value="Certificate valid (notAfter > now)",
                        affected_component=cpath,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.01,
                        mitre_attack_ids=["T1588.003", "T1574"],
                        tags=["certificates", "tls", "expiry"],
                    )
                )
        return findings

    @staticmethod
    def _check_expired(path: str) -> dict[str, str] | None:
        try:
            result = subprocess.run(
                ["openssl", "x509", "-in", path, "-noout",
                 "-subject", "-issuer", "-enddate"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode != 0:
                return None
            output = result.stdout
            subject = ""
            issuer = ""
            not_after_str = ""
            for line in output.splitlines():
                if line.startswith("subject="):
                    subject = line[8:]
                elif line.startswith("issuer="):
                    issuer = line[7:]
                elif line.startswith("notAfter="):
                    not_after_str = line[9:]

            if not not_after_str:
                return None

            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
                try:
                    not_after = datetime.datetime.strptime(not_after_str.strip(), fmt)
                    if not_after.tzinfo is None:
                        not_after = not_after.replace(tzinfo=datetime.UTC)
                    if not_after < datetime.datetime.now(datetime.UTC):
                        return {
                            "subject": subject,
                            "issuer": issuer,
                            "not_after": not_after.isoformat(),
                        }
                    return None
                except ValueError:
                    continue
        except (OSError, subprocess.TimeoutExpired):
            pass
        return None
