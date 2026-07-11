from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class InsecureServicesCheck(AuditCheck):
    id = "SVC-101"
    name = "Legacy Insecure Services"
    category = CheckCategory.SERVICES
    severity = Severity.HIGH
    description = "Checks for legacy insecure network services that should be replaced with modern alternatives"
    depends = []
    tags = ["services", "legacy", "cryptography"]

    INSECURE_SERVICES = {
        "telnet.socket": "Telnet (use SSH instead)",
        "telnet.service": "Telnet (use SSH instead)",
        "rsh.socket": "Rsh (use SSH instead)",
        "rlogin.socket": "Rlogin (use SSH instead)",
        "rsh.service": "Rsh (use SSH instead)",
        "rlogin.service": "Rlogin (use SSH instead)",
        "tftp.socket": "TFTP (unauthenticated file transfer)",
        "tftp.service": "TFTP (unauthenticated file transfer)",
        "vsftpd.service": "FTP (use SFTP or SCP instead)",
        "proftpd.service": "FTP (use SFTP or SCP instead)",
        "pure-ftpd.service": "FTP (use SFTP or SCP instead)",
    }

    def _run_check(self, collectors: dict) -> list:
        findings = []
        search_dirs = [
            Path("/etc/systemd/system"),
            Path("/lib/systemd/system"),
            Path("/run/systemd/system"),
        ]
        for unit, reason in self.INSECURE_SERVICES.items():
            found = False
            for sd in search_dirs:
                if (sd / unit).exists():
                    found = True
                    break
            if not found:
                continue
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Insecure service unit found: {unit}",
                    description=f"The legacy service '{unit}' is installed ({reason})",
                    rationale=(
                        "Legacy services like telnet, rsh, rlogin, and FTP transmit credentials "
                        "and data in cleartext. Attackers on the network can capture passwords, "
                        "session tokens, and data. These protocols also lack modern authentication "
                        "features and integrity checks."
                    ),
                    remediation=(
                        f"Disable and stop: 'systemctl disable --now {unit}'. "
                        f"Remove the associated package: 'apt purge <package>'."
                    ),
                    evidence=FileEvidence(
                        path=str(search_dirs[0] / unit),
                        content=f"Legacy service: {reason}",
                    ),
                    detected_value=f"Unit file present for {unit}",
                    expected_value=f"No unit file for {unit}",
                    affected_component=unit,
                    reference="https://ubuntu.com/security/cis",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1071"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 2.1"],
                    tags=["legacy-services", "cryptography", "hardening"],
                )
            )
        return findings
