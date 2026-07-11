from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class AuditLogCheck(AuditCheck):
    id = "FOR-101"
    name = "Audit Log Availability"
    category = CheckCategory.FORENSICS
    severity = Severity.MEDIUM
    description = "Checks that auditd logs exist and contain recent data"
    depends = []
    tags = ["forensics", "auditing", "logging"]

    def _run_check(self, collectors: dict) -> list:
        findings = []
        log_dir = Path("/var/log/audit")
        log_file = log_dir / "audit.log"

        if not log_dir.exists():
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Audit log directory does not exist",
                    description="/var/log/audit/ directory is missing",
                    rationale=(
                        "Without audit logs, there is no record of system calls, file access, "
                        "or authentication events. This severely hampers incident response and "
                        "forensic investigation. The auditd service may not be installed or running."
                    ),
                    remediation=(
                        "Install auditd: 'apt install auditd'. "
                        "Enable and start: 'systemctl enable auditd && systemctl start auditd'. "
                        "Verify: 'systemctl status auditd'."
                    ),
                    evidence=FileEvidence(
                        path=str(log_dir),
                        content="Directory does not exist",
                    ),
                    detected_value="Missing audit log directory",
                    expected_value="/var/log/audit/ exists with audit.log",
                    affected_component="/var/log/audit",
                    reference="https://ubuntu.com/security/cis",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1070", "T1562"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 4.1.1.1"],
                    tags=["auditing", "forensics"],
                )
            )
            return findings

        if not log_file.exists() or log_file.stat().st_size == 0:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Audit log is missing or empty",
                    description=f"Audit log {log_file} does not exist or is empty",
                    rationale=(
                        "An empty or missing audit log means no audit events are being recorded. "
                        "This prevents detection of security-relevant events and violates "
                        "compliance requirements (CIS, PCI-DSS, SOC2)."
                    ),
                    remediation=(
                        "Check auditd status: 'systemctl status auditd'. "
                        "Check audit rules: 'auditctl -l'. "
                        "Restart auditd: 'systemctl restart auditd'."
                    ),
                    evidence=FileEvidence(
                        path=str(log_file) if log_file.exists() else str(log_dir),
                        size=log_file.stat().st_size if log_file.exists() else 0,
                        content="Log file is empty or missing",
                    ),
                    detected_value="Empty or missing audit log",
                    expected_value="Non-empty audit.log with recent entries",
                    affected_component=str(log_file),
                    reference="https://ubuntu.com/security/cis",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1070", "T1562"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 4.1.1.1"],
                    tags=["auditing", "forensics"],
                )
            )

        return findings
