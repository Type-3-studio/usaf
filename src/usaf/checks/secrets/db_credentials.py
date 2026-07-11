from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class DBCredentialsCheck(AuditCheck):
    id = "SECR-401"
    name = "Database Credentials in Configuration Files"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects database connection strings and credentials in world-readable files"
    depends = ["secrets"]
    tags = ["secrets", "database", "credentials", "configuration"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "secrets")
        matches = data.get("db_credentials", [])
        seen_paths: set[str] = set()

        for m in matches:
            p = m.get("path", "")
            if p in seen_paths:
                continue
            seen_paths.add(p)
            perm = m.get("permission", "")
            if perm and perm.endswith(("666", "644", "777", "755")):
                severity = Severity.CRITICAL
                fp_prob = 0.1
            else:
                severity = Severity.HIGH
                fp_prob = 0.15

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Database credentials in file: {p}",
                    description=f"File '{p}' contains database connection credentials at line "
                    f"{m.get('line', '?')}. Match: {m.get('match', '')}",
                    rationale="Database credentials in configuration files allow attackers to "
                    "access backend databases, exfiltrate data, and potentially gain "
                    "access to other systems through shared credentials.",
                    remediation="Move database credentials to environment variables or a "
                    "secrets manager. Set file permissions to 600. Rotate the exposed "
                    f"credentials immediately. File: {p}",
                    evidence=FileEvidence(
                        path=p,
                        line=m.get("line"),
                        content=f"Match: {m.get('match', '')}",
                        permission=perm,
                        owner=m.get("owner"),
                        size=m.get("size"),
                    ),
                    detected_value="Database credentials present in file",
                    expected_value="No database credentials in config files",
                    affected_component=p,
                    confidence=Confidence.HIGH,
                    false_positive_probability=fp_prob,
                    mitre_attack_ids=["T1552.001", "T1552.005", "T1505"],
                    tags=["database", "credentials", "configuration"],
                )
            )
        return findings
