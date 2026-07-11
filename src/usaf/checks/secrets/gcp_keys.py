from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class GCPKeysCheck(AuditCheck):
    id = "SECR-102"
    name = "GCP Service Account Keys in Filesystem"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects GCP service account JSON key files in the filesystem"
    depends = ["secrets"]
    tags = ["secrets", "gcp", "credentials", "cloud"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "secrets")
        matches = data.get("gcp_keys", [])
        seen_paths: set[str] = set()

        for m in matches:
            p = m.get("path", "")
            if p in seen_paths:
                continue
            seen_paths.add(p)
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"GCP service account key file found: {p}",
                    description=f"File '{p}' contains GCP service account credentials at line {m.get('line', '?')}. "
                    f"Match: {m.get('match', '')}",
                    rationale="GCP service account keys grant programmatic access to Google Cloud resources. "
                    "If exposed, attackers can access cloud storage, compute, and IAM resources. "
                    "Use workload identity federation or attach service accounts to compute resources instead.",
                    remediation="Remove the service account key file. Use GCP Workload Identity Federation "
                    "or attach the service account to the compute resource directly. "
                    "If a key is truly needed, rotate it immediately and store in a secrets manager. "
                    f"File: {p}",
                    evidence=FileEvidence(
                        path=p,
                        line=m.get("line"),
                        content=f"Match: {m.get('match', '')}",
                        permission=m.get("permission"),
                        owner=m.get("owner"),
                        size=m.get("size"),
                    ),
                    detected_value="GCP service account key present",
                    expected_value="No GCP service account keys in filesystem",
                    affected_component=p,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1552.001", "T1525"],
                    tags=["gcp", "credentials", "cloud", "service-account"],
                )
            )
        return findings
