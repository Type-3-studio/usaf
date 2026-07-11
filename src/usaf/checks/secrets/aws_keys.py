from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class AWSKeysCheck(AuditCheck):
    id = "SECR-101"
    name = "AWS Access Keys in Filesystem"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects AWS access key IDs and secret access keys stored in files"
    depends = ["secrets"]
    tags = ["secrets", "aws", "credentials", "cloud"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "secrets")
        matches = data.get("aws_keys", [])
        seen_paths: set[str] = set()

        for m in matches:
            p = m.get("path", "")
            if p in seen_paths:
                continue
            seen_paths.add(p)
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"AWS credential material found in {p}",
                    description=f"File '{p}' contains AWS access key or secret key at line {m.get('line', '?')}. "
                    f"Match: {m.get('match', '')}",
                    rationale="AWS credentials in files allow attackers to access cloud resources. "
                    "They should be stored in secrets managers or environment variables, "
                    "never committed to code or stored in config files.",
                    remediation="Remove credentials from file. Use AWS IAM roles, "
                    "AWS Secrets Manager, or environment variables instead. "
                    f"File: {p}",
                    evidence=FileEvidence(
                        path=p,
                        line=m.get("line"),
                        content=f"Match: {m.get('match', '')}",
                        permission=m.get("permission"),
                        owner=m.get("owner"),
                        size=m.get("size"),
                    ),
                    detected_value="AWS credential material present",
                    expected_value="No AWS credentials in filesystem",
                    affected_component=p,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1552.001", "T1525"],
                    tags=["aws", "credentials", "cloud"],
                )
            )
        return findings
