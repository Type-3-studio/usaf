from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class APIKeysCheck(AuditCheck):
    id = "SECR-203"
    name = "Hardcoded API Keys and Tokens"
    category = CheckCategory.SECURITY
    severity = Severity.HIGH
    description = "Detects hardcoded API keys, tokens, and secrets in config and source files"
    depends = ["secrets"]
    tags = ["secrets", "api-keys", "tokens", "credentials"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "secrets")
        matches = data.get("api_keys", [])
        seen_paths: set[str] = set()

        for m in matches:
            p = m.get("path", "")
            if p in seen_paths:
                continue
            seen_paths.add(p)
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Hardcoded API key in {p}",
                    description=f"File '{p}' contains an API key or token at line {m.get('line', '?')}. "
                    f"Match: {m.get('match', '')}",
                    rationale="Hardcoded API keys allow unauthorized access to third-party services. "
                    "They can be discovered through source code leaks, CI/CD log exposure, "
                    "or filesystem compromise.",
                    remediation="Remove the hardcoded API key and use environment variables "
                    "or a secrets manager. Rotate the exposed key immediately. "
                    f"File: {p}",
                    evidence=FileEvidence(
                        path=p,
                        line=m.get("line"),
                        content=f"Match: {m.get('match', '')}",
                        permission=m.get("permission"),
                        owner=m.get("owner"),
                        size=m.get("size"),
                    ),
                    detected_value="Hardcoded API key detected",
                    expected_value="No hardcoded API keys in files",
                    affected_component=p,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1552.001"],
                    tags=["api-keys", "credentials", "hardcoded-secrets"],
                )
            )
        return findings
