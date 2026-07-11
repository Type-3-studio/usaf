from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class GitHubTokensCheck(AuditCheck):
    id = "SECR-201"
    name = "GitHub Tokens in Filesystem"
    category = CheckCategory.SECURITY
    severity = Severity.CRITICAL
    description = "Detects GitHub personal access tokens, OAuth tokens, and installation tokens in files"
    depends = ["secrets"]
    tags = ["secrets", "github", "tokens", "credentials"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "secrets")
        matches = data.get("github_tokens", [])
        seen_paths: set[str] = set()

        for m in matches:
            p = m.get("path", "")
            if p in seen_paths:
                continue
            seen_paths.add(p)
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"GitHub token found in {p}",
                    description=f"File '{p}' contains a GitHub token at line {m.get('line', '?')}. "
                    f"Match prefix: {m.get('match', '')[:20]}...",
                    rationale="GitHub tokens grant access to repositories, actions, packages, "
                    "and other GitHub resources. Exposed tokens can lead to code theft, "
                    "supply chain attacks, and infrastructure compromise.",
                    remediation="Revoke the compromised token at https://github.com/settings/tokens "
                    "and remove it from the file. Use GitHub Actions secrets or environment "
                    "variables instead of storing tokens in files. "
                    f"File: {p}",
                    evidence=FileEvidence(
                        path=p,
                        line=m.get("line"),
                        content=f"Token prefix: {m.get('match', '')[:20]}...",
                        permission=m.get("permission"),
                        owner=m.get("owner"),
                        size=m.get("size"),
                    ),
                    detected_value="GitHub token present",
                    expected_value="No GitHub tokens in filesystem",
                    affected_component=p,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1552.001", "T1552.004"],
                    tags=["github", "tokens", "credentials", "scm"],
                )
            )
        return findings
