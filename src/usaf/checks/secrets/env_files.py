from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

_SENSITIVE_ENV_KEYS: set[str] = {
    "password", "secret", "token", "key", "credential",
    "access_key", "secret_key", "api_key", "apikey",
    "auth", "passwd", "pwd",
}


@register_check
class EnvFilesCheck(AuditCheck):
    id = "SECR-202"
    name = ".env Files with Secrets"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Detects .env files containing sensitive credential information"
    depends = ["secrets"]
    tags = ["secrets", "env", "credentials", "dotenv"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "secrets")
        scanned = data.get("scanned_dirs", [])

        for home_dir in scanned:
            if not home_dir.startswith(("/home/", "/root")):
                continue
            for candidate in ("", ".env", ".env.production", ".env.dev", ".env.local"):
                fpath = Path(home_dir) / candidate
                if not fpath.is_file():
                    continue
                sensitive = self._check_env_file(str(fpath))
                if sensitive:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Sensitive keys in environment file: {fpath}",
                            description=f"File '{fpath}' contains potentially sensitive environment "
                            f"variables: {', '.join(sorted(sensitive))}",
                            rationale="Environment files commonly store secrets in plaintext. "
                            "Once exposed, these can be used to access databases, APIs, "
                            "and other services. .env files should never be committed to "
                            "version control and should have restricted permissions.",
                            remediation=f"Review {fpath} and move secrets to a secrets manager. "
                            "Set file permissions to 600 (owner-read-only). "
                            "Add .env to .gitignore if not already present.",
                            evidence=FileEvidence(
                                path=str(fpath),
                                content=f"Sensitive keys: {', '.join(sorted(sensitive))}",
                                permission=oct(os.stat(str(fpath)).st_mode),
                                size=fpath.stat().st_size,
                            ),
                            detected_value=f"Sensitive keys present: {', '.join(sorted(sensitive))}",
                            expected_value="No sensitive keys in .env files",
                            affected_component=str(fpath),
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.15,
                            mitre_attack_ids=["T1552.001"],
                            tags=["env", "dotenv", "credentials"],
                        )
                    )
        return findings

    @staticmethod
    def _check_env_file(path: str) -> set[str]:
        sensitive: set[str] = set()
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key = line.split("=", 1)[0].strip().lower()
                    val = line.split("=", 1)[1].strip().strip("\"'")
                    if not val or val in ("", "''", '""'):
                        continue
                    if any(s in key for s in _SENSITIVE_ENV_KEYS):
                        sensitive.add(key)
        except OSError:
            pass
        return sensitive
