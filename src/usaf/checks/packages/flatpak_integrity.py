from __future__ import annotations

from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

FLATPAK_BASE = Path("/var/lib/flatpak")


@register_check
class FlatpakIntegrityCheck(AuditCheck):
    id = "PKG-210"
    name = "Flatpak Deployment Integrity"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Verifies that installed Flatpak apps and runtimes have valid, intact deployments"
    depends = ["flatpak"]
    tags = ["packages", "flatpak", "integrity"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        flatpak_data = self._get_data(collectors, "flatpak")
        installed = flatpak_data.get("installed", [])

        if not installed:
            return findings

        for app in installed:
            app_id = app.get("id", "")
            kind = app.get("kind", "app")
            arch = app.get("arch", "")
            branch = app.get("branch", "")
            active_commit = app.get("active_commit", "")

            deploy_dir = FLATPAK_BASE / kind / app_id / arch / branch / active_commit / "files"
            metadata_file = FLATPAK_BASE / kind / app_id / arch / branch / active_commit / "metadata"

            issues: list[str] = []

            if not active_commit:
                issues.append("No active commit set")
            else:
                if not deploy_dir.is_dir():
                    issues.append(f"Deploy directory missing: {deploy_dir}")
                if not metadata_file.is_file():
                    issues.append(f"Metadata file missing: {metadata_file}")

            active_file = FLATPAK_BASE / kind / app_id / arch / branch / "active"
            if not active_file.is_file():
                issues.append("Active pointer file missing")

            if issues:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Flatpak {kind} '{app_id}' has deployment issues",
                        description=f"Flatpak {kind} '{app_id}' ({arch}/{branch}) has {len(issues)} issue(s): {'; '.join(issues)}",
                        rationale="Flatpak deployments with missing files or metadata may indicate tampering, "
                        "incomplete installations, or filesystem corruption. Attackers could replace flatpak "
                        "binaries by modifying deploy directories.",
                        remediation=f"Reinstall the flatpak: 'flatpak uninstall {app_id} && flatpak install {app_id}'. "
                        f"Verify the flatpak directory integrity at {FLATPAK_BASE / kind / app_id}.",
                        evidence=RegistryEvidence(
                            key=f"flatpak:{kind}:{app_id}",
                            value="; ".join(issues),
                            expected="Valid active deployment with files and metadata",
                            source=str(FLATPAK_BASE / kind / app_id),
                        ),
                        detected_value=f"Deployment issues: {'; '.join(issues)}",
                        expected_value="Valid deployment",
                        affected_component=f"flatpak/{kind}/{app_id}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1070.004", "T1036"],
                        tags=["flatpak", "deployment-integrity"],
                    )
                )
        return findings
