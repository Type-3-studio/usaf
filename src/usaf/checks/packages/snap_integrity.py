from __future__ import annotations

from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Confidence, Severity

SNAP_DIR = Path("/snap")


@register_check
class SnapIntegrityCheck(AuditCheck):
    id = "PKG-310"
    name = "Snap Deployment Integrity"
    category = CheckCategory.PACKAGES
    severity = Severity.MEDIUM
    description = "Verifies that installed snaps have valid, intact mount points and revisions"
    depends = ["snap"]
    tags = ["packages", "snap", "integrity"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        snap_data = self._get_data(collectors, "snap")
        installed = snap_data.get("installed", [])

        if not installed:
            return findings

        for snap in installed:
            snap_name = snap.get("name", "")
            current_revision = snap.get("current_revision", "")
            revisions_str = snap.get("revisions", "")
            revisions = [r for r in revisions_str.split(",") if r]

            issues: list[str] = []

            snap_path = SNAP_DIR / snap_name
            if not snap_path.is_dir():
                issues.append(f"Snap directory missing: {snap_path}")
                findings.append(self._make_finding(snap_name, issues))
                continue

            current_link = snap_path / "current"
            if not current_link.is_symlink():
                issues.append("No 'current' symlink")
            else:
                target = current_link.resolve()
                if not target.is_dir():
                    issues.append(f"Current revision directory missing: {target}")

            if current_revision and current_revision not in revisions:
                issues.append(
                    f"Current revision '{current_revision}' not found in revision list"
                )

            if issues:
                findings.append(self._make_finding(snap_name, issues))

        return findings

    def _make_finding(self, snap_name: str, issues: list[str]) -> Finding:
        return self.finding(
            finding_id="001",
            title=f"Snap '{snap_name}' has deployment issues",
            description=f"Snap '{snap_name}' has {len(issues)} issue(s): {'; '.join(issues)}",
            rationale="Snap deployments with missing directories or broken symlinks may indicate "
            "tampering, corruption, or incomplete updates. Attackers could replace snap binaries "
            "by modifying snap mount paths.",
            remediation=f"Reinstall the snap: 'snap remove {snap_name} && snap install {snap_name}'. "
            f"Verify the snap directory at /snap/{snap_name}.",
            evidence=RegistryEvidence(
                key=f"snap:{snap_name}",
                value="; ".join(issues),
                expected="Valid active snap with current revision directory",
                source=f"/snap/{snap_name}",
            ),
            detected_value=f"Deployment issues: {'; '.join(issues)}",
            expected_value="Valid deployment",
            affected_component=f"snap/{snap_name}",
            confidence=Confidence.HIGH,
            false_positive_probability=0.05,
            mitre_attack_ids=["T1070.004", "T1036"],
            tags=["snap", "deployment-integrity"],
        )
