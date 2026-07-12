from __future__ import annotations

import subprocess
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import CommandEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class FirewallServiceBootCheck(AuditCheck):
    id = "FW-209"
    name = "Firewall Service Boot Persistence"
    category = CheckCategory.SECURITY
    severity = Severity.MEDIUM
    description = "Checks that firewall service is enabled to start at boot"
    depends = []
    tags = ["firewall", "boot", "persistence", "hardening"]

    FW_SERVICES: list[str] = ["ufw", "nftables", "iptables"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []

        for svc in self.FW_SERVICES:
            try:
                result = subprocess.run(
                    ["systemctl", "is-enabled", svc],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if result.stdout.strip() == "enabled":
                    return findings
            except (OSError, subprocess.SubprocessError):
                pass

        try:
            result = subprocess.run(
                ["systemctl", "is-enabled", "ufw"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if result.stdout.strip() == "enabled":
                return findings
        except (OSError, subprocess.SubprocessError):
            pass

        findings.append(
            self.finding(
                finding_id="001",
                title="No firewall service enabled at boot",
                description="No firewall service (ufw, nftables) is enabled to start at boot.",
                rationale="Without a firewall enabled at boot, the system is unprotected from network attacks immediately after startup and until the firewall is manually started.",
                remediation="Enable firewall: 'ufw enable' or 'systemctl enable nftables'.",
                evidence=CommandEvidence(
                    command="systemctl is-enabled ufw nftables",
                    stdout="disabled or not found",
                    exit_code=1,
                ),
                detected_value="No firewall service enabled",
                expected_value="Firewall enabled at boot",
                affected_component="Firewall service",
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1562"],
                tags=["firewall", "boot", "persistence", "hardening"],
            )
        )
        return findings
