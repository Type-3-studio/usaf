from __future__ import annotations

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class UnauthorizedServicesCheck(AuditCheck):
    id = "PER-001"
    name = "Suspicious Systemd Services"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Checks for systemd services with suspicious names or descriptions that may indicate persistence mechanisms"
    depends = ["systemd"]
    tags = ["persistence", "systemd", "backdoor"]

    SUSPICIOUS_PATTERNS = [
        "backdoor",
        "reverse",
        "miner",
        "crypto",
        "shell",
        "meterp",
        "beacon",
        "implant",
        "proxy",
    ]

    BENIGN_SERVICES = {
        "switcheroo-control.service",
    }

    def _run_check(self, collectors: dict) -> list:
        sysd_data = self._get_data(collectors, "systemd")
        services = sysd_data.get("services", [])
        findings = []

        for svc in services:
            name = svc.get("name", "")
            desc = svc.get("description", "").lower()
            if not svc.get("active") or svc.get("active") == "inactive":
                continue
            if name in self.BENIGN_SERVICES:
                continue
            if name.startswith("snap."):
                continue
            matched = [p for p in self.SUSPICIOUS_PATTERNS if p in name.lower() or p in desc]
            if not matched:
                continue
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Suspicious service detected: {name}",
                    description=f"Service '{name}' matches suspicious patterns: {', '.join(matched)}",
                    rationale=(
                        "Attackers frequently create systemd services for persistence after "
                        "gaining initial access. Names containing suspicious terms (backdoor, "
                        "reverse, miner, shell) or mimicking legitimate services are strong "
                        "indicators of malicious persistence. Each such service should be vetted."
                    ),
                    remediation=(
                        f"Investigate: 'systemctl cat {name}' and "
                        f"'systemctl status {name}'. "
                        f"Disable if unauthorized: "
                        f"'systemctl disable --now {name}' and "
                        f"remove the unit file."
                    ),
                evidence=FileEvidence(
                    path=f"/etc/systemd/system/{name}",
                    content=svc.get("description", ""),
                ),
                detected_value=f"Active service '{name}' with suspicious patterns",
                expected_value="No active services matching suspicious patterns",
                affected_component=f"systemd: {name}",
                reference="https://attack.mitre.org/techniques/T1543/002/",
                confidence=Confidence.LOW,
                    false_positive_probability=0.6,
                    mitre_attack_ids=["T1543.002"],
                    tags=["persistence", "systemd", "backdoor"],
                )
            )
        return findings
