from __future__ import annotations

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import CommandEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class FirewallActiveCheck(AuditCheck):
    """Check that a firewall (ufw/nftables/iptables) is active."""

    id = "FIREWALL-001"
    name = "Firewall Active"
    category = CheckCategory.NETWORK
    severity = Severity.HIGH
    description = "Checks that a host-based firewall (UFW, nftables, or iptables) is active and enforcing rules"
    depends = ["firewall"]
    tags = ["firewall", "network-hardening", "access-control"]

    def _run_check(self, _collectors: dict) -> list:
        data = self._get_data(_collectors, "firewall")
        findings: list = []
        ufw = data.get("ufw", {})
        nftables = data.get("nftables", {})
        iptables = data.get("iptables", {})

        ufw_active = ufw.get("active", False)
        nft_active = nftables.get("active", False)
        ipt_active = iptables.get("active", False)

        any_fw_installed = any([
            ufw.get("installed", False),
            nftables.get("installed", False),
            iptables.get("installed", False),
        ])

        if ufw_active or nft_active or ipt_active:
            return findings

        evidence_details = []
        if not ufw.get("installed"):
            evidence_details.append("UFW not installed")
        elif not ufw_active:
            evidence_details.append("UFW installed but inactive")

        if not nftables.get("installed"):
            evidence_details.append("nftables not installed")
        elif not nft_active:
            evidence_details.append("nftables installed but no ruleset")

        if not iptables.get("installed"):
            evidence_details.append("iptables not installed")
        elif not ipt_active:
            evidence_details.append("iptables installed but no active rules")

        if not any_fw_installed:
            title = "No host-based firewall is installed"
            description = "Neither UFW, nftables, nor iptables are installed. The system has no firewall protection."
            rationale = (
                "Without a firewall, the system accepts all incoming network connections by default. "
                "This exposes every listening service to the network, including unintended or "
                "misconfigured services. A host-based firewall should restrict incoming traffic to "
                "only explicitly authorized services and ports. Unauthorized network access is a "
                "primary vector for remote exploitation and data exfiltration."
            )
            remediation = (
                "Install and enable UFW: 'apt install ufw && ufw enable'. "
                "Set default policies: 'ufw default deny incoming && ufw default allow outgoing'. "
                "Allow only necessary services: 'ufw allow ssh'."
            )
        else:
            title = "Installed firewall is not active"
            description = f"Firewall software is installed but not actively enforcing: {'; '.join(evidence_details)}"
            rationale = (
                "Having firewall software installed but inactive provides no protection. "
                "All incoming connections are accepted by default, bypassing the intended "
                "security controls. This is commonly caused by disabling the firewall during "
                "troubleshooting and forgetting to re-enable it."
            )
            remediation = (
                "Enable the installed firewall: "
                "For UFW: 'ufw enable'. "
                "For nftables: 'systemctl enable --now nftables'. "
                "For iptables: ensure rules are loaded and persist across reboots."
            )

        findings.append(
            self.finding(
                finding_id="001",
                title=title,
                description=description,
                rationale=rationale,
                remediation=remediation,
                evidence=CommandEvidence(
                    command="ufw status verbose; nft list ruleset; iptables -L -n",
                    stdout=str(ufw.get("raw", "")),
                    exit_code=0,
                ),
                detected_value="No active firewall" if not any_fw_installed else "Firewall installed but inactive",
                expected_value="At least one firewall (UFW/nftables/iptables) active and enforcing",
                affected_component="network (firewall)",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1562.004"],
                cis_benchmarks=["CIS Ubuntu 20.04: 3.5"],
                tags=["firewall", "network-hardening"],
            )
        )
        return findings
