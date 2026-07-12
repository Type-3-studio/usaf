from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import CommandEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


def _fw_data(data: dict[str, Any]) -> dict[str, Any]:
    return dict(data.get("firewall", {}))


@register_check
class FirewallDefaultPolicyCheck(AuditCheck):
    id = "FW-201"
    name = "Firewall Default Incoming Policy"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks that the firewall default incoming policy is set to deny"
    depends = ["firewall"]
    tags = ["firewall", "network-hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        fw = _fw_data(collectors)
        findings: list = []
        ufw = fw.get("ufw", {})

        if not ufw.get("installed", False):
            return findings

        policy = ufw.get("default_policy", "")
        if policy and "deny" not in policy.lower():
            detected = policy
            finding_id = "001"
            title = "UFW default incoming policy is not deny"
            desc = f"UFW default policy is '{policy}', expected 'deny (incoming)'"
            if "allow" in policy.lower():
                finding_id = "002"
                title = "UFW default incoming policy is allow"
                desc = f"UFW default policy is '{policy}' — all incoming traffic is allowed by default"

            findings.append(
                self.finding(
                    finding_id=finding_id,
                    title=title,
                    description=desc,
                    rationale=(
                        "A default allow incoming policy means all inbound connections "
                        "are accepted unless explicitly blocked. This is the opposite "
                        "of defense-in-depth — any service that listens on the network "
                        "is automatically exposed. Default deny is the security best practice."
                    ),
                    remediation=(
                        "Set default deny incoming: 'ufw default deny incoming'. "
                        "Then explicitly allow only needed services: 'ufw allow <service>'."
                    ),
                    evidence=RegistryEvidence(
                        key="ufw.default_policy",
                        value=detected,
                        expected="deny (incoming)",
                        source="ufw status verbose",
                    ),
                    detected_value=detected,
                    expected_value="deny (incoming)",
                    affected_component="firewall (UFW)",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1562.004"],
                    tags=["firewall", "default-policy"],
                )
            )

        return findings


@register_check
class FirewallMinimalRulesCheck(AuditCheck):
    id = "FW-202"
    name = "Firewall Without Active Rules"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks that the active firewall has rules configured beyond defaults"
    depends = ["firewall"]
    tags = ["firewall", "network-hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        fw = _fw_data(collectors)
        findings: list = []
        nft = fw.get("nftables", {})
        ipt = fw.get("iptables", {})

        nft_rules = nft.get("rulesets", [])
        ipt_rules = ipt.get("rules", [])

        has_substance = False

        if nft.get("active", False) and len(nft_rules) > 3:
            has_substance = True
        if ipt.get("active", False) and len(ipt_rules) > 3:
            has_substance = True

        if not has_substance:
            active_fws = []
            if nft.get("active", False):
                active_fws.append(f"nftables ({len(nft_rules)} lines)")
            if ipt.get("active", False):
                active_fws.append(f"iptables ({len(ipt_rules)} lines)")

            if active_fws:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title="Active firewall has minimal or no rules",
                        description=(
                            f"Active firewall(s) have very few rules: "
                            f"{', '.join(active_fws)}. "
                            f"Default chain policies alone are insufficient."
                        ),
                        rationale=(
                            "A firewall with only default chain policies and no "
                            "specific allow/deny rules provides minimal protection. "
                            "It will block all incoming traffic (if default deny) but "
                            "offers no granular control and no logging. "
                            "Explicit allow rules should exist for necessary services."
                        ),
                        remediation=(
                            "Add explicit allow rules for necessary services: "
                            "'ufw allow ssh', 'ufw allow https'. "
                            "Review and add rules for all listening services."
                        ),
                        evidence=RegistryEvidence(
                            key="firewall.rules",
                            value=f"nftables: {len(nft_rules)} lines, iptables: {len(ipt_rules)} lines",
                            expected="Multiple rules defining specific service access",
                            source="nft list ruleset; iptables -L -n",
                        ),
                        detected_value=f"nftables: {len(nft_rules)} rules, iptables: {len(ipt_rules)} rules",
                        expected_value="Multiple explicit allow rules",
                        affected_component="firewall rules",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1562.004"],
                        tags=["firewall", "rules"],
                    )
                )

        return findings


@register_check
class FirewallIPv6Check(AuditCheck):
    id = "FW-203"
    name = "IPv6 Firewall Rules"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks that IPv6 has separate firewall rules when IPv6 is enabled"
    depends = ["firewall"]
    tags = ["firewall", "ipv6", "network-hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        fw = _fw_data(collectors)
        findings: list = []
        nft = fw.get("nftables", {})

        if nft.get("active", False):
            rulesets = nft.get("rulesets", [])
            has_ip6 = any("ip6" in line.lower() for line in rulesets)
            if not has_ip6:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title="nftables active but no IPv6 family rules",
                        description=(
                            "nftables is active but no 'ip6' family rules were "
                            "detected. IPv6 traffic may not be filtered."
                        ),
                        rationale=(
                            "nftables rulesets should include 'ip6' family rules "
                            "to filter IPv6 traffic. Without them, IPv6 traffic "
                            "may bypass the firewall entirely if IPv6 is enabled."
                        ),
                        remediation=(
                            "Add IPv6 rules to nftables: ensure 'ip6' family "
                            "tables exist. For UFW, enable IPv6 in /etc/default/ufw "
                            "and verify with 'ufw status verbose'."
                        ),
                        evidence=RegistryEvidence(
                            key="nftables.families",
                            value="no ip6 family detected",
                            expected="ip6 family present",
                            source="nft list ruleset",
                        ),
                        detected_value="No IPv6 rules in nftables",
                        expected_value="IPv6 rules present",
                        affected_component="firewall (IPv6)",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.15,
                        mitre_attack_ids=["T1562.004"],
                        tags=["firewall", "ipv6"],
                    )
                )

        ipt = fw.get("iptables", {})
        if not findings and ipt.get("active", False) and ipt.get("rules", []):
            findings.append(
                self.finding(
                    finding_id="002",
                    title="IPv6 firewall rules not verified",
                    description=(
                        "iptables is active but ip6tables rules were not checked. "
                        "IPv6 traffic may bypass the IPv4 firewall."
                    ),
                    rationale=(
                        "iptables only filters IPv4 traffic. IPv6 requires a "
                        "separate ip6tables ruleset. If only iptables is active, "
                        "IPv6 traffic is unfiltered."
                    ),
                    remediation=(
                        "Verify ip6tables rules: 'ip6tables -L -n'. "
                        "If no IPv6 rules exist, install them or disable IPv6."
                    ),
                    evidence=RegistryEvidence(
                        key="ip6tables",
                        value="not checked by collector",
                        expected="active IPv6 firewall",
                        source="ip6tables -L -n",
                    ),
                    detected_value="Only IPv4 firewall active",
                    expected_value="IPv4 + IPv6 firewall active",
                    affected_component="firewall (IPv6)",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1562.004"],
                    tags=["firewall", "ipv6"],
                )
            )

        return findings


@register_check
class CompetingFirewallsCheck(AuditCheck):
    id = "FW-204"
    name = "Multiple Active Firewalls"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Checks that multiple firewall systems are not active simultaneously"
    depends = ["firewall"]
    tags = ["firewall", "network-hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        fw = _fw_data(collectors)
        findings: list = []
        ufw = fw.get("ufw", {})
        nft = fw.get("nftables", {})
        ipt = fw.get("iptables", {})

        active = []
        if ufw.get("active", False):
            active.append("UFW")
        if nft.get("active", False):
            active.append("nftables")
        if ipt.get("active", False):
            active.append("iptables")

        if len(active) > 1:
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Multiple firewalls active: {', '.join(active)}",
                    description=(
                        f"Multiple firewall systems are active: {', '.join(active)}. "
                        f"Running UFW alongside nftables or iptables can cause "
                        f"conflicts and unexpected behavior."
                    ),
                    rationale=(
                        "Running multiple firewall systems can lead to rule conflicts, "
                        "performance degradation, and unexpected traffic behavior. "
                        "UFW is a frontend that manages iptables/nftables rules — "
                        "running UFW alongside manually managed nftables/iptables "
                        "may cause conflicts."
                    ),
                    remediation=(
                        "Choose one firewall system and disable the others. "
                        "UFW is the recommended frontend for Ubuntu. "
                        "'systemctl disable nftables' or 'ufw disable'."
                    ),
                    evidence=RegistryEvidence(
                        key="active_firewalls",
                        value=", ".join(active),
                        expected="Only one firewall system active",
                        source="firewall collector",
                    ),
                    detected_value=", ".join(active),
                    expected_value="One firewall system",
                    affected_component="firewall",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    tags=["firewall", "configuration"],
                )
            )

        return findings


@register_check
class FirewallOutgoingPolicyCheck(AuditCheck):
    id = "FW-205"
    name = "Firewall Default Outgoing Policy"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Checks the firewall default outgoing policy — deny is more restrictive"
    depends = ["firewall"]
    tags = ["firewall", "network-hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        fw = _fw_data(collectors)
        findings: list = []
        ufw = fw.get("ufw", {})
        policy = ufw.get("default_policy", "")

        if policy and "allow (outgoing)" in policy:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="UFW default outgoing policy is allow",
                    description=(
                        f"UFW outgoing policy is set to allow. All outgoing traffic "
                        f"is permitted by default."
                    ),
                    rationale=(
                        "Default allow outgoing means any application can send traffic "
                        "to any destination. For high-security environments, restricting "
                        "outgoing traffic to only necessary services prevents data "
                        "exfiltration and C2 communication. This is a defense-in-depth measure."
                    ),
                    remediation=(
                        "For high-security environments: 'ufw default deny outgoing'. "
                        "Then explicitly allow needed destinations: 'ufw allow out <port>'. "
                        "Warning: this may break package updates and DNS."
                    ),
                    evidence=RegistryEvidence(
                        key="ufw.default_policy",
                        value=policy,
                        expected="deny (outgoing) for high-security environments",
                        source="ufw status verbose",
                    ),
                    detected_value=policy,
                    expected_value="deny (outgoing) for strict environments",
                    affected_component="firewall (UFW)",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    tags=["firewall", "outgoing", "hardening"],
                )
            )

        return findings


@register_check
class FirewallLoggingCheck(AuditCheck):
    id = "FW-206"
    name = "Firewall Logging"
    category = CheckCategory.NETWORK
    severity = Severity.LOW
    description = "Checks that firewall logging is enabled for denied connections"
    depends = ["firewall"]
    tags = ["firewall", "logging", "monitoring"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        fw = _fw_data(collectors)
        findings: list = []
        ufw = fw.get("ufw", {})
        raw = ufw.get("raw", "")

        if ufw.get("active", False) and raw:
            if "Logging: off" in raw:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title="UFW firewall logging is off",
                        description="UFW is active but logging is disabled.",
                        rationale=(
                            "Firewall logs are critical for detecting and investigating "
                            "network probes, port scans, and intrusion attempts. "
                            "Without logging, blocked connection attempts go unnoticed."
                        ),
                        remediation=(
                            "Enable UFW logging: 'ufw logging on'. "
                            "For high verbosity: 'ufw logging medium' or 'ufw logging high'."
                        ),
                        evidence=RegistryEvidence(
                            key="ufw.logging",
                            value="off",
                            expected="on (or medium/high)",
                            source="ufw status verbose",
                        ),
                        detected_value="Logging: off",
                        expected_value="Logging enabled",
                        affected_component="firewall (UFW)",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.0,
                        mitre_attack_ids=["T1562.001"],
                        tags=["firewall", "logging"],
                    )
                )

        return findings


@register_check
class FirewallRateLimitCheck(AuditCheck):
    id = "FW-207"
    name = "UFW Application Rate Limiting"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks if UFW rules include rate limiting for critical services"
    depends = ["firewall"]
    tags = ["firewall", "rate-limit", "brute-force"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        fw = _fw_data(collectors)
        findings: list = []
        ufw = fw.get("ufw", {})
        raw = ufw.get("raw", "")

        if ufw.get("active", False) and raw:
            has_ssh_allow = "22" in raw and "ALLOW" in raw
            has_ssh_limit = "22" in raw and "LIMIT" in raw

            if has_ssh_allow and not has_ssh_limit:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title="SSH port without rate limiting",
                        description=(
                            "UFW has an ALLOW rule for port 22/SSH but no LIMIT rule. "
                            "SSH is exposed without rate limiting."
                        ),
                        rationale=(
                            "UFW's 'limit' directive only allows 20 connections per "
                            "6 minutes from the same IP. Without this, SSH is "
                            "vulnerable to brute-force attacks with no connection "
                            "rate throttling at the firewall level."
                        ),
                        remediation=(
                            "Replace the SSH allow rule with a limit rule: "
                            "'ufw limit ssh'. This rate-limits SSH connections."
                        ),
                        evidence=RegistryEvidence(
                            key="ufw.ssh_rule",
                            value="ALLOW (no rate limit)",
                            expected="LIMIT (rate limited)",
                            source="ufw status verbose",
                        ),
                        detected_value="SSH allow without rate limit",
                        expected_value="SSH limit rule (rate limited)",
                        affected_component="firewall (UFW) — SSH",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1110"],
                        tags=["firewall", "ssh", "brute-force"],
                    )
                )

        return findings


@register_check
class FirewallBootPersistenceCheck(AuditCheck):
    id = "FW-208"
    name = "Firewall Service Persistence"
    category = CheckCategory.NETWORK
    severity = Severity.MEDIUM
    description = "Checks that the active firewall service is enabled for system boot"
    depends = ["firewall"]
    tags = ["firewall", "persistence", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        fw = _fw_data(collectors)
        findings: list = []
        nft = fw.get("nftables", {})
        ipt = fw.get("iptables", {})

        if nft.get("active", False):
            findings.append(
                self.finding(
                    finding_id="001",
                    title="nftables rules may not persist across reboot",
                    description=(
                        "nftables is currently active, but the collector did not "
                        "verify if rules are saved for persistence. "
                        "Without persistence, rules are lost on reboot."
                    ),
                    rationale=(
                        "Firewall rules that are not saved will be lost on system "
                        "reboot, leaving the system unprotected after restart. "
                        "nftables rules must be explicitly saved."
                    ),
                    remediation=(
                        "Save nftables rules: 'nft list ruleset > /etc/nftables.conf'. "
                        "Enable the nftables service: 'systemctl enable nftables'."
                    ),
                    evidence=RegistryEvidence(
                        key="nftables.persistence",
                        value="not verified",
                        expected="saved ruleset enabled at boot",
                        source="nft list ruleset",
                    ),
                    detected_value="nftables active, persistence unverified",
                    expected_value="nftables rules persistent across reboot",
                    affected_component="firewall (nftables)",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1562.004"],
                    tags=["firewall", "persistence"],
                )
            )

        if ipt.get("active", False):
            findings.append(
                self.finding(
                    finding_id="002",
                    title="iptables rules may not persist across reboot",
                    description=(
                        "iptables is currently active, but iptables rules do not "
                        "persist across reboots without additional tooling."
                    ),
                    rationale=(
                        "iptables rules are ephemeral — they are lost on reboot "
                        "unless saved with iptables-save and restored on boot "
                        "via iptables-restore or a tool like iptables-persistent."
                    ),
                    remediation=(
                        "Install iptables-persistent: 'apt install iptables-persistent'. "
                        "Or use netfilter-persistent to save and restore rules."
                    ),
                    evidence=RegistryEvidence(
                        key="iptables.persistence",
                        value="not verified",
                        expected="saved rules persistent across reboot",
                        source="iptables -L -n",
                    ),
                    detected_value="iptables active, persistence unverified",
                    expected_value="iptables rules persistent across reboot",
                    affected_component="firewall (iptables)",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1562.004"],
                    tags=["firewall", "persistence"],
                )
            )

        return findings
