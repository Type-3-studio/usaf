from __future__ import annotations

from usaf.models.scenario import AttackScenario, KillChainPhase
from usaf.models.severity import Severity

# ---------------------------------------------------------------------------
# 8 Core Attack Scenarios
# Each scenario groups related correlation rules that together indicate a
# specific real-world attack pattern. The scenario fires when a minimum
# number of its constituent rules have produced findings.
# ---------------------------------------------------------------------------

SCEN_RANSOMWARE = AttackScenario(
    id="SCEN-RANSOM",
    name="Ransomware Deployment",
    description=(
        "Detects indicators consistent with ransomware deployment: defense evasion "
        "(disabled security controls), file integrity compromise (encrypted/renamed files), "
        "and suspicious service deployment (ransomware binaries installed as services)."
    ),
    severity=Severity.CRITICAL,
    rule_ids=[
        "DEF-EVADE",
        "FILE-INTEGRITY",
        "ROGUE-SVC",
        "PERSIST-DETECT",
    ],
    kill_chain_phases=[
        KillChainPhase.DEFENSE_EVASION,
        KillChainPhase.IMPACT,
        KillChainPhase.PERSISTENCE,
    ],
    min_rules_triggered=2,
    tags=["ransomware", "impact", "defense-evasion", "file-encryption"],
    mitre_attack_ids=["T1486", "T1562", "T1543", "T1485"],
)

SCEN_CRYPTOMINER = AttackScenario(
    id="SCEN-MINER",
    name="Cryptominer Deployment",
    description=(
        "Detects indicators consistent with cryptocurrency miner deployment: "
        "unexpected SUID binaries (miner binaries with SUID), unauthorized services "
        "(miner installed as a systemd service), and exposed vulnerable services "
        "(initial access vector that delivered the miner)."
    ),
    severity=Severity.HIGH,
    rule_ids=[
        "SUID-ARM",
        "UNAUTH-SVC",
        "EXPO-VULN",
        "EXFIL-SURFACE",
    ],
    kill_chain_phases=[
        KillChainPhase.INITIAL_ACCESS,
        KillChainPhase.EXECUTION,
        KillChainPhase.IMPACT,
    ],
    min_rules_triggered=2,
    tags=["cryptominer", "impact", "resource-hijacking", "unauthorized-service"],
    mitre_attack_ids=["T1496", "T1543", "T1043"],
)

SCEN_PERSISTENCE_BACKDOOR = AttackScenario(
    id="SCEN-PERSIST",
    name="Persistence & Backdoor Installation",
    description=(
        "Detects indicators of persistent backdoor access: suspicious persistence "
        "mechanisms (user accounts, services, SUID), credential compromise "
        "(SSH keys, cloud credentials), and active breach indicators "
        "(log gaps, auth failures, new services)."
    ),
    severity=Severity.CRITICAL,
    rule_ids=[
        "PERSIST-DETECT",
        "CORR-402",
        "CORR-403",
        "ROGUE-SVC",
    ],
    kill_chain_phases=[
        KillChainPhase.PERSISTENCE,
        KillChainPhase.PRIVILEGE_ESCALATION,
        KillChainPhase.DEFENSE_EVASION,
    ],
    min_rules_triggered=2,
    tags=["persistence", "backdoor", "compromise", "credentials"],
    mitre_attack_ids=["T1098", "T1543", "T1078", "T1552"],
)

SCEN_SUPPLY_CHAIN = AttackScenario(
    id="SCEN-SUPPLY",
    name="Supply Chain Compromise",
    description=(
        "Detects software supply chain compromise: unknown repositories, "
        "unsigned/broken package signatures, and modified package files "
        "indicating tampered software distribution."
    ),
    severity=Severity.CRITICAL,
    rule_ids=["SUPPLY-CHAIN"],
    kill_chain_phases=[
        KillChainPhase.INITIAL_ACCESS,
        KillChainPhase.EXECUTION,
    ],
    min_rules_triggered=1,
    tags=["supply-chain", "tampering", "package-integrity"],
    mitre_attack_ids=["T1195", "T1195.001", "T1554"],
)

SCEN_BOOTKIT = AttackScenario(
    id="SCEN-BOOTKIT",
    name="Bootkit Installation",
    description=(
        "Detects boot-level compromise: Secure Boot disabled, unsigned kernels, "
        "and missing GRUB password allowing bootkit installation that persists "
        "across OS reinstalls."
    ),
    severity=Severity.CRITICAL,
    rule_ids=["BOOT-FAIL"],
    kill_chain_phases=[
        KillChainPhase.PERSISTENCE,
        KillChainPhase.DEFENSE_EVASION,
        KillChainPhase.IMPACT,
    ],
    min_rules_triggered=1,
    tags=["bootkit", "boot", "persistence", "efi"],
    mitre_attack_ids=["T1542", "T1542.001", "T1542.003"],
)

SCEN_CONTAINER_ESCAPE = AttackScenario(
    id="SCEN-ESCAPE",
    name="Container Escape",
    description=(
        "Detects container escape paths: exposed Docker socket combined with "
        "privilege escalation vectors (SUID binaries, root services) that "
        "enable container-to-host escape."
    ),
    severity=Severity.CRITICAL,
    rule_ids=[
        "CORR-401",
        "EXPO-VULN",
    ],
    kill_chain_phases=[
        KillChainPhase.INITIAL_ACCESS,
        KillChainPhase.PRIVILEGE_ESCALATION,
        KillChainPhase.LATERAL_MOVEMENT,
    ],
    min_rules_triggered=1,
    tags=["container-escape", "docker", "privilege-escalation"],
    mitre_attack_ids=["T1611", "T1548"],
)

SCEN_DATA_THEFT = AttackScenario(
    id="SCEN-THEFT",
    name="Data Exfiltration / Theft",
    description=(
        "Detects data exfiltration preparation: network sniffing (promiscuous mode), "
        "credential harvesting (exposed AWS/GCP/SSH keys), and exposed attack surface "
        "(listening ports, weak TLS) enabling data theft."
    ),
    severity=Severity.CRITICAL,
    rule_ids=[
        "EXFIL-SURFACE",
        "CORR-402",
        "CORR-404",
    ],
    kill_chain_phases=[
        KillChainPhase.COLLECTION,
        KillChainPhase.CREDENTIAL_ACCESS,
        KillChainPhase.EXFILTRATION,
    ],
    min_rules_triggered=2,
    tags=["exfiltration", "data-theft", "credentials", "sniffing"],
    mitre_attack_ids=["T1040", "T1552", "T1048", "T1530"],
)

SCEN_ACTIVE_BREACH = AttackScenario(
    id="SCEN-BREACH",
    name="Active Security Breach",
    description=(
        "Detects indicators of an active or recent security breach: log tampering "
        "(gaps in audit logs), authentication failures (brute-force or credential "
        "stuffing), newly installed services, and exposed credentials suggesting "
        "active attacker presence."
    ),
    severity=Severity.CRITICAL,
    rule_ids=[
        "CORR-403",
        "CORR-402",
        "SSH-BRUTE",
        "PERSIST-DETECT",
    ],
    kill_chain_phases=[
        KillChainPhase.INITIAL_ACCESS,
        KillChainPhase.CREDENTIAL_ACCESS,
        KillChainPhase.PERSISTENCE,
        KillChainPhase.DEFENSE_EVASION,
    ],
    min_rules_triggered=2,
    tags=["active-breach", "compromise", "incident-response", "forensics"],
    mitre_attack_ids=["T1070", "T1110", "T1505", "T1562", "T1098"],
)


CORE_SCENARIOS: list[AttackScenario] = [
    SCEN_RANSOMWARE,
    SCEN_CRYPTOMINER,
    SCEN_PERSISTENCE_BACKDOOR,
    SCEN_SUPPLY_CHAIN,
    SCEN_BOOTKIT,
    SCEN_CONTAINER_ESCAPE,
    SCEN_DATA_THEFT,
    SCEN_ACTIVE_BREACH,
]
