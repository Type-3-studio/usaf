from __future__ import annotations

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import ProcessEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class KnownBadProcessCheck(AuditCheck):
    id = "COM-101"
    name = "Known Malicious Process Detection"
    category = CheckCategory.COMPROMISE
    severity = Severity.HIGH
    description = "Scans running processes for names matching known malware, coinminers, and backdoor indicators"
    depends = ["processes"]
    tags = ["compromise", "malware", "incident-response"]

    SUSPICIOUS_NAMES = {
        "minerd": "Coin miner (CryptoNight)",
        "xmrig": "Coin miner (Monero)",
        "cryptonight": "Coin miner",
        "kdevtmpfsi": "Known miner process",
        "kinsing": "Known malware (cloud exploitation)",
        "donut": "Known malware loader",
        "mbrt": "Known rootkit component",
        "sliver": "C2 implant (Sliver)",
        "merlin": "C2 agent (Merlin)",
        "pwnxd": "Known backdoor",
    }

    def _run_check(self, collectors: dict) -> list:
        proc_data = self._get_data(collectors, "processes")
        processes = proc_data.get("processes", [])
        findings = []

        for proc in processes:
            name = proc.get("name") or ""
            lower_name = name.lower()
            match = self.SUSPICIOUS_NAMES.get(lower_name)
            if not match:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Suspicious process detected: {name}",
                    description=f"Running process '{name}' matches known {match}",
                    rationale=(
                        "The process name matches a known malware, coin miner, or C2 implant. "
                        "This is a strong indicator of compromise. Even if the process name is "
                        "coincidental, it warrants immediate investigation."
                    ),
                    remediation=(
                        f"Investigate PID {proc['pid']}: 'ls -la /proc/{proc['pid']}/exe'. "
                        f"Kill the process: 'kill -9 {proc['pid']}'. "
                        "Determine the attack vector and eradicate the root cause."
                    ),
                    evidence=ProcessEvidence(
                        pid=proc["pid"],
                        name=name,
                        binary=proc.get("binary"),
                        cmdline=proc.get("cmdline"),
                        state=proc.get("state"),
                        user=str(proc.get("uid", "")),
                    ),
                    detected_value=f"Process '{name}' (PID {proc['pid']})",
                    expected_value="No known malicious processes running",
                    affected_component=f"PID {proc['pid']}: {name}",
                    reference="https://attack.mitre.org/techniques/T1071/",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.15,
                    mitre_attack_ids=["T1071", "T1059", "T1496"],
                    tags=["compromise-indicator", "malware", "incident-response"],
                )
            )
        return findings
