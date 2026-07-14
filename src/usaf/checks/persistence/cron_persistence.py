import os

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

SUSPICIOUS_CRON_PATTERNS = [
    r"wget",
    r"curl.*-o",
    r"base64.*-d",
    r"chmod \+x",
    r"nc\s",
    r"ncat\s",
    r"bash -c",
    r"python3? -c",
    r"perl -e",
    r"sh -c",
    r"mkfifo",
    r"/dev/tcp/",
]

SUSPICIOUS_COMMENTS = [
    "backdoor",
    "reverse",
    "shell",
    "meterp",
    "beacon",
    "implant",
    "miner",
]

ANACRON_SPOOL = "/var/spool/anacron"
ANACRON_TABS = "/etc/anacrontab"
AT_SPOOL_DIR = "/var/spool/at"
AT_ALLOW = "/etc/at.allow"
AT_DENY = "/etc/at.deny"

BENIGN_CRON_PATTERNS = [
    "certbot",
    "updatedb",
    "man-db",
    "logrotate",
    "apt",
    "dpkg",
    "unattended-upgrades",
    "aide",
    "rkhunter",
    "chkrootkit",
    "anacron",
]


@register_check
class CronAnomalyCheck(AuditCheck):
    id = "PER-101"
    name = "Cron Job Anomalies"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects suspicious or unusual cron jobs that may indicate persistence"
    depends = ["cron"]
    tags = ["persistence", "cron", "scheduled-tasks"]

    def _run_check(self, collectors: dict) -> list:
        cron_data = self._get_data(collectors, "cron")
        findings: list = []

        all_entries: list[dict] = []

        for entry in cron_data.get("system_crontab", []):
            all_entries.append({"file": entry.get("file", "/etc/crontab"), "content": entry.get("content", "")})

        for entry in cron_data.get("cron_dirs", []):
            all_entries.append({"file": entry.get("file", ""), "content": entry.get("content", "")})

        for entry in cron_data.get("user_crontabs", []):
            all_entries.append({"file": entry.get("file", ""), "content": entry.get("content", "")})

        suspicious_lines: list[dict] = []
        for entry in all_entries:
            content = str(entry.get("content", ""))
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for pattern in SUSPICIOUS_CRON_PATTERNS:
                    if pattern in line.lower():
                        is_benign = any(bp in line.lower() for bp in BENIGN_CRON_PATTERNS)
                        if not is_benign:
                            suspicious_lines.append({"file": entry["file"], "line": line, "pattern": pattern})
                        break

        if suspicious_lines:
            for sl in suspicious_lines:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title="Suspicious cron job detected",
                        description=(
                            f"Cron entry in {sl['file']} contains potentially "
                            f"malicious pattern '{sl['pattern']}': {sl['line']}"
                        ),
                        rationale=(
                            "Cron jobs are a common persistence mechanism for attackers. "
                            "Commands using wget/curl to download payloads, base64 decoding, "
                            "or netcat reverse shells are strong indicators of compromise. "
                            "Attackers maintain persistence by scheduling malicious scripts "
                            "to run at regular intervals or on reboot."
                        ),
                        remediation=(
                            f"Investigate the cron entry in {sl['file']}: "
                            f"'crontab -l' or 'cat {sl['file']}'. "
                            "Remove if unauthorized: 'crontab -e' or edit the file directly. "
                            "Verify the referenced script/binaries with 'dpkg -S <path>'."
                        ),
                        evidence=FileEvidence(
                            path=sl["file"],
                            content=sl["line"],
                            owner="",
                            group="",
                        ),
                        detected_value=sl["line"],
                        expected_value="Cron jobs should be known/expected system tasks",
                        affected_component=sl["file"],
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1053.003"],
                        tags=["cron", "persistence", "scheduled-task"],
                    )
                )

        if not suspicious_lines:
            for entry in all_entries:
                content = str(entry.get("content", ""))
                for line in content.split("\n"):
                    stripped = line.strip().lower()
                    if any(sc in stripped for sc in SUSPICIOUS_COMMENTS):
                        findings.append(
                            self.finding(
                                finding_id="002",
                                title="Cron job with suspicious comment",
                                description=(
                                    f"Cron entry in {entry['file']} has a "
                                    f"suspicious comment/description"
                                ),
                                rationale=(
                                    "Comments in cron files referencing backdoor, implant, "
                                    "or miner terminology are highly suspicious and may "
                                    "indicate attacker persistence."
                                ),
                                remediation=(
                                    f"Investigate the cron entry in {entry['file']}. "
                                    "Remove if unauthorized and audit the system for "
                                    "additional persistence mechanisms."
                                ),
                                evidence=FileEvidence(
                                    path=entry["file"],
                                    content=line,
                                    owner="",
                                    group="",
                                ),
                                detected_value=line,
                                expected_value="No suspicious comments in cron jobs",
                                affected_component=entry["file"],
                                confidence=Confidence.LOW,
                                false_positive_probability=0.6,
                                mitre_attack_ids=["T1053.003"],
                                tags=["cron", "persistence"],
                            )
                        )
                        break

        return findings


@register_check
class AnacronJobCheck(AuditCheck):
    id = "PER-102"
    name = "Anacron Job Anomalies"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects unusual anacron jobs that may indicate persistence"
    depends = ["cron"]
    tags = ["persistence", "anacron", "scheduled-tasks"]

    def _run_check(self, collectors: dict) -> list:
        cron_data = self._get_data(collectors, "cron")
        findings: list = []

        sys_cron = cron_data.get("system_crontab", [])
        anacron_entries: list[str] = []
        for entry in sys_cron:
            fp = entry.get("file", "")
            if "anacron" in fp.lower():
                anacron_entries.append(str(entry.get("content", "")))

        anacron_file_content = ""
        if os.path.exists(ANACRON_TABS):
            try:
                with open(ANACRON_TABS) as f:
                    anacron_file_content = f.read()
            except (OSError, PermissionError):
                pass

        all_content = anacron_file_content + "\n".join(anacron_entries)

        spool_files: list[str] = []
        if os.path.isdir(ANACRON_SPOOL):
            try:
                spool_files = os.listdir(ANACRON_SPOOL)
            except (OSError, PermissionError):
                pass

        suspicious_lines: list[str] = []
        for line in all_content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                cmd = " ".join(parts[3:])
                is_benign = any(bp in cmd.lower() for bp in BENIGN_CRON_PATTERNS)
                if not is_benign:
                    for pattern in SUSPICIOUS_CRON_PATTERNS:
                        if pattern in cmd.lower():
                            suspicious_lines.append(line)
                            break

        if suspicious_lines or len(spool_files) > 10:
            detail_parts = []
            if suspicious_lines:
                detail_parts.append(f"{len(suspicious_lines)} suspicious anacron command(s)")
            if len(spool_files) > 10:
                detail_parts.append(f"{len(spool_files)} anacron spool files (expected <= 10)")

            findings.append(
                self.finding(
                    finding_id="001",
                    title="Anacron persistence indicators detected",
                    description=(
                        f"Anacron job anomalies detected: {'; '.join(detail_parts)}. "
                        "Anacron can be used for persistence on systems that are not "
                        "always running."
                    ),
                    rationale=(
                        "Anacron runs jobs that would otherwise be missed if the system "
                        "is powered off during scheduled cron times. Attackers can use "
                        "anacron to ensure their persistence mechanisms trigger even on "
                        "intermittently-powered systems like laptops or VMs."
                    ),
                    remediation=(
                        f"Review anacrontab: 'cat {ANACRON_TABS}'\n"
                        f"Check spool directory: 'ls -la {ANACRON_SPOOL}'\n"
                        "Remove any unauthorized entries."
                    ),
                    evidence=FileEvidence(
                        path=ANACRON_TABS if suspicious_lines else ANACRON_SPOOL,
                        content="\n".join(suspicious_lines[:5]) if suspicious_lines else str(spool_files),
                        owner="",
                        group="",
                    ),
                    detected_value="Anacron anomaly found" if suspicious_lines or len(spool_files) > 10 else "Normal",
                    expected_value="No suspicious anacron entries; <10 spool files",
                    affected_component=ANACRON_TABS,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.4,
                    mitre_attack_ids=["T1053.003"],
                    tags=["persistence", "anacron", "scheduled-task"],
                )
            )

        return findings


@register_check
class AtJobCheck(AuditCheck):
    id = "PER-103"
    name = "At Job Anomalies"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects at jobs that may indicate unauthorized scheduled execution"
    depends = ["cron"]
    tags = ["persistence", "at", "scheduled-tasks"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        at_spool_entries: list[str] = []
        if os.path.isdir(AT_SPOOL_DIR):
            try:
                at_spool_entries = os.listdir(AT_SPOOL_DIR)
            except (OSError, PermissionError):
                pass

        at_allow_exists = os.path.exists(AT_ALLOW)
        at_deny_exists = os.path.exists(AT_DENY)

        details: list[str] = []
        if at_spool_entries:
            details.append(f"{len(at_spool_entries)} at job(s) in spool")
        if not at_allow_exists and not at_deny_exists:
            details.append("no at.allow or at.deny (all users can schedule at jobs)")

        if details:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="At job scheduling anomalies",
                    description=(
                        f"At job concerns: {'; '.join(details)}. "
                        "At jobs can be used for temporary persistence or delayed execution."
                    ),
                    rationale=(
                        "The 'at' command schedules one-time tasks at a specified time. "
                        "Attackers use 'at' for delayed payload execution or to avoid "
                        "detection by scheduling malicious activity during off-hours. "
                        "Without at.allow/at.deny restrictions, any user can schedule jobs."
                    ),
                    remediation=(
                        "1. List pending at jobs: 'atq'\n"
                        "2. Remove unauthorized jobs: 'atrm <job_id>'\n"
                        f"3. Restrict at access: 'echo root > {AT_ALLOW}'"
                    ),
                    evidence=FileEvidence(
                        path=AT_SPOOL_DIR if at_spool_entries else AT_ALLOW,
                        content=f"Spool entries: {len(at_spool_entries)}, at.allow exists: {at_allow_exists}, at.deny exists: {at_deny_exists}",
                        owner="",
                        group="",
                    ),
                    detected_value=f"{len(at_spool_entries)} at jobs, allow={at_allow_exists}, deny={at_deny_exists}",
                    expected_value="No unexpected at jobs; at.allow should exist",
                    affected_component=AT_SPOOL_DIR,
                    confidence=Confidence.LOW if at_spool_entries and at_allow_exists else Confidence.MEDIUM,
                    false_positive_probability=0.6 if at_allow_exists else 0.3,
                    mitre_attack_ids=["T1053.002"],
                    tags=["persistence", "at", "scheduled-task"],
                )
            )

        return findings
