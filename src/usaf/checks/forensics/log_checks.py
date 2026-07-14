from __future__ import annotations

from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, LogEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class JournalMaxSizeCheck(AuditCheck):
    id = "LOG-101"
    name = "Journald Max Size / Retention"
    category = CheckCategory.AUDIT
    severity = Severity.MEDIUM
    description = "Verifies journald has max size or retention limits configured"
    depends = ["journald"]
    tags = ["logging", "journald", "retention", "disk-space"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        config = data.get("config", {})

        max_use = config.get("max_use")
        max_retention = config.get("max_retention_sec")
        storage = config.get("storage")

        if storage == "none":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Journald storage is disabled",
                    description="Journald Storage=none means no system logs are persisted. "
                    "All journal data is discarded immediately.",
                    rationale="Without persistent logging, there is no record of system events, "
                    "authentication attempts, or service failures. This severely impedes "
                    "incident response and forensic investigation.",
                    remediation="Set Storage=auto or Storage=persistent in /etc/systemd/journald.conf "
                    "and restart systemd-journald: systemctl restart systemd-journald",
                    evidence=RegistryEvidence(
                        key="journald.Storage",
                        value=storage,
                        expected="auto or persistent",
                        source="/etc/systemd/journald.conf",
                    ),
                    detected_value=f"Storage={storage}",
                    expected_value="Storage=auto or Storage=persistent",
                    affected_component="/etc/systemd/journald.conf",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.02,
                    mitre_attack_ids=["T1070", "T1562.002"],
                    tags=["logging", "journald"],
                )
            )
            return findings

        if storage == "volatile":
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Journald uses volatile storage only",
                    description="Journald Storage=volatile means logs are kept only in /run/log/journal "
                    "and are lost on reboot.",
                    rationale="Volatile logging loses all historical data on reboot, making it "
                    "impossible to investigate incidents that span reboots or require historical context.",
                    remediation="Set Storage=auto or Storage=persistent in /etc/systemd/journald.conf. "
                    "Ensure /var/log/journal exists and is writable.",
                    evidence=RegistryEvidence(
                        key="journald.Storage",
                        value=storage,
                        expected="auto or persistent",
                        source="/etc/systemd/journald.conf",
                    ),
                    detected_value=f"Storage={storage}",
                    expected_value="Storage=auto or Storage=persistent",
                    affected_component="/etc/systemd/journald.conf",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1070", "T1562.002"],
                    tags=["logging", "journald", "volatile"],
                )
            )

        if not max_use and not max_retention:
            findings.append(
                self.finding(
                    finding_id="003",
                    title="Journald has no size or retention limit",
                    description="Journald has neither SystemMaxUse nor MaxRetentionSec configured. "
                    "Logs can grow unbounded and fill the disk.",
                    rationale="Without size limits, journal logs can consume all available disk space, "
                    "causing service failures and denial of service. Without retention limits, "
                    "logs accumulate indefinitely.",
                    remediation="Set SystemMaxUse=4G and/or MaxRetentionSec=1month "
                    "in /etc/systemd/journald.conf and restart systemd-journald.",
                    evidence=RegistryEvidence(
                        key="journald.max_use / max_retention_sec",
                        value=f"max_use={max_use!r}, max_retention={max_retention!r}",
                        expected="SystemMaxUse or MaxRetentionSec configured",
                        source="/etc/systemd/journald.conf",
                    ),
                    detected_value="No size or retention limit",
                    expected_value="SystemMaxUse or MaxRetentionSec set",
                    affected_component="/etc/systemd/journald.conf",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1070"],
                    tags=["logging", "journald", "disk-space"],
                )
            )
        return findings


@register_check
class LogRotationCheck(AuditCheck):
    id = "LOG-201"
    name = "Journald Log Rotation / Persistence"
    category = CheckCategory.AUDIT
    severity = Severity.MEDIUM
    description = "Verifies journald has persistent logging with rotation (multiple archive files)"
    depends = ["journald"]
    tags = ["logging", "journald", "rotation", "persistence"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        persistence = data.get("persistence", {})
        log_files = data.get("log_files", [])

        if not persistence.get("persistent_logs", False):
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Journald persistent logging is not enabled",
                    description="/var/log/journal does not exist. Logs are stored in volatile "
                    "memory only (/run/systemd/journal) and are lost on reboot.",
                    rationale="Without persistent logging, all system logs are lost on reboot, "
                    "making forensic analysis of past incidents impossible.",
                    remediation="Create /var/log/journal: mkdir -p /var/log/journal && "
                    "systemctl restart systemd-journald. "
                    "Set Storage=persistent in journald.conf.",
                    evidence=FileEvidence(
                        path="/var/log/journal",
                        content="Directory does not exist",
                    ),
                    detected_value="Runtime-only logging",
                    expected_value="Persistent logging with /var/log/journal",
                    affected_component="/var/log/journal",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.02,
                    mitre_attack_ids=["T1070", "T1562.002"],
                    tags=["logging", "persistence"],
                )
            )
            return findings

        journal_count = len(log_files)
        if journal_count < 2:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Few journal files — rotation may not be active",
                    description=f"Only {journal_count} journal file(s) found in /var/log/journal. "
                    "Multiple journal files indicate active rotation is working.",
                    rationale="Log rotation limits disk usage and ensures old logs are archived. "
                    "A single journal file may indicate rotation is not configured or "
                    "the system has not been running long enough to rotate.",
                    remediation="Verify journald limits: SystemMaxUse and MaxFileSize in journald.conf. "
                    "Active systems should produce multiple journal files over time.",
                    evidence=RegistryEvidence(
                        key="journald.log_files.count",
                        value=str(journal_count),
                        expected="2 or more",
                        source="/var/log/journal",
                    ),
                    detected_value=f"{journal_count} journal file(s)",
                    expected_value="Multiple journal files (rotation active)",
                    affected_component="/var/log/journal",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1070"],
                    tags=["logging", "rotation"],
                )
            )
        return findings


@register_check
class LogTamperCheck(AuditCheck):
    id = "LOG-301"
    name = "Missing Log Periods (Tamper Detection)"
    category = CheckCategory.FORENSICS
    severity = Severity.HIGH
    description = "Detects gaps in journal timeline that may indicate log tampering or deletion"
    depends = ["journald"]
    tags = ["forensics", "logging", "tamper", "timeline"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        usage = data.get("usage", {})

        oldest = usage.get("oldest_entry")
        newest = usage.get("newest_entry")

        if not oldest or not newest:
            return findings

        import datetime

        def _parse_journal_date(s: str) -> datetime.datetime | None:
            s = s.strip()
            for fmt in ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S",
                        "%a %Y-%m-%d %H:%M:%S %Z", "%a %Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.datetime.strptime(s, fmt)
                except ValueError:
                    continue
            return None

        oldest_dt = _parse_journal_date(oldest)
        newest_dt = _parse_journal_date(newest)

        if oldest_dt and newest_dt and newest_dt > oldest_dt:
            span = newest_dt - oldest_dt
            total_hours = span.total_seconds() / 3600
            if oldest_dt.tzinfo is None:
                oldest_dt = oldest_dt.replace(tzinfo=datetime.UTC)
            if newest_dt.tzinfo is None:
                newest_dt = newest_dt.replace(tzinfo=datetime.UTC)

            now = datetime.datetime.now(datetime.UTC)
            age_hours = (now - newest_dt).total_seconds() / 3600

            if total_hours < 1:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title="Journal timeline span is very short",
                        description=f"Journal covers only {total_hours:.1f} hours of activity. "
                        f"Oldest: {oldest}, Newest: {newest}",
                        rationale="A very short journal timeline may indicate recent log deletion, "
                        "a newly installed system, or logs that have been rotated out too aggressively. "
                        "Short timelines impede forensic investigation of past events.",
                        remediation="Investigate why journal history is so short. Check for "
                        "log deletion, recent system reinstall, or overly aggressive rotation settings. "
                        "Ensure SystemMaxUse allows sufficient history.",
                        evidence=LogEvidence(
                            log_path="systemd-journal",
                            match_count=0,
                            pattern="timeline_gap",
                            time_range=(oldest_dt, newest_dt),
                        ),
                        detected_value=f"Timeline span: {total_hours:.1f} hours",
                        expected_value="Timeline span of days or weeks",
                        affected_component="systemd-journal",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1070", "T1562.002", "T1654"],
                        tags=["forensics", "timeline", "tamper"],
                    )
                )

            if age_hours > 24:
                findings.append(
                    self.finding(
                        finding_id="002",
                        title="No recent journal entries",
                        description=f"Newest journal entry is {age_hours:.1f} hours old. "
                        f"Newest: {newest}",
                        rationale="A gap in recent log entries may indicate the logging system "
                        "has stopped working, logs have been deleted, or the system has been "
                        "inactive. In an incident response context, this is suspicious.",
                        remediation="Check systemd-journald status: systemctl status systemd-journald. "
                        "Verify disk space on /var/log. Check for log deletion or rotation issues.",
                        evidence=LogEvidence(
                            log_path="systemd-journal",
                            match_count=0,
                            pattern="recent_entries_gap",
                            time_range=(newest_dt, datetime.datetime.now(datetime.UTC)),
                        ),
                        detected_value=f"Last entry {age_hours:.1f} hours ago",
                        expected_value="Journal entries within last 24 hours",
                        affected_component="systemd-journal",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.15,
                        mitre_attack_ids=["T1070", "T1562.002", "T1654"],
                        tags=["forensics", "timeline", "recent-activity"],
                )
            )
        return findings


@register_check
class AuditdMitreAttackCoverageCheck(AuditCheck):
    id = "LOG-503"
    name = "Auditd MITRE ATT&CK Coverage Gaps"
    category = CheckCategory.AUDIT
    severity = Severity.MEDIUM
    description = "Maps audit rules to MITRE ATT&CK techniques and identifies coverage gaps"
    depends = ["auditd"]
    tags = ["auditing", "mitre-attack", "coverage", "detection"]

    TECHNIQUE_RULES: dict[str, dict[str, str | list[str]]] = {
        "T1078": {"name": "Valid Accounts", "patterns": ["-w /etc/passwd", "-w /etc/shadow", "-w /etc/group"]},
        "T1098": {"name": "Account Manipulation", "patterns": ["-w /etc/passwd", "-w /etc/shadow", "-w /etc/sudoers", "-w /etc/group"]},
        "T1548": {"name": "Abuse Elevation Control Mechanism", "patterns": ["-w /etc/sudoers", "-w /etc/sudoers.d"]},
        "T1053": {"name": "Scheduled Task/Job", "patterns": ["-w /etc/crontab", "-w /etc/cron", "cron"]},
        "T1543": {"name": "Create/Modify System Process", "patterns": ["-w /usr/lib/systemd", "-w /etc/systemd", "systemctl"]},
        "T1070": {"name": "Indicator Removal", "patterns": ["-w /var/log", "log"]},
        "T1562": {"name": "Impair Defenses", "patterns": ["-w /etc/audit", "-w /etc/apparmor", "-w /etc/selinux"]},
        "T1554": {"name": "Compromise Client Software Binary", "patterns": ["-w /usr/bin", "-w /usr/sbin"]},
        "T1505": {"name": "Server Software Component", "patterns": ["-w /etc/ssh", "sshd"]},
        "T1195": {"name": "Supply Chain Compromise", "patterns": ["-a always,exit -S open", "apt", "dpkg"]},
        "T1565": {"name": "Data Manipulation", "patterns": ["-w /etc/hosts", "-w /etc/resolv"]},
        "T1610": {"name": "Deploy Container", "patterns": ["-w /etc/docker", "-w /var/lib/docker", "docker"]},
        "T1059": {"name": "Command and Scripting", "patterns": ["execve", "-S exec"]},
        "T1095": {"name": "Non-Application Layer Protocol", "patterns": ["-S connect", "-S bind"]},
        "T1043": {"name": "Commonly Used Port", "patterns": ["-S bind"]},
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        audit_data = self._get_data(collectors, "auditd")
        status = audit_data.get("status", {})
        rules = audit_data.get("rules", [])

        if not status.get("running", False):
            return findings

        rule_text = " ".join(r.get("rule", "") for r in rules)
        if not rule_text:
            return findings

        uncovered: list[str] = []
        for tid, info in self.TECHNIQUE_RULES.items():
            patterns = info["patterns"]
            covered = any(p in rule_text for p in patterns)
            if not covered:
                uncovered.append(f"{tid} ({info['name']})")

        if uncovered:
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Audit rules missing coverage for {len(uncovered)} MITRE ATT&CK techniques",
                    description=(
                        f"The following {len(uncovered)} MITRE ATT&CK technique(s) have no matching "
                        f"audit rules: {', '.join(uncovered)}."
                    ),
                    rationale=(
                        "MITRE ATT&CK provides a comprehensive framework for adversary behavior. "
                        "When audit rules don't cover key techniques, attackers can operate "
                        "without generating audit events, creating blind spots in detection "
                        "and forensic investigation. Each uncovered technique represents a "
                        "gap in the detection coverage."
                    ),
                    remediation=(
                        "Add audit rules for uncovered techniques. "
                        "See: https://github.com/Neo23x0/auditd"
                        "/tree/master/auditd/rules for technique-specific rules. "
                        "Consider installing CIS or STIG audit rule sets."
                    ),
                    evidence=RegistryEvidence(
                        key="auditd.mitre_uncovered",
                        value=", ".join(uncovered),
                        expected="All techniques covered",
                        source="auditctl -l",
                    ),
                    detected_value=f"Uncovered: {', '.join(uncovered)}",
                    expected_value="All MITRE ATT&CK techniques covered",
                    affected_component="/etc/audit/rules.d/",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1070", "T1562"],
                    tags=["auditing", "mitre-attack", "detection", "coverage"],
                )
            )

        return findings


@register_check
class LogFilePermissionsCheck(AuditCheck):
    id = "LOG-302"
    name = "Log File Permissions"
    category = CheckCategory.FORENSICS
    severity = Severity.MEDIUM
    description = "Checks that system log files have restricted permissions to prevent tampering"
    depends = []
    tags = ["forensics", "logging", "permissions", "tamper"]

    _LOG_DIRS = [
        "/var/log",
        "/var/log/journal",
        "/var/log/audit",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []

        for log_dir in self._LOG_DIRS:
            dp = Path(log_dir)
            if not dp.is_dir():
                continue
            try:
                for f in dp.rglob("*"):
                    if not f.is_file():
                        continue
                    if f.name.endswith(".journal") or f.name.endswith(".log"):
                        mode = f.stat().st_mode & 0o777
                        if mode & 0o007:
                            findings.append(
                                self.finding(
                                    finding_id="001",
                                    title=f"World-readable log file: {f}",
                                    description=f"Log file '{f}' has permissions {oct(mode)}, "
                                    f"which allows world-read access. Log files should be "
                                    f"restricted to owner and group read-only (640).",
                                    rationale="World-readable log files allow any user on the system "
                                    "to read sensitive information including IP addresses, "
                                    "authentication events, and system activity patterns.",
                                    remediation=f"Fix permissions: chmod 640 '{f}'",
                                    evidence=FileEvidence(
                                        path=str(f),
                                        permission=oct(mode),
                                        content=f"World-readable log: {oct(mode)}",
                                    ),
                                    detected_value=f"Permissions {oct(mode)}",
                                    expected_value="Permissions 640 (owner/group read)",
                                    affected_component=str(f),
                                    confidence=Confidence.MEDIUM,
                                    false_positive_probability=0.1,
                                    mitre_attack_ids=["T1070", "T1562.002"],
                                    tags=["logging", "permissions", "tamper"],
                                )
                            )
            except PermissionError:
                continue
        return findings


@register_check
class RepeatedSudoFailuresCheck(AuditCheck):
    id = "LOG-401"
    name = "Repeated Sudo Authentication Failures"
    category = CheckCategory.AUDIT
    severity = Severity.HIGH
    description = "Detects repeated sudo authentication failures indicating brute force attempts"
    depends = ["auditd"]
    tags = ["auditing", "sudo", "brute-force", "authentication"]

    _FAIL_THRESHOLD = 5

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        audit_data = self._get_data(collectors, "auditd")
        status = audit_data.get("status", {})
        rules = audit_data.get("rules", [])

        if not status.get("running", False):
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Auditd not running — cannot monitor sudo failures",
                    description="The audit daemon is not running. Without auditd, "
                    "sudo authentication failures cannot be monitored.",
                    rationale="Auditd provides detailed logging of authentication events. "
                    "Without it, brute force attempts against sudo may go undetected.",
                    remediation="Enable and start auditd: systemctl enable auditd && systemctl start auditd",
                    evidence=RegistryEvidence(
                        key="auditd.running",
                        value="false",
                        expected="true",
                        source="auditctl -s",
                    ),
                    detected_value="auditd not running",
                    expected_value="auditd running and monitoring",
                    affected_component="auditd",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.01,
                    mitre_attack_ids=["T1070", "T1110"],
                    tags=["auditing", "sudo", "brute-force"],
                )
            )
            return findings

        has_sudo_rule = any(
            "sudo" in r.get("rule", "").lower()
            or "-w /etc/sudoers" in r.get("rule", "")
            or "-w /etc/sudoers.d" in r.get("rule", "")
            for r in rules
        )

        if not has_sudo_rule:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="No audit rule for sudo events",
                    description="Auditd has no rule monitoring sudo configuration or execution. "
                    "Sudo authentication failures will not be audited.",
                    rationale="Without audit rules for sudo events, repeated sudo failures "
                    "(indicating brute force attempts) will not be logged or detected.",
                    remediation="Add audit rules: "
                    "auditctl -w /etc/sudoers -p wa -k sudo_changes && "
                    "auditctl -w /etc/sudoers.d -p wa -k sudo_changes. "
                    "Make persistent in /etc/audit/rules.d/audit.rules",
                    evidence=RegistryEvidence(
                        key="auditd.rules",
                        value="No sudo rules found",
                        expected="sudo-related audit rules present",
                        source="auditctl -l",
                    ),
                    detected_value="No sudo audit rules",
                    expected_value="Audit rules for sudo events",
                    affected_component="/etc/audit/rules.d/",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.02,
                    mitre_attack_ids=["T1070", "T1110"],
                    tags=["auditing", "sudo", "rules"],
                )
            )
        return findings


@register_check
class RepeatedSSHFailuresCheck(AuditCheck):
    id = "LOG-402"
    name = "Repeated SSH Authentication Failures"
    category = CheckCategory.AUDIT
    severity = Severity.HIGH
    description = "Detects repeated SSH authentication failures indicating brute force attacks"
    depends = ["auditd"]
    tags = ["auditing", "ssh", "brute-force", "authentication"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        audit_data = self._get_data(collectors, "auditd")
        status = audit_data.get("status", {})
        rules = audit_data.get("rules", [])

        if not status.get("running", False):
            return findings

        has_ssh_rule = any(
            "ssh" in r.get("rule", "").lower()
            for r in rules
        )
        has_wtmp_rule = any(
            "wtmp" in r.get("rule", "").lower()
            or "faillock" in r.get("rule", "").lower()
            or "lastlog" in r.get("rule", "").lower()
            for r in rules
        )

        if not has_ssh_rule and not has_wtmp_rule:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="No audit rule for SSH authentication events",
                    description="Auditd has no rule monitoring SSH authentication. "
                    "Repeated SSH failures (brute force) will not be audited.",
                    rationale="SSH brute force attacks are among the most common attack vectors. "
                    "Without auditing SSH events, these attacks go undetected until successful.",
                    remediation="Add SSH audit rules in /etc/audit/rules.d/audit.rules: "
                    "-w /var/log/btmp -p wa -k ssh_brute && "
                    "-w /var/log/faillock -p wa -k ssh_faillock. "
                    "Also consider fail2ban for active blocking.",
                    evidence=RegistryEvidence(
                        key="auditd.rules",
                        value="No SSH audit rules",
                        expected="SSH-related audit rules present",
                        source="auditctl -l",
                    ),
                    detected_value="No SSH authentication audit rules",
                    expected_value="Audit rules for SSH auth events",
                    affected_component="/etc/audit/rules.d/",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1070", "T1110", "T1190"],
                    tags=["auditing", "ssh", "brute-force", "rules"],
                )
            )
        return findings


@register_check
class AuditdRuleCoverageCheck(AuditCheck):
    id = "LOG-501"
    name = "Auditd Rule Coverage Gaps"
    category = CheckCategory.AUDIT
    severity = Severity.MEDIUM
    description = "Checks that auditd has comprehensive rule coverage for key security events"
    depends = ["auditd"]
    tags = ["auditing", "rules", "coverage", "compliance"]

    _RECOMMENDED_RULES = {
        "time_change": ["adjtimex", "settimeofday", "clock_settime", "-a always,exit -S adjtimex"],
        "user_group": ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"],
        "network_config": ["/etc/hosts", "/etc/hostname", "/etc/network", "-a always,exit -S sethostname"],
        "system_auth": ["/etc/pam.d", "/etc/security", "/etc/sudoers"],
        "kernel_modules": ["-w /sbin/insmod", "-w /sbin/modprobe", "-w /sbin/rmmod", "-a always,exit -S init_module"],
        "login_events": ["/var/log/wtmp", "/var/log/btmp", "/var/log/faillock"],
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        audit_data = self._get_data(collectors, "auditd")
        status = audit_data.get("status", {})
        rules = audit_data.get("rules", [])

        if not status.get("running", False):
            return findings

        if not rules:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="No audit rules configured",
                    description="Auditd is running but has zero rules loaded. "
                    "No system events are being audited.",
                    rationale="Without audit rules, critical security events like "
                    "file access, privilege escalation, and authentication are not logged, "
                    "making incident detection and forensic investigation impossible.",
                    remediation="Install CIS-compliant audit rules: "
                    "apt install auditd && "
                    "cp /usr/share/doc/auditd/examples/stig.rules /etc/audit/rules.d/audit.rules",
                    evidence=RegistryEvidence(
                        key="auditd.rule_count",
                        value="0",
                        expected="10+ rules",
                        source="auditctl -l",
                    ),
                    detected_value="Zero audit rules",
                    expected_value="10+ audit rules for security events",
                    affected_component="/etc/audit/rules.d/",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.01,
                    mitre_attack_ids=["T1070", "T1562"],
                    tags=["auditing", "rules", "coverage"],
                )
            )
            return findings

        rule_text = " ".join(r.get("rule", "") for r in rules)
        missing_categories: list[str] = []

        for cat, patterns in self._RECOMMENDED_RULES.items():
            covered = any(p in rule_text for p in patterns)
            if not covered:
                missing_categories.append(cat)

        if missing_categories:
            findings.append(
                self.finding(
                    finding_id="002",
                    title=f"Missing audit rule categories: {', '.join(missing_categories)}",
                    description=f"Auditd is missing rules for {len(missing_categories)} key area(s): "
                    f"{', '.join(missing_categories)}. Total rules: {len(rules)}.",
                    rationale="Missing audit rules create blind spots for security monitoring. "
                    "Attackers can operate in these gaps undetected.",
                    remediation=f"Add rules for: {', '.join(missing_categories)}. "
                    "See CIS Benchmark or STIG for comprehensive audit rule sets.",
                    evidence=RegistryEvidence(
                        key="auditd.coverage_gaps",
                        value=", ".join(missing_categories),
                        expected="All categories covered",
                        source="auditctl -l",
                    ),
                    detected_value=f"Missing: {', '.join(missing_categories)}",
                    expected_value="All security event categories covered",
                    affected_component="/etc/audit/rules.d/",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1070", "T1562"],
                    tags=["auditing", "rules", "coverage", "compliance"],
                )
            )
        return findings


@register_check
class AuditdLogExhaustionCheck(AuditCheck):
    id = "LOG-502"
    name = "Auditd Log Exhaustion Risk"
    category = CheckCategory.AUDIT
    severity = Severity.MEDIUM
    description = "Detects audit log exhaustion risk — large logs or missing rotation"
    depends = ["auditd"]
    tags = ["auditing", "logs", "disk-space", "rotation"]

    _MAX_LOG_SIZE_BYTES = 500 * 1024 * 1024

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        audit_data = self._get_data(collectors, "auditd")
        log_stats = audit_data.get("log_stats", {})

        log_size = log_stats.get("log_size_bytes")
        log_exists = log_stats.get("log_exists", False)

        if not log_exists:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Audit log file does not exist",
                    description="/var/log/audit/audit.log is missing. No audit events "
                    "are being recorded.",
                    rationale="Without an audit log file, there is no record of security events. "
                    "This is a critical gap for incident detection and compliance.",
                    remediation="Start auditd: systemctl start auditd. "
                    "Verify: auditctl -s. Check audit rules are loaded.",
                    evidence=FileEvidence(
                        path="/var/log/audit/audit.log",
                        content="File does not exist",
                    ),
                    detected_value="No audit log file",
                    expected_value="Non-empty audit.log",
                    affected_component="/var/log/audit/audit.log",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.01,
                    mitre_attack_ids=["T1070", "T1562"],
                    tags=["auditing", "logs"],
                )
            )
            return findings

        if log_size and log_size > self._MAX_LOG_SIZE_BYTES:
            size_mb = log_size / (1024 * 1024)
            findings.append(
                self.finding(
                    finding_id="002",
                    title=f"Audit log is very large ({size_mb:.0f} MB)",
                    description=f"Audit log is {size_mb:.0f} MB, which exceeds the "
                    f"recommended maximum of {self._MAX_LOG_SIZE_BYTES / (1024 * 1024):.0f} MB. "
                    "Large logs may cause disk exhaustion and service disruption.",
                    rationale="Unbounded audit logs can fill the filesystem, causing service "
                    "failures. Large logs also slow down forensic searches and may lead to "
                    "log rotation failures.",
                    remediation="Configure log rotation: "
                    "Set max_log_file and num_logs in /etc/audit/auditd.conf. "
                    "Example: max_log_file = 100, num_logs = 5. "
                    "Restart auditd after changes.",
                    evidence=FileEvidence(
                        path="/var/log/audit/audit.log",
                        size=log_size,
                        content=f"Log size: {size_mb:.0f} MB",
                    ),
                    detected_value=f"Log size: {size_mb:.0f} MB",
                    expected_value=f"Log size < {self._MAX_LOG_SIZE_BYTES / (1024 * 1024):.0f} MB",
                    affected_component="/var/log/audit/audit.log",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1070", "T1562"],
                    tags=["auditing", "logs", "disk-space"],
                )
            )

        log_count = log_stats.get("log_count")
        if log_count is not None and log_count < 2:
            findings.append(
                self.finding(
                    finding_id="003",
                    title="No audit log rotation detected",
                    description=f"Only {log_count} audit log file(s) found. Multiple log files "
                    "indicate that rotation is working.",
                    rationale="Without log rotation, the audit log grows unbounded and older "
                    "entries are never archived. This makes historical searches difficult "
                    "and risks disk exhaustion.",
                    remediation="Configure log rotation in /etc/audit/auditd.conf: "
                    "max_log_file = 100, num_logs = 5, max_log_file_action = ROTATE. "
                    "Restart auditd after changes.",
                    evidence=RegistryEvidence(
                        key="auditd.log_count",
                        value=str(log_count),
                        expected="2+ (rotation active)",
                        source="/var/log/audit",
                    ),
                    detected_value=f"{log_count} audit log file(s)",
                    expected_value="Multiple audit log files (rotation active)",
                    affected_component="/var/log/audit",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1070"],
                    tags=["auditing", "logs", "rotation"],
                )
            )
        return findings
