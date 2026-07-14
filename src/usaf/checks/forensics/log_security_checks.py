from __future__ import annotations

import datetime
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class JournaldCompressionCheck(AuditCheck):
    id = "LOG-601"
    name = "Journald Compression"
    category = CheckCategory.AUDIT
    severity = Severity.LOW
    description = "Checks that journald log compression is enabled"
    depends = ["journald"]
    tags = ["logging", "journald", "compression", "disk-space"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        config = data.get("config", {})

        compress = config.get("compress")

        if compress is True:
            return findings

        if compress is False:
            value = "no"
        else:
            value = "not set (defaults to yes)"

        findings.append(
            self.finding(
                finding_id="001",
                title="Journald compression is not enabled",
                description=(
                    f"Journald Compress={value}. Log compression should be explicitly "
                    f"enabled to reduce disk usage for journal logs."
                ),
                rationale=(
                    "Journal files grow quickly on active systems. Without compression, "
                    "log data consumes significantly more disk space, increasing the risk "
                    "of log loss due to disk exhaustion and reducing the available retention "
                    "window for forensic analysis."
                ),
                remediation=(
                    "Set Compress=yes in /etc/systemd/journald.conf and restart: "
                    "systemctl restart systemd-journald"
                ),
                evidence=RegistryEvidence(
                    key="journald.Compress",
                    value=str(compress),
                    expected="yes",
                    source="/etc/systemd/journald.conf",
                ),
                detected_value=f"Compress={compress}",
                expected_value="Compress=yes",
                affected_component="journald configuration",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.3,
                mitre_attack_ids=["T1070.004"],
                tags=["logging", "journald", "compression", "disk-space"],
            )
        )
        return findings


@register_check
class JournaldForwardingCheck(AuditCheck):
    id = "LOG-602"
    name = "Journald Log Forwarding"
    category = CheckCategory.AUDIT
    severity = Severity.MEDIUM
    description = "Checks that journald does not forward logs to insecure channels"
    depends = ["journald"]
    tags = ["logging", "journald", "forwarding", "information-disclosure"]

    INSECURE_FORWARD_KEYS: dict[str, str] = {
        "forward_to_kmsg": "ForwardToKmsg",
        "forward_to_console": "ForwardToConsole",
    }

    FORWARD_RATIONALES: dict[str, str] = {
        "forward_to_kmsg": (
            "Forwarding to kmsg writes log entries to the kernel ring buffer, which is "
            "readable by all users via dmesg. This exposes potentially sensitive information "
            "in the kernel log."
        ),
        "forward_to_console": (
            "Forwarding to console writes log entries to the system console (/dev/console). "
            "This exposes log data to anyone with console access and may leak sensitive "
            "information through serial consoles or virtual terminals."
        ),
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        config = data.get("config", {})

        for key, display_name in self.INSECURE_FORWARD_KEYS.items():
            enabled = config.get(key)

            if enabled is not True and enabled is not False:
                continue
            if not enabled:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Journald {display_name} is enabled",
                    description=(
                        f"Journald {display_name}=yes. Log entries are being forwarded "
                        f"to an insecure or publicly visible channel."
                    ),
                    rationale=self.FORWARD_RATIONALES.get(key, "Log forwarding to insecure channels should be disabled."),
                    remediation=(
                        f"Set {display_name}=no in /etc/systemd/journald.conf and restart: "
                        f"systemctl restart systemd-journald"
                    ),
                    evidence=RegistryEvidence(
                        key=f"journald.{display_name}",
                        value="yes",
                        expected="no",
                        source="/etc/systemd/journald.conf",
                    ),
                    detected_value=f"{display_name}=yes",
                    expected_value=f"{display_name}=no",
                    affected_component="journald configuration",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1070.004"],
                    tags=["logging", "journald", "forwarding", "information-disclosure"],
                )
            )
        return findings


@register_check
class JournaldSyncIntervalCheck(AuditCheck):
    id = "LOG-603"
    name = "Journald Sync Interval"
    category = CheckCategory.AUDIT
    severity = Severity.LOW
    description = "Checks that journald sync interval is configured for timely log persistence"
    depends = ["journald"]
    tags = ["logging", "journald", "sync", "durability"]

    MAX_SYNC_INTERVAL_SEC = 900

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        config = data.get("config", {})

        sync_interval = config.get("sync_interval_sec")

        if sync_interval is None:
            return findings

        try:
            interval = int(sync_interval)
        except (ValueError, TypeError):
            return findings

        if interval <= self.MAX_SYNC_INTERVAL_SEC:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Journald sync interval is too long",
                description=(
                    f"Journald SyncIntervalSec={sync_interval}s. The sync interval "
                    f"determines how often journal data is flushed to disk."
                ),
                rationale=(
                    "A long sync interval increases the window for log data loss during "
                    "a crash or power failure. Logs generated between syncs may be "
                    "permanently lost, impeding forensic investigation."
                ),
                remediation=(
                    "Set SyncIntervalSec=900 or lower in /etc/systemd/journald.conf "
                    "and restart: systemctl restart systemd-journald"
                ),
                evidence=RegistryEvidence(
                    key="journald.SyncIntervalSec",
                    value=f"{sync_interval}s",
                    expected=f"<={self.MAX_SYNC_INTERVAL_SEC}s",
                    source="/etc/systemd/journald.conf",
                ),
                detected_value=f"SyncIntervalSec={sync_interval}s",
                expected_value=f"SyncIntervalSec<={self.MAX_SYNC_INTERVAL_SEC}s",
                affected_component="journald configuration",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.3,
                mitre_attack_ids=["T1070.004"],
                tags=["logging", "journald", "sync", "durability"],
            )
        )
        return findings


@register_check
class JournaldMaxFileSizeCheck(AuditCheck):
    id = "LOG-604"
    name = "Journald Max File Size"
    category = CheckCategory.AUDIT
    severity = Severity.MEDIUM
    description = "Checks that journald max file size is configured for predictable log management"
    depends = ["journald"]
    tags = ["logging", "journald", "disk-space", "rotation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        config = data.get("config", {})

        max_file_size = config.get("max_file_size")

        if max_file_size is not None:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Journald max file size not configured",
                description=(
                    "Journald SystemMaxFileSize is not set. Journal files can grow "
                    "unbounded until SystemMaxUse is reached, causing log fragmentation."
                ),
                rationale=(
                    "Without a max file size limit, individual journal files may grow very "
                    "large, making them difficult to rotate, transfer, and analyze. Setting "
                    "a reasonable max file size ensures predictable log file sizes and "
                    "cleaner log rotation behavior."
                ),
                remediation=(
                    "Set SystemMaxFileSize=100M in /etc/systemd/journald.conf and restart: "
                    "systemctl restart systemd-journald"
                ),
                evidence=RegistryEvidence(
                    key="journald.SystemMaxFileSize",
                    value="not set",
                    expected="a reasonable size (e.g., 100M)",
                    source="/etc/systemd/journald.conf",
                ),
                detected_value="SystemMaxFileSize not set",
                expected_value="SystemMaxFileSize set to a reasonable value",
                affected_component="journald configuration",
                confidence=Confidence.LOW,
                false_positive_probability=0.5,
                mitre_attack_ids=["T1070.004"],
                tags=["logging", "journald", "disk-space", "rotation"],
            )
        )
        return findings


@register_check
class JournaldKeepFreeCheck(AuditCheck):
    id = "LOG-605"
    name = "Journald Keep Free Space"
    category = CheckCategory.AUDIT
    severity = Severity.MEDIUM
    description = "Checks that journald is configured to preserve free disk space"
    depends = ["journald"]
    tags = ["logging", "journald", "disk-space", "availability"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        config = data.get("config", {})

        keep_free = config.get("keep_free")

        if keep_free is not None:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Journald keep free space not configured",
                description=(
                    "Journald SystemKeepFree is not set. The journal may fill available "
                    "disk space, potentially impacting other services."
                ),
                rationale=(
                    "Without a KeepFree setting, journald may consume all available disk "
                    "space up to SystemMaxUse. If SystemMaxUse is also unset, the journal "
                    "can grow until it fills the filesystem, causing service failures and "
                    "system instability."
                ),
                remediation=(
                    "Set SystemKeepFree=1G in /etc/systemd/journald.conf and restart: "
                    "systemctl restart systemd-journald"
                ),
                evidence=RegistryEvidence(
                    key="journald.SystemKeepFree",
                    value="not set",
                    expected="a reasonable value (e.g., 1G)",
                    source="/etc/systemd/journald.conf",
                ),
                detected_value="SystemKeepFree not set",
                expected_value="SystemKeepFree set to a reasonable value",
                affected_component="journald configuration",
                confidence=Confidence.LOW,
                false_positive_probability=0.4,
                mitre_attack_ids=["T1070.004", "T1499"],
                tags=["logging", "journald", "disk-space", "availability"],
            )
        )
        return findings


@register_check
class JournaldRuntimeOnlyCheck(AuditCheck):
    id = "LOG-606"
    name = "Journald Runtime-Only Logging"
    category = CheckCategory.AUDIT
    severity = Severity.HIGH
    description = "Detects when journald is running in volatile (runtime-only) mode"
    depends = ["journald"]
    tags = ["logging", "journald", "persistence", "forensics"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        config = data.get("config", {})
        persistence = data.get("persistence", {})

        runtime_only = persistence.get("runtime_logs_only", False)
        storage = config.get("storage")

        if not runtime_only and storage != "volatile":
            return findings

        if runtime_only:
            value = "runtime-only (no /var/log/journal directory)"
        else:
            value = f"Storage={storage}"

        findings.append(
            self.finding(
                finding_id="001",
                title="Journald logging is volatile",
                description=(
                    f"Journald is configured for {value}. All log data is stored in "
                    f"/run/systemd/journal and will be lost on system reboot."
                ),
                rationale=(
                    "Volatile (runtime-only) logging means all system logs are lost on "
                    "reboot. This eliminates forensic evidence of attacks, makes incident "
                    "response impossible after restart, and prevents detection of "
                    "persistent threats across boot cycles."
                ),
                remediation=(
                    "Create persistent journal directory and set Storage=auto in "
                    "/etc/systemd/journald.conf: "
                    "mkdir -p /var/log/journal && systemctl restart systemd-journald"
                ),
                evidence=RegistryEvidence(
                    key="journald.Storage",
                    value=str(storage) if storage else "runtime-only",
                    expected="persistent or auto",
                    source="/etc/systemd/journald.conf",
                ),
                detected_value=value,
                expected_value="persistent logging (/var/log/journal exists)",
                affected_component="journald configuration",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                mitre_attack_ids=["T1070.004", "T1562.002"],
                cis_benchmarks=["CIS Ubuntu 20.04: 4.2"],
                tags=["logging", "journald", "persistence", "forensics"],
            )
        )
        return findings


@register_check
class LogRetentionFreshnessCheck(AuditCheck):
    id = "LOG-607"
    name = "Log Retention Freshness"
    category = CheckCategory.AUDIT
    severity = Severity.MEDIUM
    description = "Checks that journald retains logs for a sufficient period"
    depends = ["journald"]
    tags = ["logging", "journald", "retention", "forensics"]

    MIN_RETENTION_DAYS = 7

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        config = data.get("config", {})
        usage = data.get("usage", {})

        max_retention = config.get("max_retention_sec")

        if max_retention is not None:
            try:
                retention_sec = int(max_retention)
                retention_days = retention_sec / 86400
                if retention_days >= self.MIN_RETENTION_DAYS:
                    return findings
            except (ValueError, TypeError):
                pass

        oldest_entry = usage.get("oldest_entry")
        if oldest_entry:
            retention_days = self._estimate_retention_days(oldest_entry)
            if retention_days >= self.MIN_RETENTION_DAYS:
                return findings

        if max_retention is not None:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Log retention period is too short",
                    description=(
                        f"Journald MaxRetentionSec={max_retention} ("
                        f"{retention_days:.1f} days). Logs are retained for less "
                        f"than {self.MIN_RETENTION_DAYS} days."
                    ),
                    rationale=(
                        "Short log retention limits forensic analysis windows. Attacks may "
                        "go undetected for days or weeks; without sufficient log history, "
                        "investigators cannot determine the scope or timeline of a breach."
                    ),
                    remediation=(
                        f"Increase MaxRetentionSec in /etc/systemd/journald.conf to at "
                        f"least {self.MIN_RETENTION_DAYS * 86400} ({self.MIN_RETENTION_DAYS} days)."
                    ),
                    evidence=RegistryEvidence(
                        key="journald.MaxRetentionSec",
                        value=str(max_retention),
                        expected=f">={self.MIN_RETENTION_DAYS * 86400}",
                        source="/etc/systemd/journald.conf",
                    ),
                    detected_value=f"MaxRetentionSec={max_retention} ({retention_days:.1f} days)",
                    expected_value=f"At least {self.MIN_RETENTION_DAYS} days retention",
                    affected_component="journald configuration",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1070.004"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 4.2"],
                    tags=["logging", "journald", "retention", "forensics"],
                )
            )
        else:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Log retention period not configured",
                    description=(
                        "Journald MaxRetentionSec is not set. Actual retention depends on "
                        "disk space and log volume, which may result in insufficient "
                        "retention during high-volume logging periods."
                    ),
                    rationale=(
                        "Without an explicit retention policy, log retention is determined "
                        "by available disk space. During high-volume logging or under "
                        "disk pressure, older logs may be rotated out before forensic "
                        "needs are met."
                    ),
                    remediation=(
                        f"Set MaxRetentionSec={self.MIN_RETENTION_DAYS * 86400} "
                        f"({self.MIN_RETENTION_DAYS} days) in /etc/systemd/journald.conf."
                    ),
                    evidence=RegistryEvidence(
                        key="journald.MaxRetentionSec",
                        value="not set",
                        expected=f">={self.MIN_RETENTION_DAYS * 86400}",
                        source="/etc/systemd/journald.conf",
                    ),
                    detected_value="MaxRetentionSec not set",
                    expected_value=f"At least {self.MIN_RETENTION_DAYS} days retention",
                    affected_component="journald configuration",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1070.004"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 4.2"],
                    tags=["logging", "journald", "retention", "forensics"],
                )
            )
        return findings

    def _estimate_retention_days(self, oldest_entry: str) -> float:
        try:
            now = datetime.datetime.now()
            parts = oldest_entry.split()
            if len(parts) >= 2:
                date_str = f"{parts[0]} {parts[1]}"
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%a %Y-%m-%d %H:%M:%S"]:
                    try:
                        dt = datetime.datetime.strptime(date_str, fmt)
                        delta = now - dt
                        return delta.total_seconds() / 86400
                    except ValueError:
                        continue
        except (ValueError, IndexError):
            pass
        return 0.0


@register_check
class LogFileCountCheck(AuditCheck):
    id = "LOG-608"
    name = "Journald Log File Count"
    category = CheckCategory.AUDIT
    severity = Severity.LOW
    description = "Checks that journald has a reasonable number of log files for proper rotation"
    depends = ["journald"]
    tags = ["logging", "journald", "rotation", "monitoring"]

    MIN_LOG_FILES = 3

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "journald")
        log_files = data.get("log_files", [])
        persistence = data.get("persistence", {})

        if not persistence.get("persistent_logs"):
            return findings

        file_count = len(log_files)

        if file_count >= self.MIN_LOG_FILES:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Very few journal log files",
                description=(
                    f"Only {file_count} journal file(s) found in /var/log/journal. "
                    f"Expected at least {self.MIN_LOG_FILES} for proper rotation."
                ),
                rationale=(
                    "A low number of journal files may indicate that log rotation is not "
                    "functioning correctly, or that the system has recently been rebooted "
                    "after a long period without logging. Insufficient journal files can "
                    "limit the available log history for forensic analysis."
                ),
                remediation=(
                    "Verify journald is running: systemctl status systemd-journald. "
                    "Check journal files: ls -la /var/log/journal/*/."
                ),
                evidence=RegistryEvidence(
                    key="journald.log_file_count",
                    value=str(file_count),
                    expected=f">={self.MIN_LOG_FILES}",
                    source="/var/log/journal",
                ),
                detected_value=f"{file_count} journal files",
                expected_value=f"At least {self.MIN_LOG_FILES} journal files",
                affected_component="/var/log/journal",
                confidence=Confidence.LOW,
                false_positive_probability=0.6,
                mitre_attack_ids=["T1070.004"],
                tags=["logging", "journald", "rotation", "monitoring"],
            )
        )
        return findings
