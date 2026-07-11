from __future__ import annotations

from unittest.mock import patch

from usaf.checks.forensics.log_checks import (
    AuditdLogExhaustionCheck,
    AuditdRuleCoverageCheck,
    JournalMaxSizeCheck,
    LogFilePermissionsCheck,
    LogRotationCheck,
    LogTamperCheck,
    RepeatedSSHFailuresCheck,
    RepeatedSudoFailuresCheck,
)


class TestJournalMaxSizeCheck:
    def test_no_findings_when_configured(self):
        check = JournalMaxSizeCheck()
        collectors = {
            "journald": {
                "config": {"max_use": "4G", "max_retention_sec": "1month", "storage": "auto"}
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_no_limit_finding(self):
        check = JournalMaxSizeCheck()
        collectors = {
            "journald": {
                "config": {"max_use": None, "max_retention_sec": None, "storage": "auto"}
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        ids = [f.id for f in result.findings]
        assert any("003" in f_id for f_id in ids)

    def test_storage_none(self):
        check = JournalMaxSizeCheck()
        collectors = {
            "journald": {
                "config": {"max_use": "4G", "max_retention_sec": None, "storage": "none"}
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert any("001" in f.id for f in result.findings)

    def test_storage_volatile(self):
        check = JournalMaxSizeCheck()
        collectors = {
            "journald": {
                "config": {"max_use": None, "max_retention_sec": None, "storage": "volatile"}
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_check_id(self):
        assert JournalMaxSizeCheck.id == "LOG-101"

    def test_check_category(self):
        assert JournalMaxSizeCheck.category.value == "AUDIT"


class TestLogRotationCheck:
    def test_no_findings_with_persistent_logs_and_rotation(self):
        check = LogRotationCheck()
        collectors = {
            "journald": {
                "persistence": {"persistent_logs": True},
                "log_files": [{"path": "a.journal"}, {"path": "b.journal"}],
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_no_persistent_logs(self):
        check = LogRotationCheck()
        collectors = {
            "journald": {
                "persistence": {"persistent_logs": False},
                "log_files": [],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert any("001" in f.id for f in result.findings)

    def test_single_journal_file(self):
        check = LogRotationCheck()
        collectors = {
            "journald": {
                "persistence": {"persistent_logs": True},
                "log_files": [{"path": "a.journal"}],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_check_id(self):
        assert LogRotationCheck.id == "LOG-201"


class TestLogTamperCheck:
    def test_no_findings_when_no_usage_data(self):
        check = LogTamperCheck()
        collectors = {"journald": {"usage": {"oldest_entry": None, "newest_entry": None}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_recent_timeline_no_findings(self):
        check = LogTamperCheck()
        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        newest_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
        oldest_dt = now - __import__("datetime").timedelta(days=2)
        oldest_str = oldest_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        collectors = {
            "journald": {
                "usage": {
                    "oldest_entry": oldest_str,
                    "newest_entry": newest_str,
                }
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_very_short_timeline(self):
        check = LogTamperCheck()
        collectors = {
            "journald": {
                "usage": {
                    "oldest_entry": "2026-07-01 11:30:00 UTC",
                    "newest_entry": "2026-07-01 11:45:00 UTC",
                }
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_check_id(self):
        assert LogTamperCheck.id == "LOG-301"


class TestLogFilePermissionsCheck:
    def test_no_findings_when_no_files(self):
        check = LogFilePermissionsCheck()
        with patch("pathlib.Path.rglob", return_value=[]):
            result = check.evaluate({})
        assert result.passed

    def test_check_id(self):
        assert LogFilePermissionsCheck.id == "LOG-302"


class TestRepeatedSudoFailuresCheck:
    def test_no_findings_when_auditd_with_sudo_rule(self):
        check = RepeatedSudoFailuresCheck()
        collectors = {
            "auditd": {
                "status": {"running": True},
                "rules": [{"rule": "-w /etc/sudoers -p wa -k sudo_changes"}],
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_auditd_not_running(self):
        check = RepeatedSudoFailuresCheck()
        collectors = {
            "auditd": {
                "status": {"running": False},
                "rules": [],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_missing_sudo_rule(self):
        check = RepeatedSudoFailuresCheck()
        collectors = {
            "auditd": {
                "status": {"running": True},
                "rules": [{"rule": "-w /etc/passwd -p wa -k passwd_changes"}],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_check_id(self):
        assert RepeatedSudoFailuresCheck.id == "LOG-401"


class TestRepeatedSSHFailuresCheck:
    def test_no_findings_when_auditd_not_running(self):
        check = RepeatedSSHFailuresCheck()
        collectors = {
            "auditd": {
                "status": {"running": False},
                "rules": [],
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_no_findings_with_ssh_rules(self):
        check = RepeatedSSHFailuresCheck()
        collectors = {
            "auditd": {
                "status": {"running": True},
                "rules": [{"rule": "-w /var/log/btmp -p wa -k ssh_brute"}],
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_missing_ssh_rule(self):
        check = RepeatedSSHFailuresCheck()
        collectors = {
            "auditd": {
                "status": {"running": True},
                "rules": [{"rule": "-w /etc/passwd -p wa -k passwd_changes"}],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_check_id(self):
        assert RepeatedSSHFailuresCheck.id == "LOG-402"


class TestAuditdRuleCoverageCheck:
    def test_no_findings_with_full_coverage(self):
        check = AuditdRuleCoverageCheck()
        collectors = {
            "auditd": {
                "status": {"running": True},
                "rules": [
                    {"rule": "-a always,exit -S adjtimex -k time_change"},
                    {"rule": "-w /etc/passwd -p wa -k user_group"},
                    {"rule": "-w /etc/hosts -p wa -k network_config"},
                    {"rule": "-w /etc/pam.d -p wa -k system_auth"},
                    {"rule": "-w /sbin/insmod -p wa -k kernel_modules"},
                    {"rule": "-w /var/log/wtmp -p wa -k login_events"},
                ],
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_empty_rules(self):
        check = AuditdRuleCoverageCheck()
        collectors = {
            "auditd": {
                "status": {"running": True},
                "rules": [],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_coverage_gaps(self):
        check = AuditdRuleCoverageCheck()
        collectors = {
            "auditd": {
                "status": {"running": True},
                "rules": [{"rule": "-w /etc/passwd -p wa -k user_group"}],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert any("002" in f.id for f in result.findings)

    def test_check_id(self):
        assert AuditdRuleCoverageCheck.id == "LOG-501"


class TestAuditdLogExhaustionCheck:
    def test_no_findings_when_log_is_small(self):
        check = AuditdLogExhaustionCheck()
        collectors = {
            "auditd": {
                "log_stats": {"log_exists": True, "log_size_bytes": 10 * 1024 * 1024, "log_count": 5}
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_log_does_not_exist(self):
        check = AuditdLogExhaustionCheck()
        collectors = {
            "auditd": {
                "log_stats": {"log_exists": False, "log_size_bytes": None, "log_count": None}
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_large_log(self):
        check = AuditdLogExhaustionCheck()
        collectors = {
            "auditd": {
                "log_stats": {"log_exists": True, "log_size_bytes": 600 * 1024 * 1024, "log_count": 3}
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_no_rotation(self):
        check = AuditdLogExhaustionCheck()
        collectors = {
            "auditd": {
                "log_stats": {"log_exists": True, "log_size_bytes": 10 * 1024 * 1024, "log_count": 1}
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed

    def test_check_id(self):
        assert AuditdLogExhaustionCheck.id == "LOG-502"
