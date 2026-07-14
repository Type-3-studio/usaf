from __future__ import annotations

from usaf.checks.forensics.log_security_checks import (
    JournaldCompressionCheck,
    JournaldForwardingCheck,
    JournaldKeepFreeCheck,
    JournaldMaxFileSizeCheck,
    JournaldRuntimeOnlyCheck,
    JournaldSyncIntervalCheck,
    LogFileCountCheck,
    LogRetentionFreshnessCheck,
)
from usaf.models.severity import Confidence, Severity


class TestJournaldCompressionCheck:
    def test_passes_when_compression_enabled(self):
        check = JournaldCompressionCheck()
        collectors = {
            "journald": {
                "config": {"compress": True},
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_compression_disabled(self):
        check = JournaldCompressionCheck()
        collectors = {
            "journald": {
                "config": {"compress": False},
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "Compress" in f.description
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.MEDIUM

    def test_fails_when_compression_not_set(self):
        check = JournaldCompressionCheck()
        collectors = {
            "journald": {
                "config": {"compress": None},
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_passes_with_empty_config(self):
        check = JournaldCompressionCheck()
        collectors = {"journald": {"config": {}}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_ids(self):
        check = JournaldCompressionCheck()
        collectors = {
            "journald": {
                "config": {"compress": False},
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestJournaldForwardingCheck:
    def test_passes_when_forwarding_disabled(self):
        check = JournaldForwardingCheck()
        collectors = {
            "journald": {
                "config": {
                    "forward_to_kmsg": False,
                    "forward_to_console": False,
                },
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_forward_to_kmsg_enabled(self):
        check = JournaldForwardingCheck()
        collectors = {
            "journald": {
                "config": {
                    "forward_to_kmsg": True,
                    "forward_to_console": False,
                },
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "ForwardToKmsg" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_fails_when_forward_to_console_enabled(self):
        check = JournaldForwardingCheck()
        collectors = {
            "journald": {
                "config": {
                    "forward_to_kmsg": False,
                    "forward_to_console": True,
                },
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "ForwardToConsole" in result.findings[0].title

    def test_fails_with_all_forwarding_enabled(self):
        check = JournaldForwardingCheck()
        collectors = {
            "journald": {
                "config": {
                    "forward_to_kmsg": True,
                    "forward_to_console": True,
                },
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 2

    def test_skips_when_forwarding_not_configured(self):
        check = JournaldForwardingCheck()
        collectors = {
            "journald": {
                "config": {
                    "forward_to_kmsg": None,
                    "forward_to_console": None,
                },
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_empty_config(self):
        check = JournaldForwardingCheck()
        collectors = {"journald": {"config": {}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = JournaldForwardingCheck()
        collectors = {
            "journald": {
                "config": {
                    "forward_to_kmsg": True,
                    "forward_to_console": False,
                },
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestJournaldSyncIntervalCheck:
    def test_passes_when_sync_interval_reasonable(self):
        check = JournaldSyncIntervalCheck()
        collectors = {
            "journald": {
                "config": {"sync_interval_sec": "300"},
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_sync_interval_default(self):
        check = JournaldSyncIntervalCheck()
        collectors = {
            "journald": {
                "config": {"sync_interval_sec": None},
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_when_sync_interval_too_long(self):
        check = JournaldSyncIntervalCheck()
        collectors = {
            "journald": {
                "config": {"sync_interval_sec": "3600"},
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "sync" in f.title.lower() or "SyncInterval" in f.title
        assert f.severity == Severity.LOW

    def test_passes_with_empty_config(self):
        check = JournaldSyncIntervalCheck()
        collectors = {"journald": {"config": {}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = JournaldSyncIntervalCheck()
        collectors = {
            "journald": {
                "config": {"sync_interval_sec": "3600"},
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestJournaldMaxFileSizeCheck:
    def test_passes_when_max_file_size_set(self):
        check = JournaldMaxFileSizeCheck()
        collectors = {
            "journald": {
                "config": {"max_file_size": "100M"},
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_max_file_size_not_set(self):
        check = JournaldMaxFileSizeCheck()
        collectors = {
            "journald": {
                "config": {"max_file_size": None},
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "max file size" in f.title.lower() or "MaxFileSize" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.LOW

    def test_passes_with_empty_config(self):
        check = JournaldMaxFileSizeCheck()
        collectors = {"journald": {"config": {}}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_ids(self):
        check = JournaldMaxFileSizeCheck()
        collectors = {
            "journald": {
                "config": {"max_file_size": None},
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestJournaldKeepFreeCheck:
    def test_passes_when_keep_free_set(self):
        check = JournaldKeepFreeCheck()
        collectors = {
            "journald": {
                "config": {"keep_free": "1G"},
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_keep_free_not_set(self):
        check = JournaldKeepFreeCheck()
        collectors = {
            "journald": {
                "config": {"keep_free": None},
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "keep free" in f.title.lower() or "KeepFree" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.LOW

    def test_passes_with_empty_config(self):
        check = JournaldKeepFreeCheck()
        collectors = {"journald": {"config": {}}}
        result = check.evaluate(collectors)
        assert not result.passed

    def test_has_mitre_ids(self):
        check = JournaldKeepFreeCheck()
        collectors = {
            "journald": {
                "config": {"keep_free": None},
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestJournaldRuntimeOnlyCheck:
    def test_passes_with_persistent_logging(self):
        check = JournaldRuntimeOnlyCheck()
        collectors = {
            "journald": {
                "config": {"storage": "auto"},
                "persistence": {
                    "runtime_logs_only": False,
                    "persistent_logs": True,
                },
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_runtime_only_logging(self):
        check = JournaldRuntimeOnlyCheck()
        collectors = {
            "journald": {
                "config": {"storage": "auto"},
                "persistence": {
                    "runtime_logs_only": True,
                    "persistent_logs": False,
                },
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "volatile" in f.title.lower() or "runtime" in f.title.lower()
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_fails_with_storage_volatile(self):
        check = JournaldRuntimeOnlyCheck()
        collectors = {
            "journald": {
                "config": {"storage": "volatile"},
                "persistence": {
                    "runtime_logs_only": False,
                    "persistent_logs": False,
                },
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_passes_with_empty_data(self):
        check = JournaldRuntimeOnlyCheck()
        collectors = {"journald": {"config": {}, "persistence": {}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_cis_benchmark(self):
        check = JournaldRuntimeOnlyCheck()
        collectors = {
            "journald": {
                "config": {"storage": "volatile"},
                "persistence": {
                    "runtime_logs_only": False,
                    "persistent_logs": False,
                },
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = JournaldRuntimeOnlyCheck()
        collectors = {
            "journald": {
                "config": {"storage": "auto"},
                "persistence": {
                    "runtime_logs_only": True,
                    "persistent_logs": False,
                },
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestLogRetentionFreshnessCheck:
    def test_passes_with_adequate_max_retention(self):
        check = LogRetentionFreshnessCheck()
        collectors = {
            "journald": {
                "config": {"max_retention_sec": "864000"},
                "usage": {},
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_insufficient_max_retention(self):
        check = LogRetentionFreshnessCheck()
        collectors = {
            "journald": {
                "config": {"max_retention_sec": "86400"},
                "usage": {},
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "retention" in f.title.lower() or "MaxRetention" in f.title
        assert f.severity == Severity.MEDIUM

    def test_warns_when_no_retention_configured(self):
        check = LogRetentionFreshnessCheck()
        collectors = {
            "journald": {
                "config": {"max_retention_sec": None},
                "usage": {"oldest_entry": None},
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "not set" in result.findings[0].description

    def test_passes_with_no_retention_but_old_entries(self):
        check = LogRetentionFreshnessCheck()
        collectors = {
            "journald": {
                "config": {"max_retention_sec": None},
                "usage": {"oldest_entry": "2026-06-01 00:00:00"},
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_warns_with_empty_data(self):
        check = LogRetentionFreshnessCheck()
        collectors = {"journald": {"config": {}, "usage": {}}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "not set" in result.findings[0].description

    def test_has_cis_benchmark(self):
        check = LogRetentionFreshnessCheck()
        collectors = {
            "journald": {
                "config": {"max_retention_sec": "86400"},
                "usage": {},
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = LogRetentionFreshnessCheck()
        collectors = {
            "journald": {
                "config": {"max_retention_sec": "86400"},
                "usage": {},
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestLogFileCountCheck:
    def test_passes_with_sufficient_log_files(self):
        check = LogFileCountCheck()
        collectors = {
            "journald": {
                "log_files": [
                    {"path": "/var/log/journal/abc/system.journal", "size": 100, "modified": 1000.0},
                    {"path": "/var/log/journal/abc/system@123.journal", "size": 200, "modified": 1001.0},
                    {"path": "/var/log/journal/abc/system@456.journal", "size": 150, "modified": 1002.0},
                    {"path": "/var/log/journal/abc/user-1000.journal", "size": 50, "modified": 1003.0},
                ],
                "persistence": {"persistent_logs": True},
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_few_log_files(self):
        check = LogFileCountCheck()
        collectors = {
            "journald": {
                "log_files": [
                    {"path": "/var/log/journal/abc/system.journal", "size": 100, "modified": 1000.0},
                ],
                "persistence": {"persistent_logs": True},
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "journal" in f.title.lower() or "log file" in f.title.lower()
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW

    def test_skips_when_persistent_logging_disabled(self):
        check = LogFileCountCheck()
        collectors = {
            "journald": {
                "log_files": [],
                "persistence": {"persistent_logs": False},
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_empty_data(self):
        check = LogFileCountCheck()
        collectors = {"journald": {"log_files": [], "persistence": {}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = LogFileCountCheck()
        collectors = {
            "journald": {
                "log_files": [
                    {"path": "/var/log/journal/abc/system.journal", "size": 100, "modified": 1000.0},
                ],
                "persistence": {"persistent_logs": True},
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0
