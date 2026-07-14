from __future__ import annotations

from unittest.mock import patch

from usaf.checks.compliance.compliance_checks import (
    AuditdServiceCheck,
    FileIntegrityToolCheck,
    GrubPasswordCheck,
    LoginBannerCheck,
    MountOptionsCheck,
    SeparatePartitionCheck,
    TimeSyncCheck,
)


class TestLoginBannerCheck:
    def test_passes_when_both_exist(self, monkeypatch):
        monkeypatch.setattr("pathlib.Path.exists", lambda _: True)
        monkeypatch.setattr("pathlib.Path.stat", lambda _: type("st", (), {"st_size": 100})())
        check = LoginBannerCheck()
        result = check.evaluate({})
        assert result.passed

    def test_fails_when_missing(self, monkeypatch):
        monkeypatch.setattr("pathlib.Path.exists", lambda _: False)
        check = LoginBannerCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 2


class TestSeparatePartitionCheck:
    def test_passes_with_separate(self):
        check = SeparatePartitionCheck()
        result = check.evaluate({"mounts": {"mounts": [
            {"mount_point": "/tmp", "options": "rw"},
            {"mount_point": "/var", "options": "rw"},
            {"mount_point": "/home", "options": "rw"},
            {"mount_point": "/var/log", "options": "rw"},
            {"mount_point": "/var/tmp", "options": "rw"},
            {"mount_point": "/var/log/audit", "options": "rw"},
        ]}})
        assert result.passed

    def test_fails_without_separate(self):
        check = SeparatePartitionCheck()
        result = check.evaluate({"mounts": {"mounts": [
            {"mount_point": "/", "options": "rw"},
        ]}})
        assert not result.passed
        assert len(result.findings) >= 1


class TestMountOptionsCheck:
    def test_passes_with_options(self):
        check = MountOptionsCheck()
        result = check.evaluate({"mounts": {"mounts": [
            {"mount_point": "/tmp", "options": "rw,nosuid,nodev,noexec"},
            {"mount_point": "/home", "options": "rw,nosuid,nodev"},
        ]}})
        assert result.passed

    def test_fails_missing_options(self):
        check = MountOptionsCheck()
        result = check.evaluate({"mounts": {"mounts": [
            {"mount_point": "/tmp", "options": "rw"},
        ]}})
        assert not result.passed

    def test_skips_unknown(self):
        check = MountOptionsCheck()
        result = check.evaluate({"mounts": {"mounts": []}})
        assert result.passed


class TestTimeSyncCheck:
    def test_passes_with_timesyncd(self):
        check = TimeSyncCheck()
        with patch.object(TimeSyncCheck, "_check_service", return_value=True):
            result = check.evaluate({})
        assert result.passed

    def test_fails_without_timesync(self):
        check = TimeSyncCheck()
        with patch.object(TimeSyncCheck, "_check_service", return_value=False):
            result = check.evaluate({})
        assert not result.passed


class TestFileIntegrityToolCheck:
    def test_passes_with_aide(self):
        check = FileIntegrityToolCheck()
        with patch.object(FileIntegrityToolCheck, "_is_installed", return_value=True):
            result = check.evaluate({})
        assert result.passed

    def test_fails_without_fim(self):
        check = FileIntegrityToolCheck()
        with patch.object(FileIntegrityToolCheck, "_is_installed", return_value=False):
            result = check.evaluate({})
        assert not result.passed


class TestGrubPasswordCheck:
    def test_passes_with_password(self, monkeypatch):
        monkeypatch.setattr("pathlib.Path.exists", lambda _: True)
        monkeypatch.setattr("pathlib.Path.read_text", lambda _: "password_pbkdf2 grub.pbkdf2.sha512.10000")
        check = GrubPasswordCheck()
        result = check.evaluate({})
        assert result.passed

    def test_fails_without_password(self, monkeypatch):
        monkeypatch.setattr("pathlib.Path.exists", lambda _: True)
        monkeypatch.setattr("pathlib.Path.read_text", lambda _: "set default=0\nset timeout=5")
        check = GrubPasswordCheck()
        result = check.evaluate({})
        assert not result.passed


class TestAuditdServiceCheck:
    def test_passes_active_enabled(self):
        check = AuditdServiceCheck()
        with patch.object(AuditdServiceCheck, "_check_active", return_value=True):
            with patch.object(AuditdServiceCheck, "_check_enabled", return_value=True):
                result = check.evaluate({})
        assert result.passed

    def test_fails_inactive(self):
        check = AuditdServiceCheck()
        with patch.object(AuditdServiceCheck, "_check_active", return_value=False):
            with patch.object(AuditdServiceCheck, "_check_enabled", return_value=True):
                result = check.evaluate({})
        assert not result.passed
