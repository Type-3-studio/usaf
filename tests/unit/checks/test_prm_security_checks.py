from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.permissions.prm_security_checks import (
    CriticalDirectoryOwnershipCheck,
    DangerousCapabilityCombinationsCheck,
    GroupWritableSetuidCheck,
    SetuidWithCapabilitiesCheck,
    SetuidWithoutExecuteCheck,
    SGIDOnWorldWritableDirsCheck,
    UnexpectedSGIDOnFilesCheck,
    WeakDefaultUmaskCheck,
)
from usaf.models.severity import Confidence, Severity


class MockStatResult:
    def __init__(self, mode=0o100755, uid=0, gid=0, size=1024, st_mtime=1000000.0):
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_size = size
        self.st_mtime = st_mtime
        self.st_atime = st_mtime
        self.st_ctime = st_mtime
        self.st_nlink = 1


class TestGroupWritableSetuidCheck:
    def test_passes_with_secure_suid(self):
        check = GroupWritableSetuidCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/su", "mode": "0o104755", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_group_writable_suid(self):
        check = GroupWritableSetuidCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/evil", "mode": "0o102770", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "group-writable" in f.title.lower() or "group" in f.description.lower()
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_skips_non_suid_files(self):
        check = GroupWritableSetuidCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/normal", "mode": "0o100755", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = GroupWritableSetuidCheck()
        collectors = {"filesystem": {"suid_files": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = GroupWritableSetuidCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/evil", "mode": "0o102770", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSGIDOnWorldWritableDirsCheck:
    def test_passes_with_secure_dirs(self):
        check = SGIDOnWorldWritableDirsCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/tmp", "mode": "0o41777", "uid": 0, "is_dir": True},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_sgid_on_ww_dir(self):
        check = SGIDOnWorldWritableDirsCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/var/tmp/shared", "mode": "0o42777", "uid": 0, "is_dir": True},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "SGID" in f.title or "sgid" in f.title or "SGID" in f.description
        assert f.severity == Severity.HIGH

    def test_skips_non_directory(self):
        check = SGIDOnWorldWritableDirsCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/tmp/evil", "mode": "0o102777", "uid": 0, "is_dir": False},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_skips_known_safe_paths(self):
        check = SGIDOnWorldWritableDirsCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/var/log/journal", "mode": "0o42777", "uid": 0, "is_dir": True},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = SGIDOnWorldWritableDirsCheck()
        collectors = {"filesystem": {"world_writable": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = SGIDOnWorldWritableDirsCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/var/shared", "mode": "0o42777", "uid": 1000, "is_dir": True},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSetuidWithCapabilitiesCheck:
    def test_passes_with_no_overlap(self):
        check = SetuidWithCapabilitiesCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/su", "mode": "0o104755", "uid": 0, "gid": 0, "size": 100},
                ],
                "capabilities": [
                    {"path": "/usr/bin/ping", "capabilities": "cap_net_raw=ep"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_suid_and_caps(self):
        check = SetuidWithCapabilitiesCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/overlap", "mode": "0o104755", "uid": 0, "gid": 0, "size": 100},
                ],
                "capabilities": [
                    {"path": "/usr/bin/overlap", "capabilities": "cap_setuid=ep"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "SUID" in f.title or "capabilities" in f.title.lower()
        assert f.severity == Severity.MEDIUM

    def test_fails_with_sgid_and_caps(self):
        check = SetuidWithCapabilitiesCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/sgid_tool", "mode": "0o102755", "uid": 0, "gid": 0, "size": 100},
                ],
                "capabilities": [
                    {"path": "/usr/bin/sgid_tool", "capabilities": "cap_dac_override=ep"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_handles_empty_data(self):
        check = SetuidWithCapabilitiesCheck()
        collectors = {"filesystem": {"suid_files": [], "capabilities": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = SetuidWithCapabilitiesCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/overlap", "mode": "0o104755", "uid": 0, "gid": 0, "size": 100},
                ],
                "capabilities": [
                    {"path": "/usr/bin/overlap", "capabilities": "cap_setuid=ep"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestWeakDefaultUmaskCheck:
    def test_passes_with_strong_umask(self):
        check = WeakDefaultUmaskCheck()

        with patch.object(Path, "read_text", return_value="UMASK 027\n"):
            with patch("usaf.checks.permissions.prm_security_checks.Path.exists", return_value=True):
                with patch("usaf.checks.permissions.prm_security_checks.Path.is_file", return_value=True):
                    result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_weak_umask(self):
        check = WeakDefaultUmaskCheck()

        with patch.object(Path, "read_text", return_value="UMASK 002\n"):
            with patch("usaf.checks.permissions.prm_security_checks.Path.exists", return_value=True):
                with patch("usaf.checks.permissions.prm_security_checks.Path.is_file", return_value=True):
                    result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "002" in f.detected_value or "002" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_fails_with_umask_022(self):
        check = WeakDefaultUmaskCheck()

        with patch.object(Path, "read_text", return_value="UMASK 022\n"):
            with patch("usaf.checks.permissions.prm_security_checks.Path.exists", return_value=True):
                with patch("usaf.checks.permissions.prm_security_checks.Path.is_file", return_value=True):
                    result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        assert "022" in result.findings[0].title

    def test_handles_missing_umask(self):
        check = WeakDefaultUmaskCheck()

        with patch.object(Path, "read_text", return_value="# No umask set\n"):
            with patch("usaf.checks.permissions.prm_security_checks.Path.exists", return_value=True):
                with patch("usaf.checks.permissions.prm_security_checks.Path.is_file", return_value=True):
                    result = check.evaluate({})
        assert result.passed

    def test_handles_missing_file(self):
        check = WeakDefaultUmaskCheck()

        with patch("usaf.checks.permissions.prm_security_checks.Path.exists", return_value=False):
            result = check.evaluate({})
        assert result.passed

    def test_has_cis_benchmark(self):
        check = WeakDefaultUmaskCheck()

        with patch.object(Path, "read_text", return_value="UMASK 002\n"):
            with patch("usaf.checks.permissions.prm_security_checks.Path.exists", return_value=True):
                with patch("usaf.checks.permissions.prm_security_checks.Path.is_file", return_value=True):
                    result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = WeakDefaultUmaskCheck()

        with patch.object(Path, "read_text", return_value="UMASK 002\n"):
            with patch("usaf.checks.permissions.prm_security_checks.Path.exists", return_value=True):
                with patch("usaf.checks.permissions.prm_security_checks.Path.is_file", return_value=True):
                    result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestCriticalDirectoryOwnershipCheck:
    def test_passes_when_all_root_owned(self):
        check = CriticalDirectoryOwnershipCheck()

        with (
            patch("usaf.checks.permissions.prm_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.permissions.prm_security_checks.Path.stat", return_value=MockStatResult(mode=0o100755, uid=0)),
        ):
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_non_root_owned(self):
        check = CriticalDirectoryOwnershipCheck()

        with (
            patch("usaf.checks.permissions.prm_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.permissions.prm_security_checks.Path.stat", return_value=MockStatResult(mode=0o100755, uid=1001)),
        ):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "uid 1001" in f.description
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_skips_missing_dirs(self):
        check = CriticalDirectoryOwnershipCheck()

        with patch("usaf.checks.permissions.prm_security_checks.Path.is_dir", return_value=False):
            result = check.evaluate({})
        assert result.passed

    def test_has_mitre_ids(self):
        check = CriticalDirectoryOwnershipCheck()

        with (
            patch("usaf.checks.permissions.prm_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.permissions.prm_security_checks.Path.stat", return_value=MockStatResult(mode=0o100755, uid=1001)),
        ):
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSetuidWithoutExecuteCheck:
    def test_passes_with_proper_suid(self):
        check = SetuidWithoutExecuteCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/su", "mode": "0o104755", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_suid_no_exec(self):
        check = SetuidWithoutExecuteCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/inert", "mode": "0o104644", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "inert" in f.title.lower() or "without" in f.title.lower()
        assert f.severity == Severity.MEDIUM

    def test_fails_with_sgid_no_exec(self):
        check = SetuidWithoutExecuteCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/inert_sgid", "mode": "0o102644", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_handles_empty_data(self):
        check = SetuidWithoutExecuteCheck()
        collectors = {"filesystem": {"suid_files": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = SetuidWithoutExecuteCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/inert", "mode": "0o104644", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestUnexpectedSGIDOnFilesCheck:
    def test_passes_with_no_sgid(self):
        check = UnexpectedSGIDOnFilesCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/su", "mode": "0o104755", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_skips_executable_files(self):
        check = UnexpectedSGIDOnFilesCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/bin/sgid_tool", "mode": "0o102711", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_skips_extensionless_libraries(self):
        check = UnexpectedSGIDOnFilesCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/usr/lib/libfoo.so", "mode": "0o102644", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_sgid_on_text_file(self):
        check = UnexpectedSGIDOnFilesCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/etc/sgid_config.txt", "mode": "0o102644", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "SGID" in f.title or "sgid" in f.title
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW

    def test_handles_empty_data(self):
        check = UnexpectedSGIDOnFilesCheck()
        collectors = {"filesystem": {"suid_files": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = UnexpectedSGIDOnFilesCheck()
        collectors = {
            "filesystem": {
                "suid_files": [
                    {"path": "/etc/odd_file.yaml", "mode": "0o102644", "uid": 0, "gid": 0, "size": 100},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestDangerousCapabilityCombinationsCheck:
    def test_passes_with_benign_caps(self):
        check = DangerousCapabilityCombinationsCheck()
        collectors = {
            "filesystem": {
                "capabilities": [
                    {"path": "/usr/bin/ping", "capabilities": "cap_net_raw=ep"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_dangerous_combo(self):
        check = DangerousCapabilityCombinationsCheck()
        collectors = {
            "filesystem": {
                "capabilities": [
                    {"path": "/usr/bin/danger", "capabilities": "cap_sys_admin,cap_dac_override=ep"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "Dangerous" in f.title or "capability" in f.title.lower()
        assert f.severity == Severity.HIGH or f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.HIGH

    def test_fails_with_setuid_setgid_combo(self):
        check = DangerousCapabilityCombinationsCheck()
        collectors = {
            "filesystem": {
                "capabilities": [
                    {"path": "/usr/bin/id_control", "capabilities": "cap_setuid,cap_setgid=ep"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1

    def test_handles_empty_data(self):
        check = DangerousCapabilityCombinationsCheck()
        collectors = {"filesystem": {"capabilities": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = DangerousCapabilityCombinationsCheck()
        collectors = {
            "filesystem": {
                "capabilities": [
                    {"path": "/usr/bin/danger", "capabilities": "cap_sys_admin,cap_dac_override=ep"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0
