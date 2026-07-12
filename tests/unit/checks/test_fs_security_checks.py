from __future__ import annotations

import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

from usaf.checks.filesystem.fs_security_checks import (
    DotFilePermissionHijackingCheck,
    FilesystemSpaceCheck,
    HomeDirectoryPermissionsCheck,
    SensitiveFilePermissionsCheck,
    SystemBinaryOwnershipCheck,
    TempDirMountSecurityCheck,
    WorldWritableCronDirectoriesCheck,
    WorldWritableStickyBitCheck,
)
from usaf.models.severity import Confidence, Severity


class MockStatResult:
    """Helper to create mock os.stat/Path.stat results."""

    def __init__(self, mode=0o100755, uid=0, gid=0, size=1024, st_mtime=1000000.0):
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_size = size
        self.st_mtime = st_mtime
        self.st_atime = st_mtime
        self.st_ctime = st_mtime
        self.st_nlink = 1

    def st_mode_getter(self):
        return self.st_mode


class TestSensitiveFilePermissionsCheck:
    def test_passes_when_all_files_secure(self):
        check = SensitiveFilePermissionsCheck()

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100600, uid=0)),
        ):
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_files_missing(self):
        check = SensitiveFilePermissionsCheck()

        with patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=False):
            result = check.evaluate({})
        assert result.passed

    def test_fails_on_world_readable_shadow(self):
        check = SensitiveFilePermissionsCheck()

        mock_stat = MagicMock()
        mock_stat.side_effect = lambda *args: MockStatResult(mode=0o100644, uid=0)

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", mock_stat),
        ):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "shadow" in f.title or "shadow" in str(f.affected_component)
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_fails_on_wrong_owner(self):
        check = SensitiveFilePermissionsCheck()

        mock_stat = MagicMock()
        mock_stat.side_effect = lambda *args: MockStatResult(mode=0o100600, uid=1000)

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", mock_stat),
        ):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "uid 1000" in f.description or "1000" in f.detected_value

    def test_has_mitre_ids(self):
        check = SensitiveFilePermissionsCheck()

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100644, uid=0)),
        ):
            result = check.evaluate({})
        assert len(result.findings) > 0
        assert len(result.findings[0].mitre_attack_ids) > 0
        assert len(result.findings[0].cis_benchmarks) > 0


class TestHomeDirectoryPermissionsCheck:
    def test_passes_when_all_homes_secure(self):
        check = HomeDirectoryPermissionsCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "alice", "uid": 1001, "home": "/home/alice"},
                    {"username": "bob", "uid": 1002, "home": "/home/bob"},
                ],
            },
        }

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100750, uid=1001)),
        ):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_skips_system_users(self):
        check = HomeDirectoryPermissionsCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "root", "uid": 0, "home": "/root"},
                    {"username": "daemon", "uid": 1, "home": "/usr/sbin"},
                ],
            },
        }

        result = check.evaluate(collectors)
        assert result.passed

    def test_skips_nonexistent_home(self):
        check = HomeDirectoryPermissionsCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "nobody", "uid": 65534, "home": "/nonexistent"},
                ],
            },
        }

        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_on_world_writable_home(self):
        check = HomeDirectoryPermissionsCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "alice", "uid": 1001, "home": "/home/alice"},
                ],
            },
        }

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100777, uid=1001)),
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "world-writable" in f.description
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_fails_on_world_readable_home(self):
        check = HomeDirectoryPermissionsCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "alice", "uid": 1001, "home": "/home/alice"},
                ],
            },
        }

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100755, uid=1001)),
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "world-readable" in result.findings[0].description

    def test_handles_missing_users_data(self):
        check = HomeDirectoryPermissionsCheck()
        collectors = {"users": {}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = HomeDirectoryPermissionsCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "alice", "uid": 1001, "home": "/home/alice"},
                ],
            },
        }

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100777, uid=1001)),
        ):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestWorldWritableStickyBitCheck:
    def test_passes_with_sticky_bit(self):
        check = WorldWritableStickyBitCheck()

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o161777, uid=0)),
        ):
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_without_sticky_bit(self):
        check = WorldWritableStickyBitCheck()

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100777, uid=0)),
        ):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "sticky" in f.title.lower() or "Missing" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_handles_missing_dir(self):
        check = WorldWritableStickyBitCheck()

        with patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=False):
            result = check.evaluate({})
        assert result.passed

    def test_has_mitre_ids(self):
        check = WorldWritableStickyBitCheck()

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100777, uid=0)),
        ):
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestTempDirMountSecurityCheck:
    def test_passes_with_secure_mounts(self):
        check = TempDirMountSecurityCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/tmp", "fstype": "tmpfs", "options": "rw,noexec,nosuid,nodev,relatime", "device": "tmpfs"},
                    {"mount_point": "/var/tmp", "fstype": "ext4", "options": "rw,noexec,nosuid,nodev,relatime", "device": "/dev/sda1"},
                    {"mount_point": "/dev/shm", "fstype": "tmpfs", "options": "rw,noexec,nosuid,nodev,relatime", "device": "tmpfs"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_without_noexec(self):
        check = TempDirMountSecurityCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/tmp", "fstype": "ext4", "options": "rw,nosuid,nodev,relatime", "device": "/dev/sda1"},
                    {"mount_point": "/var/tmp", "fstype": "ext4", "options": "rw,noexec,nosuid,nodev,relatime", "device": "/dev/sda1"},
                    {"mount_point": "/dev/shm", "fstype": "tmpfs", "options": "rw,noexec,nosuid,nodev,relatime", "device": "tmpfs"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "Insecure" in f.title
        assert "/tmp" in f.title
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_fails_with_missing_all_options(self):
        check = TempDirMountSecurityCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/tmp", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        desc = result.findings[0].description
        assert "noexec" in desc and "nosuid" in desc and "nodev" in desc

    def test_skips_unmounted_tmp(self):
        check = TempDirMountSecurityCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_empty_data(self):
        check = TempDirMountSecurityCheck()
        collectors = {"mounts": {"mounts": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = TempDirMountSecurityCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/tmp", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestFilesystemSpaceCheck:
    def test_passes_with_low_usage(self):
        check = FilesystemSpaceCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
                ],
                "disk_usage": {"/": 1000000000000},
            },
        }

        class MockStatVFS:
            f_frsize = 4096
            f_blocks = 250000000
            f_bfree = 200000000

        with patch("os.statvfs", return_value=MockStatVFS()):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_high_usage(self):
        check = FilesystemSpaceCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
                ],
                "disk_usage": {"/": 1000000000000},
            },
        }

        class MockStatVFS:
            f_frsize = 4096
            f_blocks = 1000000
            f_bfree = 50000

        with patch("os.statvfs", return_value=MockStatVFS()):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "%" in f.detected_value
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM

    def test_skips_virtual_fstypes(self):
        check = FilesystemSpaceCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/proc", "fstype": "proc", "options": "rw,relatime", "device": "proc"},
                    {"mount_point": "/sys", "fstype": "sysfs", "options": "rw,relatime", "device": "sysfs"},
                ],
                "disk_usage": {"/proc": 1000000, "/sys": 1000000},
            },
        }

        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_empty_data(self):
        check = FilesystemSpaceCheck()
        collectors = {"mounts": {"mounts": [], "disk_usage": {}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_respects_max_findings(self):
        check = FilesystemSpaceCheck()

        class MockStatVFS:
            f_frsize = 4096
            f_blocks = 1000
            f_bfree = 50

        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/", "fstype": "ext4", "options": "", "device": "/dev/sda1"},
                    {"mount_point": "/var", "fstype": "ext4", "options": "", "device": "/dev/sda2"},
                ],
                "disk_usage": {"/": 1000000, "/var": 1000000},
            },
        }

        with patch("os.statvfs", return_value=MockStatVFS()):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) <= check.max_findings

    def test_has_mitre_ids(self):
        check = FilesystemSpaceCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
                ],
                "disk_usage": {"/": 1000000},
            },
        }

        class MockStatVFS:
            f_frsize = 4096
            f_blocks = 1000
            f_bfree = 50

        with patch("os.statvfs", return_value=MockStatVFS()):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestDotFilePermissionHijackingCheck:
    def test_passes_with_secure_dotfiles(self):
        check = DotFilePermissionHijackingCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "alice", "uid": 1001, "home": "/home/alice"},
                ],
            },
        }

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100644, uid=1001)),
        ):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_world_writable_dotfile(self):
        check = DotFilePermissionHijackingCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "alice", "uid": 1001, "home": "/home/alice"},
                ],
            },
        }

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100777, uid=1001)),
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "world-writable" in f.description
        assert ".bashrc" in str(f.affected_component) or ".bashrc" in f.title
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_skips_system_users(self):
        check = DotFilePermissionHijackingCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "root", "uid": 0, "home": "/root"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_finds_multiple_compromised_dotfiles(self):
        check = DotFilePermissionHijackingCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "alice", "uid": 1001, "home": "/home/alice"},
                ],
            },
        }

        mock_stat = MagicMock()
        mock_stat.side_effect = lambda *args: MockStatResult(mode=0o100777, uid=1001)

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", mock_stat),
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 2

    def test_skips_nonexistent_files(self):
        check = DotFilePermissionHijackingCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "alice", "uid": 1001, "home": "/home/alice"},
                ],
            },
        }

        with patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=False):
            result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = DotFilePermissionHijackingCheck()
        collectors = {
            "users": {
                "users": [
                    {"username": "alice", "uid": 1001, "home": "/home/alice"},
                ],
            },
        }

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100777, uid=1001)),
        ):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSystemBinaryOwnershipCheck:
    def test_passes_when_all_root_owned(self):
        check = SystemBinaryOwnershipCheck()

        mock_entry = MagicMock(spec=os.DirEntry)
        mock_entry.is_file.return_value = True
        mock_entry.is_symlink.return_value = False
        mock_entry.stat.return_value = MockStatResult(mode=0o100755, uid=0)
        type(mock_entry).path = PropertyMock(return_value="/bin/ls")

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.iterdir", return_value=[mock_entry]),
        ):
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_on_non_root_owned_binary(self):
        check = SystemBinaryOwnershipCheck()

        mock_entry = MagicMock(spec=os.DirEntry)
        mock_entry.is_file.return_value = True
        mock_entry.is_symlink.return_value = False
        mock_entry.stat.return_value = MockStatResult(mode=0o100755, uid=1001)
        type(mock_entry).path = PropertyMock(return_value="/usr/bin/evil")

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.iterdir", return_value=[mock_entry]),
        ):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "uid 1001" in f.description
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_skips_symlinks(self):
        check = SystemBinaryOwnershipCheck()

        mock_symlink = MagicMock(spec=os.DirEntry)
        mock_symlink.is_file.return_value = False
        mock_symlink.is_symlink.return_value = True
        mock_symlink.stat.return_value = MockStatResult(mode=0o100755, uid=0)
        type(mock_symlink).path = PropertyMock(return_value="/usr/bin/link")

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.iterdir", return_value=[mock_symlink]),
        ):
            result = check.evaluate({})
        assert result.passed

    def test_handles_missing_bin_dir(self):
        check = SystemBinaryOwnershipCheck()

        with patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=False):
            result = check.evaluate({})
        assert result.passed

    def test_deduplicates_paths(self):
        check = SystemBinaryOwnershipCheck()

        mock_entry = MagicMock(spec=os.DirEntry)
        mock_entry.is_file.return_value = True
        mock_entry.is_symlink.return_value = False
        mock_entry.stat.return_value = MockStatResult(mode=0o100755, uid=1001)
        type(mock_entry).path = PropertyMock(return_value="/bin/evil_sh")

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.iterdir", return_value=[mock_entry]),
        ):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_ids(self):
        check = SystemBinaryOwnershipCheck()

        mock_entry = MagicMock(spec=os.DirEntry)
        mock_entry.is_file.return_value = True
        mock_entry.is_symlink.return_value = False
        mock_entry.stat.return_value = MockStatResult(mode=0o100755, uid=1001)
        type(mock_entry).path = PropertyMock(return_value="/usr/bin/evil")

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.iterdir", return_value=[mock_entry]),
        ):
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestWorldWritableCronDirectoriesCheck:
    def test_passes_with_secure_cron_dirs(self):
        check = WorldWritableCronDirectoriesCheck()

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100755, uid=0)),
        ):
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_on_world_writable_cron_d(self):
        check = WorldWritableCronDirectoriesCheck()

        mock_stat = MagicMock()
        mock_stat.side_effect = lambda *args: MockStatResult(mode=0o100777, uid=0)

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", mock_stat),
        ):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "world-writable" in f.description
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_handles_missing_dirs(self):
        check = WorldWritableCronDirectoriesCheck()

        with patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=False):
            result = check.evaluate({})
        assert result.passed

    def test_passes_with_non_dir_paths(self):
        check = WorldWritableCronDirectoriesCheck()

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=False),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100755, uid=0)),
        ):
            result = check.evaluate({})
        assert result.passed

    def test_passes_with_secure_perms(self):
        check = WorldWritableCronDirectoriesCheck()

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=MockStatResult(mode=0o100755, uid=0)),
        ):
            result = check.evaluate({})
        assert result.passed

    def test_has_mitre_ids(self):
        check = WorldWritableCronDirectoriesCheck()

        mock_stat = MagicMock()
        mock_stat.side_effect = lambda *args: MockStatResult(mode=0o100777, uid=0)

        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", mock_stat),
        ):
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0
        assert len(result.findings[0].cis_benchmarks) > 0
