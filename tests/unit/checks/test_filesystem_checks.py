from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.filesystem.checks import (
    DeletedBinaryRunningCheck,
    HiddenFilesInWorldWritableCheck,
    ImmutableFileDriftCheck,
    MountOptionGapsCheck,
    OrphanedFilesCheck,
    UnexpectedFileCapabilitiesCheck,
    UnexpectedFilesInEtcCheck,
    UnexpectedPathExecutablesCheck,
    UnexpectedSymlinksInEtcCheck,
    WorldWritableDirectoriesCheck,
)
from usaf.models.severity import Confidence, Severity


class TestUnexpectedFilesInEtcCheck:
    def test_passes_with_known_etc_files(self):
        check = UnexpectedFilesInEtcCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"name": "passwd", "path": "/etc/passwd"},
                        {"name": "shadow", "path": "/etc/shadow"},
                        {"name": "ssh", "path": "/etc/ssh"},
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_package_owned_file(self):
        check = UnexpectedFilesInEtcCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"name": "custom_tool.conf", "path": "/etc/custom_tool.conf"},
                    ],
                },
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.get_package_for_file",
            return_value="custom-tool",
        ):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_unknown_unowned_file(self):
        check = UnexpectedFilesInEtcCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"name": "unknown.conf", "path": "/etc/unknown.conf", "mode": "0644", "uid": 0, "size": 100, "is_dir": False},
                    ],
                },
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.get_package_for_file",
            return_value=None,
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "unknown.conf" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM
        assert len(f.mitre_attack_ids) > 0

    def test_passes_with_empty_data(self):
        check = UnexpectedFilesInEtcCheck()
        collectors = {"filesystem": {"etc_snapshots": {"files": []}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_missing_etc_snapshots(self):
        check = UnexpectedFilesInEtcCheck()
        collectors = {"filesystem": {}}
        result = check.evaluate(collectors)
        assert result.passed


class TestUnexpectedPathExecutablesCheck:
    def test_passes_when_all_are_package_owned(self):
        check = UnexpectedPathExecutablesCheck()
        collectors = {
            "filesystem": {
                "path_executables": [
                    {"path": "/usr/bin/ls", "mode": "0755", "uid": 0, "size": 50000},
                    {"path": "/usr/bin/cat", "mode": "0755", "uid": 0, "size": 40000},
                ],
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.get_package_for_file",
            return_value="coreutils",
        ):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_unowned_executable(self):
        check = UnexpectedPathExecutablesCheck()
        collectors = {
            "filesystem": {
                "path_executables": [
                    {"path": "/usr/local/bin/suspicious", "mode": "0755", "uid": 1000, "size": 12345},
                ],
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.get_package_for_file",
            return_value=None,
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "suspicious" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH
        assert len(f.mitre_attack_ids) > 0

    def test_passes_with_empty_data(self):
        check = UnexpectedPathExecutablesCheck()
        collectors = {"filesystem": {"path_executables": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_missing_data(self):
        check = UnexpectedPathExecutablesCheck()
        collectors = {"filesystem": {}}
        result = check.evaluate(collectors)
        assert result.passed


class TestHiddenFilesInWorldWritableCheck:
    def test_passes_with_no_hidden_files(self):
        check = HiddenFilesInWorldWritableCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/tmp/visible.txt", "mode": "0777", "uid": 0, "size": 100},
                    {"path": "/var/tmp/data.bin", "mode": "0777", "uid": 0, "size": 200},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_hidden_file(self):
        check = HiddenFilesInWorldWritableCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/tmp/.hidden_script.sh", "mode": "0777", "uid": 1000, "size": 50},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert ".hidden_script.sh" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM
        assert len(f.mitre_attack_ids) > 0

    def test_passes_with_empty_data(self):
        check = HiddenFilesInWorldWritableCheck()
        collectors = {"filesystem": {"world_writable": []}}
        result = check.evaluate(collectors)
        assert result.passed


class TestDeletedBinaryRunningCheck:
    def test_passes_when_binary_exists(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        check = DeletedBinaryRunningCheck()
        collectors = {
            "processes": {
                "processes": [
                    {"pid": 1, "name": "systemd", "binary": "/usr/lib/systemd/systemd", "cmdline": "/sbin/init"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_deleted_binary(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = DeletedBinaryRunningCheck()
        collectors = {
            "processes": {
                "processes": [
                    {"pid": 9999, "name": "malicious", "binary": "/tmp/malware.bin", "cmdline": "/tmp/malware.bin"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "malicious" in f.title or "malware.bin" in f.title or "9999" in f.title
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert len(f.mitre_attack_ids) > 0

    def test_skips_process_without_binary(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = DeletedBinaryRunningCheck()
        collectors = {
            "processes": {
                "processes": [
                    {"pid": 2, "name": "kthreadd"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_empty_data(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        check = DeletedBinaryRunningCheck()
        collectors = {"processes": {"processes": []}}
        result = check.evaluate(collectors)
        assert result.passed


class TestUnexpectedSymlinksInEtcCheck:
    def test_passes_with_no_symlinks(self):
        check = UnexpectedSymlinksInEtcCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"name": "passwd", "path": "/etc/passwd", "is_symlink": False},
                        {"name": "hosts", "path": "/etc/hosts", "is_symlink": False},
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_symlink(self):
        check = UnexpectedSymlinksInEtcCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"name": "redirect", "path": "/etc/redirect", "is_symlink": True, "mode": "0777", "uid": 0, "size": 20},
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "redirect" in f.title
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW
        assert len(f.mitre_attack_ids) > 0

    def test_passes_with_empty_data(self):
        check = UnexpectedSymlinksInEtcCheck()
        collectors = {"filesystem": {"etc_snapshots": {"files": []}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_mixed_entries(self):
        check = UnexpectedSymlinksInEtcCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"name": "passwd", "path": "/etc/passwd", "is_symlink": False},
                        {"name": "malicious_link", "path": "/etc/malicious_link", "is_symlink": True, "mode": "0777", "uid": 0, "size": 10},
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "malicious_link" in result.findings[0].title


class TestImmutableFileDriftCheck:
    def test_passes_when_all_files_have_immutable(self):
        check = ImmutableFileDriftCheck()

        def mock_subprocess_run(cmd, **kwargs):
            return type("Result", (), {
                "returncode": 0,
                "stdout": f"----i------- {cmd[1]}",
                "stderr": "",
            })()

        with patch("subprocess.run", side_effect=mock_subprocess_run), \
             patch.object(Path, "exists", return_value=True):
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_missing_immutable(self):
        check = ImmutableFileDriftCheck()

        def mock_subprocess_run(cmd, **kwargs):
            return type("Result", (), {
                "returncode": 0,
                "stdout": f"------------- {cmd[1]}",
                "stderr": "",
            })()

        with patch("subprocess.run", side_effect=mock_subprocess_run), \
             patch.object(Path, "exists", return_value=True):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == len(check.CRITICAL_FILES)
        f = result.findings[0]
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH
        assert len(f.mitre_attack_ids) > 0

    def test_skips_nonexistent_files(self):
        check = ImmutableFileDriftCheck()

        exists_results = {path: False for path in check.CRITICAL_FILES}

        def mock_subprocess_run(cmd, **kwargs):
            return type("Result", (), {
                "returncode": 0,
                "stdout": f"------------- {cmd[1]}",
                "stderr": "",
            })()

        with patch("subprocess.run", side_effect=mock_subprocess_run), \
             patch.object(Path, "exists", lambda self: exists_results.get(str(self), True)):
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_file_with_lsattr_error(self):
        check = ImmutableFileDriftCheck()

        def mock_subprocess_run(cmd, **kwargs):
            return type("Result", (), {
                "returncode": 1,
                "stdout": "",
                "stderr": "error",
            })()

        with patch("subprocess.run", side_effect=mock_subprocess_run), \
             patch.object(Path, "exists", return_value=True):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == len(check.CRITICAL_FILES)

    def test_has_mitre_mapping(self):
        check = ImmutableFileDriftCheck()

        def mock_subprocess_run(cmd, **kwargs):
            return type("Result", (), {
                "returncode": 0,
                "stdout": f"------------- {cmd[1]}",
                "stderr": "",
            })()

        with patch("subprocess.run", side_effect=mock_subprocess_run), \
             patch.object(Path, "exists", return_value=True):
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0
        assert len(result.findings[0].cis_benchmarks) > 0


class TestUnexpectedFileCapabilitiesCheck:
    def test_passes_with_known_safe_package(self):
        check = UnexpectedFileCapabilitiesCheck()
        collectors = {
            "filesystem": {
                "capabilities": [
                    {"path": "/bin/ping", "capabilities": "cap_net_raw=ep"},
                ],
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.get_package_for_file",
            return_value="iputils-ping",
        ):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_unknown_package(self):
        check = UnexpectedFileCapabilitiesCheck()
        collectors = {
            "filesystem": {
                "capabilities": [
                    {"path": "/opt/custom/tool", "capabilities": "cap_dac_override=ep"},
                ],
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.get_package_for_file",
            return_value="custom-package",
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "cap_dac_override" in f.title or "capabilities" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM
        assert len(f.mitre_attack_ids) > 0

    def test_fails_with_no_package(self):
        check = UnexpectedFileCapabilitiesCheck()
        collectors = {
            "filesystem": {
                "capabilities": [
                    {"path": "/tmp/malicious", "capabilities": "cap_sys_admin=ep"},
                ],
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.get_package_for_file",
            return_value=None,
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.confidence == Confidence.HIGH
        assert f.false_positive_probability == 0.05

    def test_skips_entry_with_empty_capabilities(self):
        check = UnexpectedFileCapabilitiesCheck()
        collectors = {
            "filesystem": {
                "capabilities": [
                    {"path": "/bin/ls", "capabilities": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_empty_data(self):
        check = UnexpectedFileCapabilitiesCheck()
        collectors = {"filesystem": {"capabilities": []}}
        result = check.evaluate(collectors)
        assert result.passed


class TestWorldWritableDirectoriesCheck:
    def test_passes_with_known_exceptions(self):
        check = WorldWritableDirectoriesCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/tmp", "is_dir": True, "mode": "01777", "uid": 0},
                    {"path": "/var/tmp", "is_dir": True, "mode": "01777", "uid": 0},
                    {"path": "/dev/shm", "is_dir": True, "mode": "01777", "uid": 0},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_unexpected_world_writable_dir(self):
        check = WorldWritableDirectoriesCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/opt", "is_dir": True, "mode": "01777", "uid": 0},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "/opt" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM
        assert len(f.mitre_attack_ids) > 0

    def test_skips_regular_files(self):
        check = WorldWritableDirectoriesCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/tmp/some_file", "is_dir": False, "mode": "0777", "uid": 0},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_empty_data(self):
        check = WorldWritableDirectoriesCheck()
        collectors = {"filesystem": {"world_writable": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_mapping(self):
        check = WorldWritableDirectoriesCheck()
        collectors = {
            "filesystem": {
                "world_writable": [
                    {"path": "/var/log", "is_dir": True, "mode": "01777", "uid": 0},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0
        assert len(result.findings[0].cis_benchmarks) > 0


class TestOrphanedFilesCheck:
    def test_passes_when_all_files_are_owned(self):
        check = OrphanedFilesCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"path": "/etc/passwd", "name": "passwd", "mode": "0644", "uid": 0, "size": 1000},
                    ],
                },
                "path_executables": [],
                "world_writable": [],
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.resolve_package",
            return_value="base-files",
        ):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_orphaned_file(self):
        check = OrphanedFilesCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"path": "/etc/unknown.conf", "name": "unknown.conf", "mode": "0644", "uid": 1000, "size": 50},
                    ],
                },
                "path_executables": [],
                "world_writable": [],
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.resolve_package",
            return_value=None,
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "unknown.conf" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM
        assert len(f.mitre_attack_ids) > 0

    def test_deduplicates_paths(self):
        check = OrphanedFilesCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"path": "/etc/duplicate", "name": "duplicate", "mode": "0644", "uid": 1000, "size": 50},
                    ],
                },
                "path_executables": [
                    {"path": "/etc/duplicate", "mode": "0755", "uid": 1000, "size": 50},
                ],
                "world_writable": [
                    {"path": "/etc/duplicate", "is_dir": False, "mode": "0777", "uid": 1000, "size": 50},
                ],
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.resolve_package",
            return_value=None,
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_checks_all_sources(self):
        check = OrphanedFilesCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {
                    "files": [
                        {"path": "/etc/unknown.conf", "name": "unknown.conf", "mode": "0644", "uid": 1000, "size": 50},
                    ],
                },
                "path_executables": [
                    {"path": "/usr/local/bin/strange", "mode": "0755", "uid": 1001, "size": 200},
                ],
                "world_writable": [
                    {"path": "/tmp/.evil", "is_dir": False, "mode": "0777", "uid": 1002, "size": 300},
                ],
            },
        }
        with patch(
            "usaf.checks.filesystem.checks.resolve_package",
            return_value=None,
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        # world_writable no longer checked by FS-403 (too noisy)
        assert len(result.findings) == 2

    def test_passes_with_empty_data(self):
        check = OrphanedFilesCheck()
        collectors = {
            "filesystem": {
                "etc_snapshots": {"files": []},
                "path_executables": [],
                "world_writable": [],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed


class TestMountOptionGapsCheck:
    def test_passes_with_secure_tmp(self):
        check = MountOptionGapsCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {
                        "mount_point": "/tmp",
                        "fstype": "ext4",
                        "options": "rw,noexec,nosuid,nodev,relatime",
                        "device": "/dev/sda1",
                    },
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_tmp_missing_noexec(self):
        check = MountOptionGapsCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {
                        "mount_point": "/tmp",
                        "fstype": "ext4",
                        "options": "rw,nosuid,nodev,relatime",
                        "device": "/dev/sda1",
                    },
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "noexec" in f.title
        assert "/tmp" in f.title
        assert f.severity == Severity.MEDIUM
        assert len(f.mitre_attack_ids) > 0

    def test_fails_when_tmp_missing_all_options(self):
        check = MountOptionGapsCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {
                        "mount_point": "/tmp",
                        "fstype": "ext4",
                        "options": "rw,relatime",
                        "device": "/dev/sda1",
                    },
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 3

    def test_fails_when_home_missing_nosuid(self):
        check = MountOptionGapsCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {
                        "mount_point": "/home",
                        "fstype": "ext4",
                        "options": "rw,relatime",
                        "device": "/dev/sda2",
                    },
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 2  # nosuid and nodev
        assert any("nosuid" in f.title for f in result.findings)
        assert any("nodev" in f.title for f in result.findings)

    def test_skips_known_safe_fstypes(self):
        check = MountOptionGapsCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {
                        "mount_point": "/proc",
                        "fstype": "proc",
                        "options": "rw,relatime",
                        "device": "proc",
                    },
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_writable_fs_missing_options(self):
        check = MountOptionGapsCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {
                        "mount_point": "/mnt/data",
                        "fstype": "ext4",
                        "options": "rw,relatime",
                        "device": "/dev/sdb1",
                    },
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1  # combined finding for all missing options
        f = result.findings[0]
        assert "Missing mount hardening options" in f.title

    def test_skips_snap_mounts(self):
        check = MountOptionGapsCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {
                        "mount_point": "/snap/core/12345",
                        "fstype": "squashfs",
                        "options": "ro,relatime",
                        "device": "/dev/loop0",
                    },
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_empty_data(self):
        check = MountOptionGapsCheck()
        collectors = {"mounts": {"mounts": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_mapping(self):
        check = MountOptionGapsCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {
                        "mount_point": "/tmp",
                        "fstype": "ext4",
                        "options": "rw,relatime",
                        "device": "/dev/sda1",
                    },
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0
        assert len(result.findings[0].cis_benchmarks) > 0
