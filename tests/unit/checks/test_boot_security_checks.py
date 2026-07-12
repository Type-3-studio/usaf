from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.boot.boot_security_checks import (
    BootPartitionMountCheck,
    EfiBootEntryCheck,
    GrubConfigPermissionsCheck,
    InitramfsPresentCheck,
    KernelImageCountCheck,
    KernelLockdownConfidentialityCheck,
    LatestKernelRunningCheck,
    SbatStatusCheck,
)
from usaf.models.severity import Confidence, Severity


class MockStatResult:
    def __init__(self, mode=0o100644, uid=0, gid=0, size=1024):
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_size = size
        self.st_mtime = 1000000.0
        self.st_atime = 1000000.0
        self.st_ctime = 1000000.0
        self.st_nlink = 1


class TestSbatStatusCheck:
    def test_passes_when_sbat_present(self):
        check = SbatStatusCheck()

        with (
            patch("usaf.checks.boot.boot_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.boot.boot_security_checks.Path.exists", return_value=True),
            patch.object(Path, "iterdir", return_value=[Path("SbatLevel")]),
        ):
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_warns_when_sbat_missing(self):
        check = SbatStatusCheck()

        with (
            patch("usaf.checks.boot.boot_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.boot.boot_security_checks.Path.exists", return_value=True),
            patch.object(Path, "iterdir", return_value=[]),
        ):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "SBAT" in f.title
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.MEDIUM

    def test_skips_when_not_uefi(self):
        check = SbatStatusCheck()

        with (
            patch("usaf.checks.boot.boot_security_checks.Path.is_dir", return_value=False),
            patch("usaf.checks.boot.boot_security_checks.Path.exists", return_value=False),
        ):
            result = check.evaluate({})
        assert result.passed

    def test_has_mitre_ids(self):
        check = SbatStatusCheck()

        with (
            patch("usaf.checks.boot.boot_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.boot.boot_security_checks.Path.exists", return_value=True),
            patch.object(Path, "iterdir", return_value=[]),
        ):
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestKernelImageCountCheck:
    def test_passes_with_few_kernels(self):
        check = KernelImageCountCheck()
        collectors = {
            "boot": {
                "kernel_images": {
                    "images": [
                        {"name": "vmlinuz-6.8.0-35-generic", "path": "/boot/vmlinuz-6.8.0-35-generic", "modified": 1000.0},
                        {"name": "vmlinuz-6.8.0-34-generic", "path": "/boot/vmlinuz-6.8.0-34-generic", "modified": 2000.0},
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_too_many_kernels(self):
        check = KernelImageCountCheck()
        images = [
            {"name": f"vmlinuz-6.8.0-{i}-generic", "path": f"/boot/vmlinuz-6.8.0-{i}-generic", "modified": float(i)}
            for i in range(10)
        ]
        collectors = {"boot": {"kernel_images": {"images": images}}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "kernel" in f.title.lower() or "10" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_handles_empty_data(self):
        check = KernelImageCountCheck()
        collectors = {"boot": {"kernel_images": {"images": []}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = KernelImageCountCheck()
        images = [{"name": f"vmlinuz-{i}", "path": f"/boot/vmlinuz-{i}", "modified": float(i)} for i in range(10)]
        collectors = {"boot": {"kernel_images": {"images": images}}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestLatestKernelRunningCheck:
    def test_passes_on_latest_kernel(self):
        check = LatestKernelRunningCheck()
        collectors = {
            "kernel": {"kernel": {"release": "6.8.0-35-generic"}},
            "boot": {
                "kernel_images": {
                    "images": [
                        {"name": "vmlinuz-6.8.0-34-generic", "path": "/boot/...", "modified": 1000.0},
                        {"name": "vmlinuz-6.8.0-35-generic", "path": "/boot/...", "modified": 2000.0},
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_on_old_kernel(self):
        check = LatestKernelRunningCheck()
        collectors = {
            "kernel": {"kernel": {"release": "6.8.0-33-generic"}},
            "boot": {
                "kernel_images": {
                    "images": [
                        {"name": "vmlinuz-6.8.0-35-generic", "path": "/boot/...", "modified": 2000.0},
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "6.8.0-33" in f.description and "6.8.0-35" in f.description
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_handles_empty_data(self):
        check = LatestKernelRunningCheck()
        collectors = {"kernel": {}, "boot": {"kernel_images": {"images": []}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = LatestKernelRunningCheck()
        collectors = {
            "kernel": {"kernel": {"release": "6.8.0-33-generic"}},
            "boot": {
                "kernel_images": {
                    "images": [
                        {"name": "vmlinuz-6.8.0-35-generic", "path": "/boot/...", "modified": 2000.0},
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestEfiBootEntryCheck:
    def test_passes_with_standard_entries(self):
        check = EfiBootEntryCheck()
        collectors = {
            "boot": {
                "efi": {
                    "boot_entries": [
                        "ubuntu/grubx64.efi",
                        "ubuntu/shimx64.efi",
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_suspicious_entry(self):
        check = EfiBootEntryCheck()
        collectors = {
            "boot": {
                "efi": {
                    "boot_entries": [
                        "ubuntu/grubx64.efi",
                        "unknown/malicious.efi",
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "malicious" in f.title or "unexpected" in f.title.lower()
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.MEDIUM

    def test_handles_empty_entries(self):
        check = EfiBootEntryCheck()
        collectors = {"boot": {"efi": {"boot_entries": []}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = EfiBootEntryCheck()
        collectors = {
            "boot": {
                "efi": {
                    "boot_entries": [
                        "ubuntu/grubx64.efi",
                        "unknown/bad.efi",
                    ],
                },
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestKernelLockdownConfidentialityCheck:
    def test_passes_with_confidentiality(self):
        check = KernelLockdownConfidentialityCheck()
        collectors = {"boot": {"kernel_lockdown": {"mode": "confidentiality"}}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_warns_with_integrity_mode(self):
        check = KernelLockdownConfidentialityCheck()
        collectors = {"boot": {"kernel_lockdown": {"mode": "integrity"}}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "confidentiality" in f.title or "confidentiality" in f.description
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM

    def test_skips_when_lockdown_disabled(self):
        check = KernelLockdownConfidentialityCheck()
        collectors = {"boot": {"kernel_lockdown": {"mode": "none"}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_skips_when_not_available(self):
        check = KernelLockdownConfidentialityCheck()
        collectors = {"boot": {"kernel_lockdown": {"mode": ""}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = KernelLockdownConfidentialityCheck()
        collectors = {"boot": {"kernel_lockdown": {"mode": "integrity"}}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestGrubConfigPermissionsCheck:
    def test_passes_with_restricted_perms(self):
        check = GrubConfigPermissionsCheck()
        collectors = {"boot": {"grub": {"cfg_path": "/boot/grub/grub.cfg"}}}

        with patch("usaf.checks.boot.boot_security_checks.Path.stat", return_value=MockStatResult(mode=0o100640, uid=0)):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_world_readable(self):
        check = GrubConfigPermissionsCheck()
        collectors = {"boot": {"grub": {"cfg_path": "/boot/grub/grub.cfg"}}}

        with patch("usaf.checks.boot.boot_security_checks.Path.stat", return_value=MockStatResult(mode=0o100644, uid=0)):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "world-readable" in f.title.lower() or "GRUB" in f.title
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_skips_when_no_grub(self):
        check = GrubConfigPermissionsCheck()
        collectors = {"boot": {"grub": {"cfg_path": None}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = GrubConfigPermissionsCheck()
        collectors = {"boot": {"grub": {"cfg_path": "/boot/grub/grub.cfg"}}}

        with patch("usaf.checks.boot.boot_security_checks.Path.stat", return_value=MockStatResult(mode=0o100644, uid=0)):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestBootPartitionMountCheck:
    def test_passes_with_secure_boot_mount(self):
        check = BootPartitionMountCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/boot", "fstype": "ext4", "options": "rw,nosuid,nodev,relatime", "device": "/dev/sda1"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_without_nosuid(self):
        check = BootPartitionMountCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/boot", "fstype": "ext4", "options": "rw,nodev,relatime", "device": "/dev/sda1"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "nosuid" in f.title or "Missing" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM

    def test_skips_when_no_boot_mount(self):
        check = BootPartitionMountCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = BootPartitionMountCheck()
        collectors = {
            "mounts": {
                "mounts": [
                    {"mount_point": "/boot", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestInitramfsPresentCheck:
    def test_passes_with_all_initrds(self):
        check = InitramfsPresentCheck()
        collectors = {
            "boot": {
                "kernel_images": {
                    "images": [
                        {"name": "vmlinuz-6.8.0-35-generic", "path": "/boot/vmlinuz-6.8.0-35-generic", "modified": 1000.0},
                    ],
                },
            },
        }

        with patch("usaf.checks.boot.boot_security_checks.Path.exists", return_value=True):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_missing_initrd(self):
        check = InitramfsPresentCheck()
        collectors = {
            "boot": {
                "kernel_images": {
                    "images": [
                        {"name": "vmlinuz-6.8.0-35-generic", "path": "/boot/vmlinuz-6.8.0-35-generic", "modified": 1000.0},
                    ],
                },
            },
        }

        with patch("usaf.checks.boot.boot_security_checks.Path.exists", return_value=False):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "initramfs" in f.title.lower() or "Missing" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_handles_empty_data(self):
        check = InitramfsPresentCheck()
        collectors = {"boot": {"kernel_images": {"images": []}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = InitramfsPresentCheck()
        collectors = {
            "boot": {
                "kernel_images": {
                    "images": [
                        {"name": "vmlinuz-6.8.0-35-generic", "path": "/boot/vmlinuz-6.8.0-35-generic", "modified": 1000.0},
                    ],
                },
            },
        }

        with patch("usaf.checks.boot.boot_security_checks.Path.exists", return_value=False):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0
