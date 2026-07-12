from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.permissions.suid_checks import UnexpectedSUIDCheck, WorldWritableFilesCheck
from usaf.config.model import USAFConfig
from usaf.models.severity import Confidence, Severity


class FakeNoWriteStat:
    """st_mode without world-writable bit."""
    st_mode = 0o100644
    st_uid = 0
    st_size = 1024


class FakeWriteStat:
    """st_mode with world-writable bit."""
    st_mode = 0o100777
    st_uid = 0
    st_size = 1024


class TestWorldWritableFilesCheck:
    def test_passes_when_not_world_writable(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "stat", lambda _: FakeNoWriteStat())
        check = WorldWritableFilesCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_world_writable(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "stat", lambda _: FakeWriteStat())
        check = WorldWritableFilesCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == len(check.CRITICAL_PATHS)

    def test_skips_nonexistent_paths(self, monkeypatch):
        exists_results = iter([False] + [True] * 20)
        monkeypatch.setattr(Path, "exists", lambda _: next(exists_results))
        monkeypatch.setattr(Path, "stat", lambda _: FakeWriteStat())
        check = WorldWritableFilesCheck()
        result = check.evaluate({})
        assert len(result.findings) == len(check.CRITICAL_PATHS) - 1

    def test_has_mitre_mapping(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "stat", lambda _: FakeWriteStat())
        check = WorldWritableFilesCheck()
        result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class FakeStat:
    """Shared fake stat result for SUID tests."""
    st_mode = 0o104555
    st_uid = 0
    st_size = 50000


class TestUnexpectedSUIDCheck:
    def _make_mock_fs(self, monkeypatch, entries: list[str]) -> None:
        class FakeEntry:
            def __init__(self, path_str: str) -> None:
                self._path = path_str
            def is_file(self) -> bool:
                return True
            def is_symlink(self) -> bool:
                return False
            def stat(self):
                return FakeStat()
            def __str__(self) -> str:
                return self._path

        def mock_iterdir(_):
            return [FakeEntry(p) for p in entries]

        monkeypatch.setattr(Path, "is_dir", lambda _: True)
        monkeypatch.setattr(Path, "iterdir", mock_iterdir)
        monkeypatch.setattr(Path, "stat", lambda _: FakeStat())

    def test_passes_when_no_suid_binaries(self, monkeypatch):
        self._make_mock_fs(monkeypatch, [])
        check = UnexpectedSUIDCheck()
        result = check.evaluate({})
        assert result.passed

    def test_detects_suid_binary_not_in_expected(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/custom_suid_tool"])
        check = UnexpectedSUIDCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "custom_suid_tool" in f.title
        assert f.severity == Severity.HIGH

    def test_skips_expected_suid_binary(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/sudo", "/usr/bin/passwd"])
        check = UnexpectedSUIDCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_has_mitre_mapping(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/suspicious_binary"])
        check = UnexpectedSUIDCheck()
        result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0

    def test_config_allowlist_suppresses_finding(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/opt/custom/suid-tool"])
        check = UnexpectedSUIDCheck()
        config = USAFConfig(suid_allowlist=["/opt/custom/suid-tool"])
        result = check.evaluate({}, config)
        assert result.passed
        assert len(result.findings) == 0

    def test_config_allowlist_only_affects_listed(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/opt/custom/other-tool"])
        check = UnexpectedSUIDCheck()
        config = USAFConfig(suid_allowlist=["/opt/custom/suid-tool"])
        result = check.evaluate({}, config)
        assert not result.passed
        assert len(result.findings) == 1

    def test_non_package_binary_gets_high_confidence(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/unknown_suid"])
        check = UnexpectedSUIDCheck()
        with patch(
            "usaf.checks.permissions.suid_checks.get_package_for_file",
            return_value=None,
        ):
            result = check.evaluate({})
        assert not result.passed
        f = result.findings[0]
        assert f.confidence == Confidence.HIGH
        assert f.false_positive_probability == 0.05

    def test_package_owned_binary_gets_medium_confidence(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/package_suid"])
        check = UnexpectedSUIDCheck()
        with patch(
            "usaf.checks.permissions.suid_checks.get_package_for_file",
            return_value="some-package",
        ):
            result = check.evaluate({})
        assert not result.passed
        f = result.findings[0]
        assert f.confidence == Confidence.MEDIUM
        assert f.false_positive_probability == 0.3

    def test_known_safe_package_gets_low_confidence(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/from_coreutils"])
        check = UnexpectedSUIDCheck()
        with patch(
            "usaf.checks.permissions.suid_checks.get_package_for_file",
            return_value="coreutils",
        ):
            result = check.evaluate({})
        assert not result.passed
        f = result.findings[0]
        assert f.confidence == Confidence.LOW
        assert f.false_positive_probability == 0.8

    def test_known_safe_package_description_mentions_known_safe(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/from_coreutils"])
        check = UnexpectedSUIDCheck()
        with patch(
            "usaf.checks.permissions.suid_checks.get_package_for_file",
            return_value="coreutils",
        ):
            result = check.evaluate({})
        assert not result.passed
        f = result.findings[0]
        assert "known-safe" in f.description

    def test_known_safe_package_remediation_mentions_known_safe(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/from_coreutils"])
        check = UnexpectedSUIDCheck()
        with patch(
            "usaf.checks.permissions.suid_checks.get_package_for_file",
            return_value="coreutils",
        ):
            result = check.evaluate({})
        assert not result.passed
        f = result.findings[0]
        assert "known-safe" in f.remediation

    def test_path_allowlist_overrides_known_package(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/from_coreutils"])
        check = UnexpectedSUIDCheck()
        config = USAFConfig(suid_allowlist=["/usr/bin/from_coreutils"])
        with patch(
            "usaf.checks.permissions.suid_checks.get_package_for_file",
            return_value="coreutils",
        ):
            result = check.evaluate({}, config)
        assert result.passed  # Path allowlist overrides everything

    def test_non_package_binary_description_indicates_suspicious(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/usr/bin/unknown"])
        check = UnexpectedSUIDCheck()
        with patch(
            "usaf.checks.permissions.suid_checks.get_package_for_file",
            return_value=None,
        ):
            result = check.evaluate({})
        assert not result.passed
        f = result.findings[0]
        assert "highly suspicious" in f.description


from usaf.checks.permissions.permission_checks import (
    DangerousCapabilitiesCheck,
    MissingStickyBitCheck,
    NonRootSetuidOwnershipCheck,
    SetuidShellScriptsCheck,
    SGIDBinariesCheck,
    UnexpectedCapabilitiesCheck,
    WorldWritablePathExecutablesCheck,
    WorldWritableSetuidFilesCheck,
)


def _fs_data(suid=None, ww=None, caps=None, execs=None):
    return {
        "filesystem": {
            "suid_files": suid or [],
            "world_writable": ww or [],
            "capabilities": caps or [],
            "path_executables": execs or [],
        }
    }


class TestSGIDBinariesCheck:
    def test_passes_when_no_suid_files(self):
        check = SGIDBinariesCheck()
        result = check.evaluate(_fs_data(suid=[]))
        assert result.passed

    def test_passes_when_no_sgid_binaries(self):
        check = SGIDBinariesCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/su", "mode": "0o4755", "uid": 0}]))
        assert result.passed

    def test_finds_sgid_binary(self):
        check = SGIDBinariesCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/custom_sgid", "mode": "0o2755", "uid": 0}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_allowlisted_path_skipped(self):
        check = SGIDBinariesCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/screen", "mode": "0o2755", "uid": 0}]))
        assert result.passed

    def test_severity_medium(self):
        check = SGIDBinariesCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/custom", "mode": "0o2755", "uid": 0}]))
        assert result.findings[0].severity == Severity.MEDIUM


class TestDangerousCapabilitiesCheck:
    def test_passes_when_no_capabilities(self):
        check = DangerousCapabilitiesCheck()
        result = check.evaluate(_fs_data(caps=[]))
        assert result.passed

    def test_passes_with_safe_capabilities(self):
        check = DangerousCapabilitiesCheck()
        result = check.evaluate(_fs_data(caps=[{"path": "/usr/bin/ping", "capabilities": "cap_net_raw=ep"}]))
        assert result.passed

    def test_finds_dangerous_capability(self):
        check = DangerousCapabilitiesCheck()
        result = check.evaluate(_fs_data(caps=[{"path": "/usr/bin/custom", "capabilities": "cap_sys_admin=ep"}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_finds_cap_dac_override(self):
        check = DangerousCapabilitiesCheck()
        result = check.evaluate(_fs_data(caps=[{"path": "/usr/bin/myapp", "capabilities": "cap_dac_override=ep"}]))
        assert not result.passed

    def test_severity_high(self):
        check = DangerousCapabilitiesCheck()
        result = check.evaluate(_fs_data(caps=[{"path": "/usr/bin/bad", "capabilities": "cap_setuid=ep"}]))
        assert result.findings[0].severity == Severity.HIGH


class TestMissingStickyBitCheck:
    def test_passes_when_no_ww_dirs(self):
        check = MissingStickyBitCheck()
        result = check.evaluate(_fs_data(ww=[]))
        assert result.passed

    def test_passes_when_sticky_bit_set(self):
        check = MissingStickyBitCheck()
        result = check.evaluate(_fs_data(ww=[{"path": "/tmp", "mode": "0o1777", "is_dir": True}]))
        assert result.passed

    def test_fails_when_ww_dir_no_sticky(self):
        check = MissingStickyBitCheck()
        result = check.evaluate(_fs_data(ww=[{"path": "/opt/shared", "mode": "0o0777", "is_dir": True}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_skips_files(self):
        check = MissingStickyBitCheck()
        result = check.evaluate(_fs_data(ww=[{"path": "/etc/hosts", "mode": "0o0777", "is_dir": False}]))
        assert result.passed

    def test_expected_dirs_skipped(self):
        check = MissingStickyBitCheck()
        result = check.evaluate(_fs_data(ww=[{"path": "/tmp", "mode": "0o0777", "is_dir": True}]))
        assert result.passed


class TestWorldWritablePathExecutablesCheck:
    def test_passes_when_no_executables(self):
        check = WorldWritablePathExecutablesCheck()
        result = check.evaluate(_fs_data(execs=[]))
        assert result.passed

    def test_passes_when_not_ww(self):
        check = WorldWritablePathExecutablesCheck()
        result = check.evaluate(_fs_data(execs=[{"path": "/usr/bin/ls", "mode": "0o0755", "uid": 0}]))
        assert result.passed

    def test_fails_when_ww_exec(self):
        check = WorldWritablePathExecutablesCheck()
        result = check.evaluate(_fs_data(execs=[{"path": "/usr/bin/custom", "mode": "0o0777", "uid": 0}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_severity_critical(self):
        check = WorldWritablePathExecutablesCheck()
        result = check.evaluate(_fs_data(execs=[{"path": "/usr/bin/hacked", "mode": "0o0777", "uid": 0}]))
        assert result.findings[0].severity == Severity.CRITICAL


class TestSetuidShellScriptsCheck:
    def test_passes_when_no_suid(self):
        check = SetuidShellScriptsCheck()
        result = check.evaluate(_fs_data(suid=[]))
        assert result.passed

    def test_passes_for_binary_suid(self, monkeypatch):
        monkeypatch.setattr(Path, "open", lambda _: (_ for _ in ()).throw(OSError))
        check = SetuidShellScriptsCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/su", "mode": "0o4755", "uid": 0}]))
        assert result.passed

    def test_passes_when_no_suid_no_sgid(self):
        check = SetuidShellScriptsCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/ls", "mode": "0o0755", "uid": 0}]))
        assert result.passed


class TestNonRootSetuidOwnershipCheck:
    def test_passes_when_root_owned(self):
        check = NonRootSetuidOwnershipCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/su", "mode": "0o4755", "uid": 0}]))
        assert result.passed

    def test_passes_without_suid_bit(self):
        check = NonRootSetuidOwnershipCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/ls", "mode": "0o0755", "uid": 1000}]))
        assert result.passed

    def test_fails_when_non_root_owner(self):
        check = NonRootSetuidOwnershipCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/custom", "mode": "0o4755", "uid": 1001}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_finds_sgid_non_root(self):
        check = NonRootSetuidOwnershipCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/grp_bin", "mode": "0o2755", "uid": 1002}]))
        assert not result.passed


class TestUnexpectedCapabilitiesCheck:
    def test_passes_when_no_caps(self):
        check = UnexpectedCapabilitiesCheck()
        result = check.evaluate(_fs_data(caps=[]))
        assert result.passed

    def test_passes_when_allowlisted(self):
        check = UnexpectedCapabilitiesCheck()
        result = check.evaluate(_fs_data(caps=[{"path": "/usr/bin/ping", "capabilities": "cap_net_raw=ep"}]))
        assert result.passed

    def test_fails_when_no_package_owner(self):
        check = UnexpectedCapabilitiesCheck()
        result = check.evaluate(_fs_data(caps=[{"path": "/opt/custom_bin", "capabilities": "cap_net_raw=ep"}]))
        assert not result.passed
        assert len(result.findings) == 1


class TestWorldWritableSetuidFilesCheck:
    def test_passes_when_no_suid(self):
        check = WorldWritableSetuidFilesCheck()
        result = check.evaluate(_fs_data(suid=[]))
        assert result.passed

    def test_passes_when_not_ww(self):
        check = WorldWritableSetuidFilesCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/su", "mode": "0o4755", "uid": 0}]))
        assert result.passed

    def test_fails_when_ww_and_suid(self):
        check = WorldWritableSetuidFilesCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/bad", "mode": "0o4777", "uid": 0}]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_ww_and_sgid(self):
        check = WorldWritableSetuidFilesCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/grp_bad", "mode": "0o2777", "uid": 0}]))
        assert not result.passed

    def test_severity_critical(self):
        check = WorldWritableSetuidFilesCheck()
        result = check.evaluate(_fs_data(suid=[{"path": "/usr/bin/evil", "mode": "0o4777", "uid": 0}]))
        assert result.findings[0].severity == Severity.CRITICAL
