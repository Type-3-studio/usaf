from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.permissions.suid_checks import UnexpectedSUIDCheck, WorldWritableFilesCheck
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
        collectors = {
            "_usaf_config": {
                "suid_allowlist": ["/opt/custom/suid-tool"],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_config_allowlist_only_affects_listed(self, monkeypatch):
        self._make_mock_fs(monkeypatch, ["/opt/custom/other-tool"])
        check = UnexpectedSUIDCheck()
        collectors = {
            "_usaf_config": {
                "suid_allowlist": ["/opt/custom/suid-tool"],
            },
        }
        result = check.evaluate(collectors)
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
