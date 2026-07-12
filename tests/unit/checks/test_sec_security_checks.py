from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.security.sec_security_checks import (
    AppArmorCacheStatusCheck,
    AppArmorComplainModeCheck,
    AppArmorExtraProfilesCheck,
    AppArmorProfileIntegrityCheck,
    LsmStackingCheck,
    ModuleLoadingRestrictionsCheck,
    SeccompStatusCheck,
    UnconfinedRootProcessesCheck,
)
from usaf.models.severity import Confidence, Severity


class TestAppArmorComplainModeCheck:
    def test_passes_with_enforce_mode(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="Y"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "4 profiles are in enforce mode.\n3 processes are in enforce mode.\n"
            check = AppArmorComplainModeCheck()
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_complain_profiles(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="Y"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "2 profiles are in complain mode.\n   profile_name\n2 processes are in complain mode.\n"
            check = AppArmorComplainModeCheck()
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "complain" in f.title.lower()
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_skips_when_apparmor_disabled(self):
        with patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=False):
            check = AppArmorComplainModeCheck()
            result = check.evaluate({})
        assert result.passed

    def test_has_mitre_ids(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="Y"),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "1 profiles are in complain mode.\n  test_profile\n"
            check = AppArmorComplainModeCheck()
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestAppArmorProfileIntegrityCheck:
    def test_skips_when_no_profile_dir(self):
        with patch("os.path.isdir", return_value=False):
            check = AppArmorProfileIntegrityCheck()
            result = check.evaluate({})
        assert result.passed

    def test_fails_with_no_loaded_profiles(self):
        with (
            patch("pathlib.Path.is_dir", return_value=True),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "No profiles loaded.\n"
            mock_run.return_value.stderr = ""
            check = AppArmorProfileIntegrityCheck()
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1

    def test_has_mitre_ids(self):
        with (
            patch("pathlib.Path.is_dir", return_value=True),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = "No profiles loaded.\n"
            mock_run.return_value.stderr = ""
            check = AppArmorProfileIntegrityCheck()
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestAppArmorExtraProfilesCheck:
    def test_passes_with_packages_installed(self):
        check = AppArmorExtraProfilesCheck()
        collectors = {
            "apt": {
                "packages": [
                    {"name": "apparmor-profiles"},
                    {"name": "apparmor-profiles-extra"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_missing_packages(self):
        check = AppArmorExtraProfilesCheck()
        collectors = {"apt": {"packages": [{"name": "coreutils"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "AppArmor" in f.title or "profiles" in f.title.lower()
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW

    def test_has_mitre_ids(self):
        check = AppArmorExtraProfilesCheck()
        collectors = {"apt": {"packages": []}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSeccompStatusCheck:
    def test_passes_with_seccomp_full(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="2"),
        ):
            check = SeccompStatusCheck()
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_without_seccomp(self):
        with patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=False):
            check = SeccompStatusCheck()
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        assert "not available" in result.findings[0].title.lower() or "not available" in result.findings[0].description.lower()

    def test_has_mitre_ids(self):
        with patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=False):
            check = SeccompStatusCheck()
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestLsmStackingCheck:
    def test_passes_with_apparmor_in_stack(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="lockdown,apparmor,yama"),
        ):
            check = LsmStackingCheck()
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_without_apparmor(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="lockdown,yama"),
        ):
            check = LsmStackingCheck()
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "AppArmor" in f.title or "apparmor" in f.description
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.HIGH

    def test_skips_when_not_available(self):
        with patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=False):
            check = LsmStackingCheck()
            result = check.evaluate({})
        assert result.passed

    def test_has_mitre_ids(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="lockdown,yama"),
        ):
            check = LsmStackingCheck()
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestAppArmorCacheStatusCheck:
    def test_passes_with_cache(self):
        with patch("usaf.checks.security.sec_security_checks.Path.is_dir", return_value=True):
            check = AppArmorCacheStatusCheck()
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_without_cache(self):
        with patch("usaf.checks.security.sec_security_checks.Path.is_dir", return_value=False):
            check = AppArmorCacheStatusCheck()
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        assert "cache" in result.findings[0].title.lower()

    def test_has_mitre_ids(self):
        with patch("usaf.checks.security.sec_security_checks.Path.is_dir", return_value=False):
            check = AppArmorCacheStatusCheck()
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestModuleLoadingRestrictionsCheck:
    def test_passes_with_modules_disabled(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="1"),
        ):
            check = ModuleLoadingRestrictionsCheck()
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_modules_enabled(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists") as mock_exists,
            patch.object(Path, "read_text", return_value="0"),
        ):
            mock_exists.return_value = True
            check = ModuleLoadingRestrictionsCheck()
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1
        titles = [f.title for f in result.findings]
        assert any("not disabled" in t.lower() or "enabled" in t.lower() for t in titles)

    def test_has_mitre_ids(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists") as mock_exists,
            patch.object(Path, "read_text", return_value="0"),
        ):
            mock_exists.return_value = True
            check = ModuleLoadingRestrictionsCheck()
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestUnconfinedRootProcessesCheck:
    def test_passes_with_confined_root(self):
        check = UnconfinedRootProcessesCheck()
        collectors = {
            "processes": {
                "processes": [
                    {"pid": 100, "uid": 0, "name": "sshd"},
                ],
            },
        }

        with patch("builtins.open") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = "sshd (enforce)"
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_unconfined_root(self):
        check = UnconfinedRootProcessesCheck()
        collectors = {
            "processes": {
                "processes": [
                    {"pid": 200, "uid": 0, "name": "evil"},
                ],
            },
        }

        with patch("builtins.open") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = "unconfined"
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "unconfined" in f.title.lower()
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.MEDIUM

    def test_skips_non_root(self):
        check = UnconfinedRootProcessesCheck()
        collectors = {
            "processes": {
                "processes": [
                    {"pid": 300, "uid": 1000, "name": "user_proc"},
                ],
            },
        }

        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = UnconfinedRootProcessesCheck()
        collectors = {"processes": {"processes": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = UnconfinedRootProcessesCheck()
        collectors = {
            "processes": {
                "processes": [
                    {"pid": 200, "uid": 0, "name": "evil"},
                ],
            },
        }

        with patch("builtins.open") as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = "unconfined"
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0
