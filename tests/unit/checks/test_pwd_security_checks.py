from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.authentication.pwd_security_checks import (
    AccountLockoutCheck,
    DefaultPasswordCheck,
    PasswordHashAlgorithmCheck,
    PasswordMaxAgeCheck,
    PasswordMinAgeCheck,
    PasswordQualityCheck,
    PasswordReuseCheck,
    PasswordWarnAgeCheck,
)
from usaf.models.severity import Confidence, Severity


class TestPasswordReuseCheck:
    def test_passes_with_remember_configured(self):
        with patch.object(Path, "read_text", return_value="password requisite pam_unix.so remember=5 sha512\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordReuseCheck()
                result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_without_remember(self):
        with patch.object(Path, "read_text", return_value="password requisite pam_unix.so sha512\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordReuseCheck()
                result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "not configured" in f.title.lower()
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_fails_with_too_few_remember(self):
        with patch.object(Path, "read_text", return_value="password requisite pam_unix.so remember=2 sha512\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordReuseCheck()
                result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        assert "too short" in result.findings[0].title.lower() or "short" in result.findings[0].title.lower()

    def test_has_cis_benchmark(self):
        with patch.object(Path, "read_text", return_value="password requisite pam_unix.so sha512\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordReuseCheck()
                result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        with patch.object(Path, "read_text", return_value="password requisite pam_unix.so sha512\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordReuseCheck()
                result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestPasswordMinAgeCheck:
    def test_passes_with_min_days_configured(self):
        with patch.object(Path, "read_text", return_value="PASS_MIN_DAYS 7\nPASS_MAX_DAYS 90\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordMinAgeCheck()
                result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_low_min_days(self):
        with patch.object(Path, "read_text", return_value="PASS_MIN_DAYS 0\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordMinAgeCheck()
                result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "minimum" in f.title.lower() or "low" in f.title.lower()
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_has_cis_benchmark(self):
        with patch.object(Path, "read_text", return_value="PASS_MIN_DAYS 0\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordMinAgeCheck()
                result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0


class TestPasswordMaxAgeCheck:
    def test_passes_with_max_days_configured(self):
        with patch.object(Path, "read_text", return_value="PASS_MAX_DAYS 90\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordMaxAgeCheck()
                result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_no_expiry(self):
        with patch.object(Path, "read_text", return_value="PASS_MAX_DAYS 0\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordMaxAgeCheck()
                result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "never expires" in f.description.lower() or "permissive" in f.title.lower()
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_fails_with_very_high_max_days(self):
        with patch.object(Path, "read_text", return_value="PASS_MAX_DAYS 99999\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordMaxAgeCheck()
                result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_cis_benchmark(self):
        with patch.object(Path, "read_text", return_value="PASS_MAX_DAYS 99999\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordMaxAgeCheck()
                result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        with patch.object(Path, "read_text", return_value="PASS_MAX_DAYS 99999\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordMaxAgeCheck()
                result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestPasswordWarnAgeCheck:
    def test_passes_with_warn_age_configured(self):
        with patch.object(Path, "read_text", return_value="PASS_WARN_AGE 7\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordWarnAgeCheck()
                result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_without_warn_age(self):
        with patch.object(Path, "read_text", return_value="# no warn age\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordWarnAgeCheck()
                result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "warning" in f.title.lower() or "short" in f.title.lower()
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.HIGH

    def test_has_cis_benchmark(self):
        with patch.object(Path, "read_text", return_value="# no warn age\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordWarnAgeCheck()
                result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        with patch.object(Path, "read_text", return_value="# no warn age\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordWarnAgeCheck()
                result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestAccountLockoutCheck:
    def test_passes_with_faillock_configured(self):
        with patch.object(Path, "read_text", return_value="auth required pam_faillock.so preauth silent deny=5 unlock_time=900\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = AccountLockoutCheck()
                result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_without_lockout(self):
        with patch.object(Path, "read_text", return_value="auth required pam_unix.so\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = AccountLockoutCheck()
                result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "not configured" in f.title.lower()
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_fails_with_incomplete_lockout(self):
        with patch.object(Path, "read_text", return_value="auth required pam_faillock.so preauth silent deny=5\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = AccountLockoutCheck()
                result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_cis_benchmark(self):
        with patch.object(Path, "read_text", return_value="auth required pam_unix.so\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = AccountLockoutCheck()
                result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        with patch.object(Path, "read_text", return_value="auth required pam_unix.so\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = AccountLockoutCheck()
                result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestPasswordHashAlgorithmCheck:
    def test_passes_with_sha512(self):
        with patch.object(Path, "read_text", return_value="password requisite pam_unix.so sha512\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordHashAlgorithmCheck()
                result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_md5(self):
        with patch.object(Path, "read_text", return_value="password requisite pam_unix.so md5\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordHashAlgorithmCheck()
                result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "md5" in f.description.lower() or "weak" in f.title.lower()
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_has_cis_benchmark(self):
        with patch.object(Path, "read_text", return_value="password requisite pam_unix.so md5\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordHashAlgorithmCheck()
                result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        with patch.object(Path, "read_text", return_value="password requisite pam_unix.so md5\n"):
            with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True):
                check = PasswordHashAlgorithmCheck()
                result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestPasswordQualityCheck:
    def test_passes_with_good_config(self):
        with (
            patch.object(Path, "read_text", return_value="minlen = 12\nminclass = 3\nmaxrepeat = 3\n"),
            patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True),
        ):
            check = PasswordQualityCheck()
            result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_weak_config(self):
        with (
            patch.object(Path, "read_text", return_value="minlen = 8\nminclass = 2\n"),
            patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=True),
        ):
            check = PasswordQualityCheck()
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "weak" in f.title.lower() or "quality" in f.description.lower()
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM

    def test_fails_with_missing_config(self):
        with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=False):
            check = PasswordQualityCheck()
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        assert "not configured" in result.findings[0].title.lower()

    def test_has_cis_benchmark(self):
        with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=False):
            check = PasswordQualityCheck()
            result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        with patch("usaf.checks.authentication.pwd_security_checks.Path.exists", return_value=False):
            check = PasswordQualityCheck()
            result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestDefaultPasswordCheck:
    def test_passes_with_strong_hashes(self):
        check = DefaultPasswordCheck()
        collectors = {
            "users": {
                "shadow": [
                    {"username": "alice", "password_hash": "$6$xyzabc123"},
                    {"username": "bob", "password_hash": "$y$jkyes123"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_skips_locked_accounts(self):
        check = DefaultPasswordCheck()
        collectors = {
            "users": {
                "shadow": [
                    {"username": "alice", "password_hash": "!"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_md5_hash(self):
        check = DefaultPasswordCheck()
        collectors = {
            "users": {
                "shadow": [
                    {"username": "old_user", "password_hash": "$1$abcdefgh"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "weak" in f.title.lower() or "hash" in f.description.lower()
        assert f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.HIGH

    def test_fails_with_blowfish_hash(self):
        check = DefaultPasswordCheck()
        collectors = {
            "users": {
                "shadow": [
                    {"username": "user1", "password_hash": "$2a$abcdefgh"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_handles_empty_data(self):
        check = DefaultPasswordCheck()
        collectors = {"users": {"users": [], "shadow": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = DefaultPasswordCheck()
        collectors = {
            "users": {
                "shadow": [
                    {"username": "old_user", "password_hash": "$1$abcdefgh"},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0
