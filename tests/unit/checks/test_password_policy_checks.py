from __future__ import annotations

from pathlib import Path

from usaf.checks.authentication.password_policy import PasswordPolicyCheck
from usaf.models.severity import Severity


class TestPasswordPolicyCheck:
    def test_passes_when_minlen_12_and_pass_min_len_12(self, monkeypatch):
        def fake_read_text(p):
            s = str(p)
            if s.endswith("common-password"):
                return "password requisite pam_unix.so sha512 minlen=12\n"
            if s.endswith("login.defs"):
                return "PASS_MIN_LEN 12\n"
            return ""

        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", fake_read_text)
        check = PasswordPolicyCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_minlen_below_12(self, monkeypatch):
        def fake_read_text(p):
            s = str(p)
            if s.endswith("common-password"):
                return "password requisite pam_unix.so sha512 minlen=8\n"
            if s.endswith("login.defs"):
                return "PASS_MIN_LEN 12\n"
            return ""

        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", fake_read_text)
        check = PasswordPolicyCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "minlen" in f.title.lower() or "length" in f.title.lower()
        assert f.severity == Severity.HIGH

    def test_fails_when_pass_min_len_below_12(self, monkeypatch):
        def fake_read_text(p):
            s = str(p)
            if s.endswith("common-password"):
                return "password requisite pam_unix.so sha512 minlen=12\n"
            if s.endswith("login.defs"):
                return "PASS_MIN_LEN 8\n"
            return ""

        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", fake_read_text)
        check = PasswordPolicyCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_pam_unix_not_configured(self, monkeypatch):
        def fake_read_text(p):
            s = str(p)
            if s.endswith("common-password"):
                return "password requisite pam_deny.so\n"
            if s.endswith("login.defs"):
                return "PASS_MIN_LEN 12\n"
            return ""

        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", fake_read_text)
        check = PasswordPolicyCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_handles_missing_files(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = PasswordPolicyCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_handles_invalid_minlen_value(self, monkeypatch):
        def fake_read_text(p):
            s = str(p)
            if s.endswith("common-password"):
                return "password requisite pam_unix.so sha512 minlen=abc\n"
            if s.endswith("login.defs"):
                return "PASS_MIN_LEN 12\n"
            return ""

        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", fake_read_text)
        check = PasswordPolicyCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_and_cis_mapping(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = PasswordPolicyCheck()
        result = check.evaluate({})
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert len(f.cis_benchmarks) > 0
