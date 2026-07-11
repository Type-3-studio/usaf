from __future__ import annotations

from pathlib import Path

from usaf.checks.forensics.audit_log_check import AuditLogCheck
from usaf.models.severity import Severity


class FakeNonEmptyStat:
    st_size = 4096


class FakeEmptyStat:
    st_size = 0


class TestAuditLogCheck:
    def test_passes_when_audit_log_exists_and_nonempty(self, monkeypatch):
        orig_exists = Path.exists

        def fake_exists(p):
            if str(p).endswith("/audit"):
                return True
            if str(p).endswith("/audit.log"):
                return True
            return orig_exists(p)

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(Path, "stat", lambda _: FakeNonEmptyStat())
        check = AuditLogCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_audit_dir_missing(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = AuditLogCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "directory" in f.title.lower()
        assert f.severity == Severity.MEDIUM

    def test_fails_when_audit_log_empty(self, monkeypatch):
        orig_exists = Path.exists

        def fake_exists(p):
            if str(p).endswith("/audit"):
                return True
            if str(p).endswith("/audit.log"):
                return True
            return orig_exists(p)

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(Path, "stat", lambda _: FakeEmptyStat())
        check = AuditLogCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "empty" in f.title.lower() or "missing" in f.title.lower()

    def test_fails_when_audit_log_missing(self, monkeypatch):
        orig_exists = Path.exists
        call_count = 0

        def fake_exists(p):
            nonlocal call_count
            call_count += 1
            if str(p).endswith("/audit"):
                return call_count > 1
            return orig_exists(p)

        monkeypatch.setattr(Path, "exists", fake_exists)
        check = AuditLogCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_and_cis_mapping(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = AuditLogCheck()
        result = check.evaluate({})
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert len(f.cis_benchmarks) > 0
