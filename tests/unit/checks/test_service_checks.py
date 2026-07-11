from __future__ import annotations

from pathlib import Path

from usaf.checks.services.insecure_services import InsecureServicesCheck
from usaf.models.severity import Severity


class TestInsecureServicesCheck:
    def test_passes_when_no_insecure_units(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = InsecureServicesCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_telnet_unit_exists(self, monkeypatch):
        orig_exists = Path.exists

        def fake_exists(p):
            s = str(p)
            if s.endswith("telnet.socket") or s.endswith("telnet.service"):
                return True
            return orig_exists(p)

        monkeypatch.setattr(Path, "exists", fake_exists)
        check = InsecureServicesCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "telnet" in f.title.lower()
        assert f.severity == Severity.HIGH

    def test_fails_with_multiple_insecure_services(self, monkeypatch):
        orig_exists = Path.exists

        def fake_exists(p):
            s = str(p)
            if any(u in s for u in ["telnet.socket", "rsh.service", "vsftpd.service"]):
                return True
            return orig_exists(p)

        monkeypatch.setattr(Path, "exists", fake_exists)
        check = InsecureServicesCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 3

    def test_checks_all_search_dirs(self, monkeypatch):
        orig_exists = Path.exists
        checked_dirs = set()

        def fake_exists(p):
            s = str(p)
            if s.endswith("telnet.socket"):
                checked_dirs.add(str(p))
                return True
            return orig_exists(p)

        monkeypatch.setattr(Path, "exists", fake_exists)
        check = InsecureServicesCheck()
        check.evaluate({})
        assert any("systemd/system" in d for d in checked_dirs)

    def test_has_mitre_and_cis_mapping(self, monkeypatch):
        def fake_exists(p):
            return str(p).endswith("telnet.socket")

        monkeypatch.setattr(Path, "exists", fake_exists)
        check = InsecureServicesCheck()
        result = check.evaluate({})
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert len(f.cis_benchmarks) > 0
