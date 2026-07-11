from __future__ import annotations

from pathlib import Path

from usaf.checks.system.ssh_checks import SSHKeyExchangeCheck, SSHProtocolCheck, SSHRootLoginCheck
from usaf.models.severity import Confidence, Severity


class TestSSHProtocolCheck:
    def test_passes_when_protocol_2(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "Protocol 2\nPort 22\n")
        check = SSHProtocolCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_protocol_1(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "Protocol 1\nPort 22\n")
        check = SSHProtocolCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.HIGH
        assert "1" in (f.detected_value or "")
        assert "protocol version 1" in f.title.lower()

    def test_fails_when_protocol_2_1(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "Protocol 2,1\nPort 22\n")
        check = SSHProtocolCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_no_findings_when_no_ssh_config(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = SSHProtocolCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_has_cis_mapping(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "Protocol 1\n")
        check = SSHProtocolCheck()
        result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0


class TestSSHRootLoginCheck:
    def test_passes_when_root_login_no(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "PermitRootLogin no\n")
        check = SSHRootLoginCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_root_login_yes(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "PermitRootLogin yes\n")
        check = SSHRootLoginCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.HIGH
        assert "yes" in (f.detected_value or "")

    def test_fails_when_prohibit_password(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "PermitRootLogin prohibit-password\n")
        check = SSHRootLoginCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_no_findings_when_no_config(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = SSHRootLoginCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_mitre_mapping(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "PermitRootLogin yes\n")
        check = SSHRootLoginCheck()
        result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSSHKeyExchangeCheck:
    def test_passes_with_secure_kex(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "KexAlgorithms curve25519-sha256,diffie-hellman-group-exchange-sha256\n")
        check = SSHKeyExchangeCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_weak_kex(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "KexAlgorithms diffie-hellman-group1-sha1,curve25519-sha256\n")
        check = SSHKeyExchangeCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM
        assert "diffie-hellman-group1-sha1" in (f.detected_value or "")

    def test_passes_with_no_kex_line(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "Port 22\n")
        check = SSHKeyExchangeCheck()
        result = check.evaluate({})
        assert result.passed

    def test_no_findings_when_no_config(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = SSHKeyExchangeCheck()
        result = check.evaluate({})
        assert result.passed
