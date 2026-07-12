from __future__ import annotations

from usaf.checks.system.ssh_checks import SSHKeyExchangeCheck, SSHProtocolCheck, SSHRootLoginCheck
from usaf.models.severity import Confidence, Severity

_BASE_DIRECTIVES = {
    "protocol": "2",
    "permitrootlogin": "no",
    "kexalgorithms": "curve25519-sha256",
}

def _collectors(directives: dict | None = None) -> dict:
    d = dict(_BASE_DIRECTIVES)
    if directives:
        d.update(directives)
    return {"ssh_config": {"sshd_config": {"directives": d}}}


class TestSSHProtocolCheck:
    def test_passes_when_protocol_2(self):
        check = SSHProtocolCheck()
        result = check.evaluate(_collectors({"protocol": "2"}))
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_protocol_1(self):
        check = SSHProtocolCheck()
        result = check.evaluate(_collectors({"protocol": "1"}))
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.HIGH
        assert "1" in (f.detected_value or "")
        assert "protocol version 1" in f.title.lower()

    def test_fails_when_protocol_2_1(self):
        check = SSHProtocolCheck()
        result = check.evaluate(_collectors({"protocol": "2,1"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_no_findings_when_no_ssh_config(self):
        check = SSHProtocolCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_has_cis_mapping(self):
        check = SSHProtocolCheck()
        result = check.evaluate(_collectors({"protocol": "1"}))
        assert len(result.findings[0].cis_benchmarks) > 0


class TestSSHRootLoginCheck:
    def test_passes_when_root_login_no(self):
        check = SSHRootLoginCheck()
        result = check.evaluate(_collectors({"permitrootlogin": "no"}))
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_root_login_yes(self):
        check = SSHRootLoginCheck()
        result = check.evaluate(_collectors({"permitrootlogin": "yes"}))
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.HIGH
        assert "yes" in (f.detected_value or "")

    def test_fails_when_prohibit_password(self):
        check = SSHRootLoginCheck()
        result = check.evaluate(_collectors({"permitrootlogin": "prohibit-password"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_no_findings_when_no_ssh_config(self):
        check = SSHRootLoginCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_has_cis_mapping(self):
        check = SSHRootLoginCheck()
        result = check.evaluate(_collectors({"permitrootlogin": "yes"}))
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_mapping(self):
        check = SSHRootLoginCheck()
        result = check.evaluate(_collectors({"permitrootlogin": "yes"}))
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSSHKeyExchangeCheck:
    def test_passes_with_secure_kex(self):
        check = SSHKeyExchangeCheck()
        result = check.evaluate(_collectors({"kexalgorithms": "curve25519-sha256"}))
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_weak_kex(self):
        check = SSHKeyExchangeCheck()
        result = check.evaluate(_collectors({"kexalgorithms": "diffie-hellman-group1-sha1,curve25519-sha256"}))
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM
        assert "diffie-hellman-group1-sha1" in (f.detected_value or "")

    def test_passes_with_no_kex_line(self):
        check = SSHKeyExchangeCheck()
        result = check.evaluate(_collectors({"port": "22"}))
        assert result.passed

    def test_no_findings_when_no_config(self):
        check = SSHKeyExchangeCheck()
        result = check.evaluate({})
        assert result.passed
