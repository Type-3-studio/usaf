from __future__ import annotations

from pathlib import Path

from usaf.checks.system.ssh_security_checks import (
    SSHBannerCheck,
    SSHCiphersCheck,
    SSHEmptyPasswordsCheck,
    SSHHostbasedAuthCheck,
    SSHMaxAuthTriesCheck,
    SSHMaxStartupsCheck,
    SSHClientAliveCheck,
    SSHPermitUserEnvironmentCheck,
)
from usaf.models.severity import Confidence, Severity


def _make_collectors(directives: dict | None = None) -> dict:
    return {
        "ssh_config": {
            "sshd_config": {
                "directives": directives or {},
            }
        }
    }


class TestSSHMaxAuthTriesCheck:
    def test_passes_when_maxauthtries_4(self):
        check = SSHMaxAuthTriesCheck()
        collectors = _make_collectors({"maxauthtries": "4"})
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_maxauthtries_6(self):
        check = SSHMaxAuthTriesCheck()
        collectors = _make_collectors({"maxauthtries": "6"})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.HIGH
        assert "6" in (f.detected_value or "")

    def test_fails_when_maxauthtries_10(self):
        check = SSHMaxAuthTriesCheck()
        collectors = _make_collectors({"maxauthtries": "10"})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_passes_without_directive(self):
        check = SSHMaxAuthTriesCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_cis_mapping(self):
        check = SSHMaxAuthTriesCheck()
        collectors = _make_collectors({"maxauthtries": "6"})
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestSSHEmptyPasswordsCheck:
    def test_passes_when_no_directive(self):
        check = SSHEmptyPasswordsCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_when_no(self):
        check = SSHEmptyPasswordsCheck()
        collectors = _make_collectors({"permitemptypasswords": "no"})
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_when_yes(self):
        check = SSHEmptyPasswordsCheck()
        collectors = _make_collectors({"permitemptypasswords": "yes"})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL

    def test_no_findings_when_no_ssh_config(self):
        check = SSHEmptyPasswordsCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_mitre_mapping(self):
        check = SSHEmptyPasswordsCheck()
        collectors = _make_collectors({"permitemptypasswords": "yes"})
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSSHClienAliveCheck:
    def test_passes_when_both_configured(self):
        check = SSHClientAliveCheck()
        collectors = _make_collectors({
            "clientaliveinterval": "300",
            "clientalivecountmax": "0",
        })
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_when_interval_missing(self):
        check = SSHClientAliveCheck()
        collectors = _make_collectors({"clientalivecountmax": "0"})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "ClientAliveInterval" in (result.findings[0].description or "")

    def test_fails_when_countmax_missing(self):
        check = SSHClientAliveCheck()
        collectors = _make_collectors({"clientaliveinterval": "300"})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "ClientAliveCountMax" in (result.findings[0].description or "")

    def test_fails_when_neither_configured(self):
        check = SSHClientAliveCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_no_findings_without_ssh_config(self):
        check = SSHClientAliveCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_cis_mapping(self):
        check = SSHClientAliveCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestSSHBannerCheck:
    def test_fails_when_no_banner(self):
        check = SSHBannerCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_banner_file_missing(self):
        check = SSHBannerCheck()
        collectors = _make_collectors({"banner": "/etc/ssh/nonexistent_banner"})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "not exist" in result.findings[0].title.lower()

    def test_passes_when_banner_exists(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        check = SSHBannerCheck()
        collectors = _make_collectors({"banner": "/etc/ssh/banner"})
        result = check.evaluate(collectors)
        assert result.passed

    def test_no_findings_without_ssh_config(self):
        check = SSHBannerCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_cis_mapping(self):
        check = SSHBannerCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestSSHPermitUserEnvironmentCheck:
    def test_passes_when_no_directive(self):
        check = SSHPermitUserEnvironmentCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_when_no(self):
        check = SSHPermitUserEnvironmentCheck()
        collectors = _make_collectors({"permituserenvironment": "no"})
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_when_yes(self):
        check = SSHPermitUserEnvironmentCheck()
        collectors = _make_collectors({"permituserenvironment": "yes"})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM

    def test_has_mitre_mapping(self):
        check = SSHPermitUserEnvironmentCheck()
        collectors = _make_collectors({"permituserenvironment": "yes"})
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSSHMaxStartupsCheck:
    def test_fails_when_not_configured(self):
        check = SSHMaxStartupsCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_passes_when_configured(self):
        check = SSHMaxStartupsCheck()
        collectors = _make_collectors({"maxstartups": "10:30:60"})
        result = check.evaluate(collectors)
        assert result.passed

    def test_no_findings_without_ssh_config(self):
        check = SSHMaxStartupsCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_mitre_mapping(self):
        check = SSHMaxStartupsCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSSHHostbasedAuthCheck:
    def test_passes_when_no_directive(self):
        check = SSHHostbasedAuthCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_when_no(self):
        check = SSHHostbasedAuthCheck()
        collectors = _make_collectors({"hostbasedauthentication": "no"})
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_when_yes(self):
        check = SSHHostbasedAuthCheck()
        collectors = _make_collectors({"hostbasedauthentication": "yes"})
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_has_cis_mapping(self):
        check = SSHHostbasedAuthCheck()
        collectors = _make_collectors({"hostbasedauthentication": "yes"})
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestSSHCiphersCheck:
    def test_passes_with_no_ciphers_line(self):
        check = SSHCiphersCheck()
        collectors = _make_collectors({})
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_strong_ciphers(self):
        check = SSHCiphersCheck()
        collectors = _make_collectors({
            "ciphers": "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com"
        })
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_weak_ciphers(self):
        check = SSHCiphersCheck()
        collectors = _make_collectors({
            "ciphers": "aes128-cbc,aes256-ctr"
        })
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "aes128-cbc" in (result.findings[0].detected_value or "")

    def test_fails_with_arcfour(self):
        check = SSHCiphersCheck()
        collectors = _make_collectors({
            "ciphers": "arcfour,chacha20-poly1305@openssh.com"
        })
        result = check.evaluate(collectors)
        assert not result.passed
        assert "arcfour" in (result.findings[0].detected_value or "")

    def test_fails_with_none_cipher(self):
        check = SSHCiphersCheck()
        collectors = _make_collectors({
            "ciphers": "none"
        })
        result = check.evaluate(collectors)
        assert not result.passed

    def test_no_findings_without_ssh_config(self):
        check = SSHCiphersCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_cis_mapping(self):
        check = SSHCiphersCheck()
        collectors = _make_collectors({
            "ciphers": "aes128-cbc,aes256-ctr"
        })
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_mapping(self):
        check = SSHCiphersCheck()
        collectors = _make_collectors({
            "ciphers": "aes128-cbc"
        })
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


from usaf.checks.system.ssh_security_checks import (
    SSHHostKeyTypeCheck,
    SSHAuthorizedKeysPermsCheck,
    SSHLogLevelCheck,
    SSHX11ForwardingCheck,
    SSHTcpForwardingCheck,
    SSHCompressionCheck,
    SSHPermitTunnelCheck,
    SSHGSSAPICheck,
)


class TestSSHHostKeyTypeCheck:
    def test_passes_no_keys(self):
        check = SSHHostKeyTypeCheck()
        result = check.evaluate({"ssh_config": {"host_keys": []}})
        assert result.passed

    def test_passes_rsa_key(self):
        check = SSHHostKeyTypeCheck()
        result = check.evaluate({"ssh_config": {"host_keys": [
            {"path": "/etc/ssh/ssh_host_rsa_key", "type": "rsa", "public": False},
        ]}})
        assert result.passed

    def test_fails_dsa_key(self):
        check = SSHHostKeyTypeCheck()
        result = check.evaluate({"ssh_config": {"host_keys": [
            {"path": "/etc/ssh/ssh_host_dsa_key", "type": "dsa", "public": False},
        ]}})
        assert not result.passed
        assert len(result.findings) == 1


class TestSSHAuthorizedKeysPermsCheck:
    def test_passes_no_keys(self):
        check = SSHAuthorizedKeysPermsCheck()
        result = check.evaluate({"ssh_config": {"authorized_keys_dirs": []}})
        assert result.passed

    def test_passes_600(self):
        check = SSHAuthorizedKeysPermsCheck()
        result = check.evaluate({"ssh_config": {"authorized_keys_dirs": [
            {"user": "test", "path": "/home/test/.ssh/authorized_keys", "permissions": "0o600"},
        ]}})
        assert result.passed

    def test_fails_weak(self):
        check = SSHAuthorizedKeysPermsCheck()
        result = check.evaluate({"ssh_config": {"authorized_keys_dirs": [
            {"user": "test", "path": "/home/test/.ssh/authorized_keys", "permissions": "0o777"},
        ]}})
        assert not result.passed


class TestSSHLogLevelCheck:
    def test_passes_verbose(self):
        check = SSHLogLevelCheck()
        result = check.evaluate(_make_collectors({"loglevel": "VERBOSE"}))
        assert result.passed

    def test_fails_quiet(self):
        check = SSHLogLevelCheck()
        result = check.evaluate(_make_collectors({"loglevel": "QUIET"}))
        assert not result.passed


class TestSSHX11ForwardingCheck:
    def test_passes_no(self):
        check = SSHX11ForwardingCheck()
        result = check.evaluate(_make_collectors({"x11forwarding": "no"}))
        assert result.passed

    def test_fails_yes(self):
        check = SSHX11ForwardingCheck()
        result = check.evaluate(_make_collectors({"x11forwarding": "yes"}))
        assert not result.passed


class TestSSHTcpForwardingCheck:
    def test_passes_no(self):
        check = SSHTcpForwardingCheck()
        result = check.evaluate(_make_collectors({"allowtcpforwarding": "no"}))
        assert result.passed

    def test_fails_yes(self):
        check = SSHTcpForwardingCheck()
        result = check.evaluate(_make_collectors({"allowtcpforwarding": "yes"}))
        assert not result.passed


class TestSSHCompressionCheck:
    def test_passes_no(self):
        check = SSHCompressionCheck()
        result = check.evaluate(_make_collectors({"compression": "no"}))
        assert result.passed

    def test_fails_yes(self):
        check = SSHCompressionCheck()
        result = check.evaluate(_make_collectors({"compression": "yes"}))
        assert not result.passed


class TestSSHPermitTunnelCheck:
    def test_passes_no(self):
        check = SSHPermitTunnelCheck()
        result = check.evaluate(_make_collectors({"permittunnel": "no"}))
        assert result.passed

    def test_fails_yes(self):
        check = SSHPermitTunnelCheck()
        result = check.evaluate(_make_collectors({"permittunnel": "yes"}))
        assert not result.passed


class TestSSHGSSAPICheck:
    def test_passes_no(self):
        check = SSHGSSAPICheck()
        result = check.evaluate(_make_collectors({"gssapiauthentication": "no"}))
        assert result.passed

    def test_fails_yes(self):
        check = SSHGSSAPICheck()
        result = check.evaluate(_make_collectors({"gssapiauthentication": "yes"}))
        assert not result.passed
