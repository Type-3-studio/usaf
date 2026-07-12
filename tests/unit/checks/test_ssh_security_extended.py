from __future__ import annotations

from usaf.checks.system.ssh_security_extended import (
    SshAgentForwardingCheck,
    SshClientAliveCountMaxCheck,
    SshHostKeySizeCheck,
    SshMacAlgorithmsCheck,
    SshPortCheck,
    SshPubkeyAuthOnlyCheck,
)
from usaf.models.severity import Confidence, Severity


def _collectors(directives: dict | None = None) -> dict:
    base = {
        "allowagentforwarding": "no",
        "pubkeyauthentication": "yes",
        "passwordauthentication": "no",
        "macs": "hmac-sha2-256,hmac-sha2-512",
        "clientaliveinterval": "300",
        "clientalivecountmax": "3",
    }
    if directives:
        base.update(directives)
    return {"ssh_config": {"sshd_config": {"directives": base}}}


class TestSshMacAlgorithmsCheck:
    def test_passes_with_strong_macs(self):
        check = SshMacAlgorithmsCheck()
        result = check.evaluate(_collectors({"macs": "hmac-sha2-256,hmac-sha2-512"}))
        assert result.passed

    def test_fails_with_weak_macs(self):
        check = SshMacAlgorithmsCheck()
        result = check.evaluate(_collectors({"macs": "hmac-md5,hmac-sha1"}))
        assert not result.passed
        assert len(result.findings) == 1
        assert "hmac-md5" in result.findings[0].description
        assert result.findings[0].severity == Severity.MEDIUM

    def test_has_cis(self):
        check = SshMacAlgorithmsCheck()
        result = check.evaluate(_collectors({"macs": "hmac-md5"}))
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = SshMacAlgorithmsCheck()
        result = check.evaluate(_collectors({"macs": "hmac-md5"}))
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSshHostKeySizeCheck:
    def test_passes_with_strong_keys(self):
        check = SshHostKeySizeCheck()
        collectors = {"ssh_config": {"host_keys": [
            {"type": "ssh-rsa", "size": 4096, "path": "/etc/ssh/ssh_host_rsa_key"},
            {"type": "ecdsa-sha2-nistp256", "size": 256, "path": "/etc/ssh/ssh_host_ecdsa_key"},
        ]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_weak_rsa(self):
        check = SshHostKeySizeCheck()
        collectors = {"ssh_config": {"host_keys": [
            {"type": "ssh-rsa", "size": 2048, "path": "/etc/ssh/ssh_host_rsa_key"},
        ]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "2048" in result.findings[0].title
        assert result.findings[0].severity == Severity.MEDIUM

    def test_has_mitre_ids(self):
        check = SshHostKeySizeCheck()
        collectors = {"ssh_config": {"host_keys": [
            {"type": "ssh-rsa", "size": 2048, "path": "/etc/ssh/ssh_host_rsa_key"},
        ]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSshAgentForwardingCheck:
    def test_passes_with_forwarding_off(self):
        check = SshAgentForwardingCheck()
        result = check.evaluate(_collectors({"allowagentforwarding": "no"}))
        assert result.passed

    def test_fails_with_forwarding_on(self):
        check = SshAgentForwardingCheck()
        result = check.evaluate(_collectors({"allowagentforwarding": "yes"}))
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM

    def test_fails_with_not_configured(self):
        check = SshAgentForwardingCheck()
        result = check.evaluate({"ssh_config": {"sshd_config": {"directives": {}}}})
        assert not result.passed

    def test_has_cis(self):
        check = SshAgentForwardingCheck()
        result = check.evaluate(_collectors({"allowagentforwarding": "yes"}))
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = SshAgentForwardingCheck()
        result = check.evaluate(_collectors({"allowagentforwarding": "yes"}))
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSshPubkeyAuthOnlyCheck:
    def test_passes_with_proper_config(self):
        check = SshPubkeyAuthOnlyCheck()
        result = check.evaluate(_collectors({"pubkeyauthentication": "yes", "passwordauthentication": "no"}))
        assert result.passed

    def test_fails_with_password_auth(self):
        check = SshPubkeyAuthOnlyCheck()
        result = check.evaluate(_collectors({"pubkeyauthentication": "yes", "passwordauthentication": "yes"}))
        assert not result.passed
        assert len(result.findings) == 1
        assert "PasswordAuthentication" in result.findings[0].description
        assert result.findings[0].severity == Severity.HIGH

    def test_has_cis(self):
        check = SshPubkeyAuthOnlyCheck()
        result = check.evaluate(_collectors({"passwordauthentication": "yes"}))
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = SshPubkeyAuthOnlyCheck()
        result = check.evaluate(_collectors({"passwordauthentication": "yes"}))
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSshPortCheck:
    def test_passes_with_default_port(self):
        check = SshPortCheck()
        result = check.evaluate(_collectors({}))
        assert result.passed

    def test_has_mitre_ids(self):
        check = SshPortCheck()
        result = check.evaluate(_collectors({"port": "2222"}))
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestSshClientAliveCountMaxCheck:
    def test_passes_with_reasonable_timeout(self):
        check = SshClientAliveCountMaxCheck()
        result = check.evaluate(_collectors({"clientaliveinterval": "300", "clientalivecountmax": "3"}))
        assert result.passed

    def test_fails_with_long_timeout(self):
        check = SshClientAliveCountMaxCheck()
        result = check.evaluate(_collectors({"clientaliveinterval": "600", "clientalivecountmax": "10"}))
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM

    def test_has_cis(self):
        check = SshClientAliveCountMaxCheck()
        result = check.evaluate(_collectors({"clientaliveinterval": "600", "clientalivecountmax": "10"}))
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = SshClientAliveCountMaxCheck()
        result = check.evaluate(_collectors({"clientaliveinterval": "600", "clientalivecountmax": "10"}))
        assert len(result.findings[0].mitre_attack_ids) > 0
