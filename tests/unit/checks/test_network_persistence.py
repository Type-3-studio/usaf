from __future__ import annotations

from usaf.checks.persistence.network_persistence import (
    NetworkHookScriptsCheck,
    SshAuthorizedKeysFileTamperCheck,
    SshForcedCommandsCheck,
)


class TestNetworkHookScriptsCheck:
    def test_does_not_error_with_no_data(self):
        check = NetworkHookScriptsCheck()
        result = check.evaluate({})
        assert result.error is None

    def test_has_mitre_mapping(self):
        check = NetworkHookScriptsCheck()
        result = check.evaluate({})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestSshForcedCommandsCheck:
    def test_passes_with_no_ssh_data(self):
        check = SshForcedCommandsCheck()
        result = check.evaluate({"ssh_config": {}})
        assert result.passed

    def test_passes_with_empty_authorized_keys_dirs(self):
        check = SshForcedCommandsCheck()
        result = check.evaluate({"ssh_config": {"authorized_keys_dirs": []}})
        assert result.passed

    def test_passes_with_nonexistent_paths(self):
        check = SshForcedCommandsCheck()
        result = check.evaluate({
            "ssh_config": {
                "authorized_keys_dirs": [
                    {"path": "/nonexistent/path/authorized_keys", "user": "testuser"},
                ]
            }
        })
        assert result.passed

    def test_has_mitre_mapping(self):
        check = SshForcedCommandsCheck()
        result = check.evaluate({"ssh_config": {}})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestSshAuthorizedKeysFileTamperCheck:
    def test_passes_with_default_directive(self):
        check = SshAuthorizedKeysFileTamperCheck()
        result = check.evaluate({
            "ssh_config": {
                "sshd_config": {
                    "directives": {"authorizedkeysfile": ".ssh/authorized_keys"},
                    "path": "/etc/ssh/sshd_config",
                },
                "authorized_keys_dirs": [],
            }
        })
        assert result.passed

    def test_passes_with_no_ssh_data(self):
        check = SshAuthorizedKeysFileTamperCheck()
        result = check.evaluate({"ssh_config": {}})
        assert result.passed

    def test_fails_with_modified_directive(self):
        check = SshAuthorizedKeysFileTamperCheck()
        result = check.evaluate({
            "ssh_config": {
                "sshd_config": {
                    "directives": {"authorizedkeysfile": "/tmp/custom_keys"},
                    "path": "/etc/ssh/sshd_config",
                },
                "authorized_keys_dirs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert "AuthorizedKeysFile" in result.findings[0].title

    def test_fails_with_absolute_path_directive(self):
        check = SshAuthorizedKeysFileTamperCheck()
        result = check.evaluate({
            "ssh_config": {
                "sshd_config": {
                    "directives": {"authorizedkeysfile": "/var/lib/ssh/keys"},
                    "path": "/etc/ssh/sshd_config",
                },
                "authorized_keys_dirs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_mapping(self):
        check = SshAuthorizedKeysFileTamperCheck()
        result = check.evaluate({
            "ssh_config": {
                "sshd_config": {
                    "directives": {"authorizedkeysfile": "/tmp/custom_keys"},
                    "path": "/etc/ssh/sshd_config",
                },
                "authorized_keys_dirs": [],
            }
        })
        assert len(result.findings) > 0
        assert len(result.findings[0].mitre_attack_ids) > 0
