from __future__ import annotations

from usaf.checks.secrets.weak_ssh_keys import WeakSSHKeysCheck


class TestWeakSSHKeysCheck:
    def test_no_findings_when_no_keys(self):
        check = WeakSSHKeysCheck()
        collectors = {"ssh_config": {"host_keys": []}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_detects_dsa_key(self):
        check = WeakSSHKeysCheck()
        collectors = {
            "ssh_config": {
                "host_keys": [
                    {"path": "/etc/ssh/ssh_host_dsa_key", "name": "ssh_host_dsa_key",
                     "type": "dsa", "size": 1024, "public": False},
                ]
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].id.endswith("-001")

    def test_skips_ed25519_key(self):
        check = WeakSSHKeysCheck()
        collectors = {
            "ssh_config": {
                "host_keys": [
                    {"path": "/etc/ssh/ssh_host_ed25519_key", "name": "ssh_host_ed25519_key",
                     "type": "ed25519", "size": 400, "public": False},
                ]
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_check_id(self):
        assert WeakSSHKeysCheck.id == "SECR-302"
