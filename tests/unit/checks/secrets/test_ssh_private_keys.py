from __future__ import annotations

from unittest.mock import patch

from usaf.checks.secrets.ssh_private_keys import ExposedSSHPrivateKeysCheck


class TestExposedSSHPrivateKeysCheck:
    def test_no_findings_when_no_keys(self):
        check = ExposedSSHPrivateKeysCheck()
        collectors = {"ssh_config": {"host_keys": []}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_no_findings_for_public_keys(self):
        check = ExposedSSHPrivateKeysCheck()
        collectors = {
            "ssh_config": {
                "host_keys": [
                    {"path": "/etc/ssh/ssh_host_rsa_key.pub", "name": "ssh_host_rsa_key.pub",
                     "type": "rsa", "size": 400, "public": True},
                ]
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    @patch("os.stat")
    def test_skips_when_permission_is_safe(self, mock_stat):
        mock_stat.return_value.st_mode = 0o100600
        check = ExposedSSHPrivateKeysCheck()
        collectors = {
            "ssh_config": {
                "host_keys": [
                    {"path": "/etc/ssh/ssh_host_rsa_key", "name": "ssh_host_rsa_key",
                     "type": "rsa", "size": 1679, "public": False},
                ]
            }
        }
        result = check.evaluate(collectors)
        assert result.passed

    @patch("os.stat")
    def test_detects_weak_permissions(self, mock_stat):
        mock_stat.return_value.st_mode = 0o100644
        check = ExposedSSHPrivateKeysCheck()
        collectors = {
            "ssh_config": {
                "host_keys": [
                    {"path": "/etc/ssh/ssh_host_rsa_key", "name": "ssh_host_rsa_key",
                     "type": "rsa", "size": 1679, "public": False},
                ]
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].id.endswith("-001")

    @patch("os.stat")
    def test_detects_dsa_key(self, mock_stat):
        mock_stat.return_value.st_mode = 0o100600
        check = ExposedSSHPrivateKeysCheck()
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
        findings_by_id = {}
        for f in result.findings:
            findings_by_id[f.id] = f
        assert any(fid.endswith("-002") for fid in findings_by_id)

    @patch("os.stat")
    def test_multi_finding_for_dsa_with_weak_perms(self, mock_stat):
        mock_stat.return_value.st_mode = 0o100777
        check = ExposedSSHPrivateKeysCheck()
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
        assert len(result.findings) == 2

    def test_check_id(self):
        assert ExposedSSHPrivateKeysCheck.id == "SECR-301"
