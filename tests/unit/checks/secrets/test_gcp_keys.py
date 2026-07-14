from __future__ import annotations

from usaf.checks.secrets.gcp_keys import GCPKeysCheck


class TestGCPKeysCheck:
    def test_no_findings_when_no_gcp_keys(self):
        check = GCPKeysCheck()
        collectors = {"secrets": {"gcp_keys": [], "scanned_dirs": []}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_finds_service_account_key(self):
        check = GCPKeysCheck()
        collectors = {
            "secrets": {
                "gcp_keys": [
                    {
                        "path": "/home/user/sa-key.json",
                        "line": 1,
                        "match": '"type": "service_account"',
                        "permission": "0o644",
                        "owner": "1000",
                        "size": 3000,
                    }
                ],
                "scanned_dirs": ["/home/user"],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "service_account" in result.findings[0].description

    def test_deduplicates(self):
        check = GCPKeysCheck()
        collectors = {
            "secrets": {
                "gcp_keys": [
                    {"path": "/home/user/sa-key.json", "line": 1, "match": "service_account"},
                    {"path": "/home/user/sa-key.json", "line": 5, "match": "private_key"},
                ],
                "scanned_dirs": ["/home/user"],
            }
        }
        result = check.evaluate(collectors)
        assert len(result.findings) == 1

    def test_check_id(self):
        assert GCPKeysCheck.id == "SECR-102"
