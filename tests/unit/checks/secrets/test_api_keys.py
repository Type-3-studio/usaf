from __future__ import annotations

from usaf.checks.secrets.api_keys import APIKeysCheck


class TestAPIKeysCheck:
    def test_no_findings_when_no_api_keys(self):
        check = APIKeysCheck()
        collectors = {"secrets": {"api_keys": [], "scanned_dirs": []}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_finds_api_key(self):
        check = APIKeysCheck()
        collectors = {
            "secrets": {
                "api_keys": [
                    {
                        "path": "/home/user/config.yml",
                        "line": 5,
                        "match": "api_key = sk-1234567890abcdef12345678",
                        "permission": "0o644",
                        "owner": "1000",
                        "size": 1000,
                    }
                ],
                "scanned_dirs": ["/home/user"],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "api_key" in result.findings[0].description.lower()

    def test_check_id(self):
        assert APIKeysCheck.id == "SECR-203"
