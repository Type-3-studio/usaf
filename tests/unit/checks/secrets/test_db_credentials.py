from __future__ import annotations

from usaf.checks.secrets.db_credentials import DBCredentialsCheck


class TestDBCredentialsCheck:
    def test_no_findings_when_no_db_creds(self):
        check = DBCredentialsCheck()
        collectors = {"secrets": {"db_credentials": [], "scanned_dirs": []}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_finds_db_connection_string(self):
        check = DBCredentialsCheck()
        collectors = {
            "secrets": {
                "db_credentials": [
                    {
                        "path": "/home/user/app/config.py",
                        "line": 10,
                        "match": "postgresql://user:password@localhost:5432/mydb",
                        "permission": "0o644",
                        "owner": "1000",
                        "size": 5000,
                    }
                ],
                "scanned_dirs": ["/home/user"],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "database" in result.findings[0].description.lower()

    def test_check_id(self):
        assert DBCredentialsCheck.id == "SECR-401"
