from __future__ import annotations

from usaf.checks.secrets.aws_keys import AWSKeysCheck
from usaf.models.severity import CheckCategory


class TestAWSKeysCheck:
    def test_no_findings_when_no_aws_keys(self):
        check = AWSKeysCheck()
        collectors = {"secrets": {"aws_keys": [], "scanned_dirs": []}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_finds_aws_access_key_id(self):
        check = AWSKeysCheck()
        collectors = {
            "secrets": {
                "aws_keys": [
                    {
                        "path": "/home/user/.aws/credentials",
                        "line": 2,
                        "match": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
                        "permission": "0o644",
                        "owner": "1000",
                        "size": 200,
                    }
                ],
                "scanned_dirs": ["/home/user"],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "AKIA" in result.findings[0].description

    def test_deduplicates_duplicate_paths(self):
        check = AWSKeysCheck()
        collectors = {
            "secrets": {
                "aws_keys": [
                    {"path": "/home/user/.aws/credentials", "line": 2, "match": "AKIAxxx"},
                    {"path": "/home/user/.aws/credentials", "line": 4, "match": "AKIAyyy"},
                ],
                "scanned_dirs": ["/home/user"],
            }
        }
        result = check.evaluate(collectors)
        assert len(result.findings) == 1

    def test_check_metadata(self):
        check = AWSKeysCheck()
        assert check.id == "SECR-101"
        assert check.category == CheckCategory.SECURITY
        assert check.depends == ["secrets"]
