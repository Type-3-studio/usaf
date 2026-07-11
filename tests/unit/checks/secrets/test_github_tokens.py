from __future__ import annotations

from usaf.checks.secrets.github_tokens import GitHubTokensCheck


class TestGitHubTokensCheck:
    def test_no_findings_when_no_tokens(self):
        check = GitHubTokensCheck()
        collectors = {"secrets": {"github_tokens": [], "scanned_dirs": []}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_finds_github_pat(self):
        check = GitHubTokensCheck()
        collectors = {
            "secrets": {
                "github_tokens": [
                    {
                        "path": "/home/user/.gitconfig",
                        "line": 3,
                        "match": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
                        "permission": "0o644",
                        "owner": "1000",
                        "size": 500,
                    }
                ],
                "scanned_dirs": ["/home/user"],
            }
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "GitHub" in result.findings[0].title

    def test_check_id(self):
        assert GitHubTokensCheck.id == "SECR-201"
