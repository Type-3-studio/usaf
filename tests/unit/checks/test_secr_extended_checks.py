from __future__ import annotations

from usaf.checks.secrets.secr_extended_checks import (
    AzureDevopsCheck,
    DockerCredsCheck,
    GitlabTokensCheck,
    NpmTokensCheck,
    PasswordInCodeCheck,
    SlackTokensCheck,
    StripeKeysCheck,
    TwilioKeysCheck,
)
from usaf.models.severity import Confidence, Severity


def make_collector(cat: str, path: str = "/home/user/.env", line: int = 5, match_str: str = "found_token_here") -> dict:
    return {"secrets": {cat: [{"path": path, "line": line, "match": match_str}]}}


def test_gitlab_tokens_check():
    check = GitlabTokensCheck()
    result = check.evaluate(make_collector("gitlab_tokens"))
    assert not result.passed
    assert len(result.findings) == 1
    f = result.findings[0]
    assert "GitLab" in f.title
    assert f.severity == Severity.CRITICAL
    assert f.confidence == Confidence.HIGH
    assert len(f.mitre_attack_ids) > 0


def test_gitlab_passes_with_no_tokens():
    check = GitlabTokensCheck()
    result = check.evaluate({"secrets": {"gitlab_tokens": []}})
    assert result.passed


def test_slack_tokens_check():
    check = SlackTokensCheck()
    result = check.evaluate(make_collector("slack_tokens"))
    assert not result.passed
    assert len(result.findings) == 1
    assert "Slack" in result.findings[0].title
    assert result.findings[0].severity == Severity.CRITICAL


def test_slack_passes_with_no_tokens():
    check = SlackTokensCheck()
    result = check.evaluate({"secrets": {"slack_tokens": []}})
    assert result.passed


def test_npm_tokens_check():
    check = NpmTokensCheck()
    result = check.evaluate(make_collector("npm_tokens"))
    assert not result.passed
    assert len(result.findings) == 1
    assert "NPM" in result.findings[0].title
    assert result.findings[0].severity == Severity.CRITICAL


def test_npm_passes_with_no_tokens():
    check = NpmTokensCheck()
    result = check.evaluate({"secrets": {"npm_tokens": []}})
    assert result.passed


def test_azure_devops_check():
    check = AzureDevopsCheck()
    result = check.evaluate(make_collector("azure_devops"))
    assert not result.passed
    assert len(result.findings) == 1
    assert "Azure" in result.findings[0].title
    assert result.findings[0].severity == Severity.HIGH


def test_azure_passes_with_no_tokens():
    check = AzureDevopsCheck()
    result = check.evaluate({"secrets": {"azure_devops": []}})
    assert result.passed


def test_docker_creds_check():
    check = DockerCredsCheck()
    result = check.evaluate(make_collector("docker_creds"))
    assert not result.passed
    assert len(result.findings) == 1
    assert "Docker" in result.findings[0].title
    assert result.findings[0].severity == Severity.CRITICAL


def test_docker_passes_with_no_tokens():
    check = DockerCredsCheck()
    result = check.evaluate({"secrets": {"docker_creds": []}})
    assert result.passed


def test_stripe_keys_check():
    check = StripeKeysCheck()
    result = check.evaluate(make_collector("stripe_keys"))
    assert not result.passed
    assert len(result.findings) == 1
    assert "Stripe" in result.findings[0].title
    assert result.findings[0].severity == Severity.CRITICAL


def test_stripe_passes_with_no_tokens():
    check = StripeKeysCheck()
    result = check.evaluate({"secrets": {"stripe_keys": []}})
    assert result.passed


def test_twilio_keys_check():
    check = TwilioKeysCheck()
    result = check.evaluate(make_collector("twilio_keys"))
    assert not result.passed
    assert len(result.findings) == 1
    assert "Twilio" in result.findings[0].title
    assert result.findings[0].severity == Severity.CRITICAL


def test_twilio_passes_with_no_tokens():
    check = TwilioKeysCheck()
    result = check.evaluate({"secrets": {"twilio_keys": []}})
    assert result.passed


def test_password_in_code_check():
    check = PasswordInCodeCheck()
    result = check.evaluate({
        "secrets": {
            "stripe_keys": [{"path": "/home/user/app.py", "line": 10, "match": "sk_live_abc123"}],
        },
    })
    assert not result.passed
    assert len(result.findings) >= 1
    f = result.findings[0]
    assert "credential" in f.title.lower()
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.MEDIUM


def test_password_in_code_passes_with_clean():
    check = PasswordInCodeCheck()
    result = check.evaluate({
        "secrets": {
            "gitlab_tokens": [],
            "slack_tokens": [],
            "npm_tokens": [],
            "azure_devops": [],
            "docker_creds": [],
            "stripe_keys": [],
            "twilio_keys": [],
        },
    })
    assert result.passed


def test_all_checks_have_mitre_ids():
    for check_cls in [GitlabTokensCheck, SlackTokensCheck, NpmTokensCheck,
                       AzureDevopsCheck, DockerCredsCheck, StripeKeysCheck,
                       TwilioKeysCheck, PasswordInCodeCheck]:
        check = check_cls()
        result = check.evaluate(make_collector(check.depends[0].replace("secrets", "").strip() or "stripe_keys"
                                                if hasattr(check, 'depends') and check.depends
                                                else "stripe_keys",
                                                path="/tmp/test"))
        if not result.findings and isinstance(check, PasswordInCodeCheck):
            result = check.evaluate({
                "secrets": {
                    "stripe_keys": [{"path": "/tmp/test", "line": 1, "match": "sk_live_test"}],
                },
            })
        elif not result.findings:
            # For the specific checks, use their own collector key
            cat_map = {
                GitlabTokensCheck: "gitlab_tokens",
                SlackTokensCheck: "slack_tokens",
                NpmTokensCheck: "npm_tokens",
                AzureDevopsCheck: "azure_devops",
                DockerCredsCheck: "docker_creds",
                StripeKeysCheck: "stripe_keys",
                TwilioKeysCheck: "twilio_keys",
            }
            key = cat_map.get(check_cls, "stripe_keys")
            result = check.evaluate({"secrets": {key: [{"path": "/tmp/test", "line": 1, "match": "token"}]}})
        assert len(result.findings) > 0, f"No findings for {check_cls.__name__}"
        assert len(result.findings[0].mitre_attack_ids) > 0
