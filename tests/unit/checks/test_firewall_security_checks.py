from __future__ import annotations

from usaf.checks.security.firewall_security_checks import (
    CompetingFirewallsCheck,
    FirewallBootPersistenceCheck,
    FirewallDefaultPolicyCheck,
    FirewallIPv6Check,
    FirewallLoggingCheck,
    FirewallMinimalRulesCheck,
    FirewallOutgoingPolicyCheck,
    FirewallRateLimitCheck,
)


def _fw(ufw=None, nft=None, ipt=None) -> dict:
    return {
        "firewall": {
            "ufw": ufw or {"installed": False, "active": False},
            "nftables": nft or {"installed": False, "active": False},
            "iptables": ipt or {"installed": False, "active": False},
        }
    }


class TestFirewallDefaultPolicyCheck:
    def test_passes_when_deny(self):
        check = FirewallDefaultPolicyCheck()
        result = check.evaluate(_fw(ufw={"installed": True, "default_policy": "deny (incoming), allow (outgoing)"}))
        assert result.passed

    def test_fails_when_allow(self):
        check = FirewallDefaultPolicyCheck()
        result = check.evaluate(_fw(ufw={"installed": True, "default_policy": "allow (incoming), allow (outgoing)"}))
        assert not result.passed
        assert len(result.findings) >= 1

    def test_skips_when_not_installed(self):
        check = FirewallDefaultPolicyCheck()
        result = check.evaluate(_fw(ufw={"installed": False}))
        assert result.passed


class TestFirewallMinimalRulesCheck:
    def test_passes_with_substance(self):
        check = FirewallMinimalRulesCheck()
        result = check.evaluate(_fw(
            nft={"active": True, "rulesets": ["table", "chain", "rule1", "rule2", "rule3"]},
        ))
        assert result.passed

    def test_fails_with_few_rules(self):
        check = FirewallMinimalRulesCheck()
        result = check.evaluate(_fw(
            nft={"active": True, "rulesets": ["table", "chain"]},
        ))
        assert not result.passed
        assert len(result.findings) == 1

    def test_skips_when_inactive(self):
        check = FirewallMinimalRulesCheck()
        result = check.evaluate(_fw())
        assert result.passed


class TestFirewallIPv6Check:
    def test_passes_with_ip6_nft(self):
        check = FirewallIPv6Check()
        result = check.evaluate(_fw(
            nft={"active": True, "rulesets": ["table ip6 filter", "chain input", "rule"]},
        ))
        assert result.passed

    def test_fails_without_ip6_nft(self):
        check = FirewallIPv6Check()
        result = check.evaluate(_fw(
            nft={"active": True, "rulesets": ["table ip filter", "chain input"]},
        ))
        assert not result.passed

    def test_skips_when_inactive(self):
        check = FirewallIPv6Check()
        result = check.evaluate(_fw())
        assert result.passed


class TestCompetingFirewallsCheck:
    def test_passes_with_one(self):
        check = CompetingFirewallsCheck()
        result = check.evaluate(_fw(ufw={"installed": True, "active": True}))
        assert result.passed

    def test_fails_with_two(self):
        check = CompetingFirewallsCheck()
        result = check.evaluate(_fw(
            ufw={"installed": True, "active": True},
            nft={"installed": True, "active": True},
        ))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_three(self):
        check = CompetingFirewallsCheck()
        result = check.evaluate(_fw(
            ufw={"installed": True, "active": True},
            nft={"installed": True, "active": True},
            ipt={"installed": True, "active": True},
        ))
        assert not result.passed


class TestFirewallOutgoingPolicyCheck:
    def test_passes_when_no_ufw(self):
        check = FirewallOutgoingPolicyCheck()
        result = check.evaluate(_fw())
        assert result.passed

    def test_fails_when_allow_outgoing(self):
        check = FirewallOutgoingPolicyCheck()
        result = check.evaluate(_fw(ufw={"installed": True, "default_policy": "deny (incoming), allow (outgoing)"}))
        assert not result.passed

    def test_skips_when_not_installed(self):
        check = FirewallOutgoingPolicyCheck()
        result = check.evaluate(_fw(ufw={"installed": False}))
        assert result.passed


class TestFirewallLoggingCheck:
    def test_passes_when_logging_on(self):
        check = FirewallLoggingCheck()
        result = check.evaluate(_fw(ufw={"active": True, "raw": "Logging: on\nStatus: active"}))
        assert result.passed

    def test_fails_when_logging_off(self):
        check = FirewallLoggingCheck()
        result = check.evaluate(_fw(ufw={"active": True, "raw": "Logging: off\nStatus: active"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_skips_when_inactive(self):
        check = FirewallLoggingCheck()
        result = check.evaluate(_fw(ufw={"active": False}))
        assert result.passed


class TestFirewallRateLimitCheck:
    def test_passes_when_ssh_limited(self):
        check = FirewallRateLimitCheck()
        result = check.evaluate(_fw(ufw={"active": True, "raw": "22/tcp LIMIT IN\n80/tcp ALLOW IN"}))
        assert result.passed

    def test_fails_when_ssh_unlimited(self):
        check = FirewallRateLimitCheck()
        result = check.evaluate(_fw(ufw={"active": True, "raw": "22/tcp ALLOW IN\n80/tcp ALLOW IN"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_skips_when_no_ssh_rule(self):
        check = FirewallRateLimitCheck()
        result = check.evaluate(_fw(ufw={"active": True, "raw": "80/tcp ALLOW IN"}))
        assert result.passed


class TestFirewallBootPersistenceCheck:
    def test_skips_when_no_active_fw(self):
        check = FirewallBootPersistenceCheck()
        result = check.evaluate(_fw())
        assert result.passed

    def test_finds_nft_persistence_issue(self):
        check = FirewallBootPersistenceCheck()
        result = check.evaluate(_fw(nft={"active": True, "rulesets": ["table", "chain"]}))
        assert not result.passed
        assert len(result.findings) >= 1

    def test_finds_ipt_persistence_issue(self):
        check = FirewallBootPersistenceCheck()
        result = check.evaluate(_fw(ipt={"active": True, "rules": ["rule1"]}))
        assert not result.passed
        assert len(result.findings) >= 1
