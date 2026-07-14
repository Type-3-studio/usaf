from __future__ import annotations

import pytest

from usaf.config.model import USAFConfig
from usaf.core.exceptions import PolicyError
from usaf.policies.engine import Policy, PolicyEngine


class TestPolicyModel:
    def test_defaults(self):
        policy = Policy(name="test")
        assert policy.name == "test"
        assert policy.description == ""
        assert policy.check_overrides == {}
        assert policy.ignore_patterns == []
        assert policy.severity_overrides == {}

    def test_full_policy(self):
        policy = Policy(
            name="hardened",
            description="Hardened server policy",
            check_overrides={"SSH-101": {"enabled": True}},
            ignore_patterns=["/tmp/*"],
            severity_overrides={"SSH-101": "CRITICAL"},
        )
        assert policy.name == "hardened"
        assert policy.check_overrides["SSH-101"]["enabled"] is True
        assert policy.ignore_patterns == ["/tmp/*"]
        assert policy.severity_overrides["SSH-101"] == "CRITICAL"


class TestPolicyEngine:
    def test_load_valid_yaml(self, tmp_path):
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("name: test-policy\ndescription: Test\n")
        engine = PolicyEngine()
        policy = engine.load(str(policy_file))
        assert policy.name == "test-policy"
        assert policy.description == "Test"

    def test_load_nonexistent(self):
        engine = PolicyEngine()
        with pytest.raises(PolicyError, match="not found"):
            engine.load("/nonexistent/policy.yaml")

    def test_load_invalid_yaml(self, tmp_path):
        policy_file = tmp_path / "bad.yaml"
        policy_file.write_text("{invalid: yaml:\n  broken")
        engine = PolicyEngine()
        with pytest.raises(PolicyError, match="Invalid YAML"):
            engine.load(str(policy_file))

    def test_load_all_from_directory(self, tmp_path):
        (tmp_path / "policy1.yaml").write_text("name: policy1\n")
        (tmp_path / "policy2.yaml").write_text("name: policy2\n")
        (tmp_path / "not-a-policy.txt").write_text("ignore me\n")

        engine = PolicyEngine()
        policies = engine.load_all(str(tmp_path))
        assert len(policies) == 2
        names = {p.name for p in policies}
        assert names == {"policy1", "policy2"}

    def test_load_all_nonexistent_dir(self):
        engine = PolicyEngine()
        with pytest.raises(PolicyError, match="not found"):
            engine.load_all("/nonexistent/policies/")

    def test_get_override(self):
        policy = Policy(
            name="test",
            check_overrides={"SSH-101": {"severity": "LOW"}},
        )
        assert PolicyEngine.get_override(policy, "SSH-101", "severity") == "LOW"
        assert PolicyEngine.get_override(policy, "SSH-101", "nonexistent") is None
        assert PolicyEngine.get_override(policy, "UNKNOWN", "severity") is None

    def test_apply_to_config_severity_overrides(self):
        policy = Policy(
            name="test",
            severity_overrides={"SSH-101": "CRITICAL"},
        )
        config = USAFConfig()
        PolicyEngine.apply_to_config(policy, config)
        assert config.plugins.overrides["SSH-101"].severity == "CRITICAL"

    def test_apply_to_config_ignore_patterns(self):
        policy = Policy(
            name="test",
            ignore_patterns=["/tmp/*", "/var/tmp/*"],
        )
        config = USAFConfig()
        PolicyEngine.apply_to_config(policy, config)
        assert "/tmp/*" in (config.ignore or [])

    def test_validate_valid(self):
        policy = Policy(name="valid")
        errors = PolicyEngine.validate(policy)
        assert errors == []

    def test_validate_empty_name(self):
        policy = Policy(name="")
        errors = PolicyEngine.validate(policy)
        assert "name is required" in errors[0].lower()

    def test_validate_invalid_severity(self):
        policy = Policy(
            name="test",
            severity_overrides={"SSH-101": "INVALID"},
        )
        errors = PolicyEngine.validate(policy)
        assert len(errors) == 1
        assert "INVALID" in errors[0]

    def test_validate_valid_severity_overrides(self):
        policy = Policy(
            name="test",
            severity_overrides={"SSH-101": "HIGH", "KERN-101": "MEDIUM"},
        )
        errors = PolicyEngine.validate(policy)
        assert errors == []

    def test_model_dump_includes_all(self):
        policy = Policy(name="test")
        data = policy.model_dump()
        assert data["name"] == "test"

    def test_load_all_skips_invalid(self, tmp_path):
        (tmp_path / "good.yaml").write_text("name: good-policy\n")
        (tmp_path / "bad.yaml").write_text("{invalid: yaml: broken")
        engine = PolicyEngine()
        policies = engine.load_all(str(tmp_path))
        assert len(policies) == 1
        assert policies[0].name == "good-policy"

    def test_apply_to_config_no_plugins_attr(self):
        class FakeConfig:
            severity_overrides = {}

        policy = Policy(
            name="test",
            severity_overrides={"SSH-101": "CRITICAL"},
        )
        config = FakeConfig()
        result = PolicyEngine.apply_to_config(policy, config)
        assert result.severity_overrides["SSH-101"] == "CRITICAL"

    def test_get_override_nonexistent_check_id(self):
        policy = Policy(name="test")
        assert PolicyEngine.get_override(policy, "NONEXISTENT", "severity") is None

    def test_get_override_nonexistent_key(self):
        policy = Policy(
            name="test",
            check_overrides={"SSH-101": {"enabled": True}},
        )
        assert PolicyEngine.get_override(policy, "SSH-101", "severity") is None
