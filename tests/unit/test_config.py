from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from usaf.config.defaults import DEFAULT_CONFIG_YAML
from usaf.config.loader import _deep_merge, find_config_files, load_config
from usaf.config.model import USAFConfig
from usaf.core.exceptions import ConfigurationError


class TestUSAFConfigModel:
    def test_default_config(self):
        config = USAFConfig()
        assert config.general.scan_name == "usaf-scan"
        assert config.general.parallel is True
        assert config.general.max_workers == 8
        assert config.plugins.enabled == ["*"]
        assert config.plugins.disabled == []
        assert config.severity.CRITICAL == 10.0
        assert config.severity.HIGH == 7.5
        assert config.baseline.compare is False
        assert config.reporting.format == "terminal"
        assert config.reporting.color is True
        assert config.suid_allowlist == []

    def test_suid_allowlist_default(self):
        config = USAFConfig()
        assert config.suid_allowlist == []

    def test_custom_suid_allowlist(self):
        config = USAFConfig(suid_allowlist=["/opt/custom/suid"])
        assert config.suid_allowlist == ["/opt/custom/suid"]

    def test_plugin_override(self):
        config = USAFConfig(
            plugins={
                "enabled": ["*"],
                "disabled": ["SSH-101"],
                "overrides": {
                    "KERN-101": {"severity": "LOW", "enabled": False},
                },
            }
        )
        assert "SSH-101" in config.plugins.disabled
        assert config.plugins.overrides["KERN-101"].severity == "LOW"
        assert config.plugins.overrides["KERN-101"].enabled is False

    def test_reporting_config(self):
        config = USAFConfig(reporting={"format": "json", "verbose": True, "output": "/tmp/report.json"})
        assert config.reporting.format == "json"
        assert config.reporting.verbose is True
        assert config.reporting.output == "/tmp/report.json"

    def test_compliance_config(self):
        config = USAFConfig(compliance={"enabled": True, "frameworks": ["cis", "nist"]})
        assert config.compliance.enabled is True
        assert config.compliance.frameworks == ["cis", "nist"]

    def test_ignore_list(self):
        config = USAFConfig(ignore=["/tmp/*", "/var/log/*"])
        assert len(config.ignore) == 2


class TestDefaultConfigYAML:
    def test_valid_yaml(self):
        data = yaml.safe_load(DEFAULT_CONFIG_YAML)
        assert data is not None
        assert "general" in data
        assert "plugins" in data
        assert "severity" in data

    def test_parse_to_model(self):
        data = yaml.safe_load(DEFAULT_CONFIG_YAML)
        config = USAFConfig(**data)
        assert config.general.scan_name == "usaf-scan"


class TestDeepMerge:
    def test_simple_override(self):
        base = {"a": 1, "b": 2}
        _deep_merge(base, {"b": 3})
        assert base == {"a": 1, "b": 3}

    def test_nested_merge(self):
        base = {"a": {"x": 1, "y": 2}, "b": 3}
        _deep_merge(base, {"a": {"y": 99, "z": 100}})
        assert base == {"a": {"x": 1, "y": 99, "z": 100}, "b": 3}

    def test_new_key_added(self):
        base = {"a": 1}
        _deep_merge(base, {"b": 2})
        assert base == {"a": 1, "b": 2}

    def test_non_dict_override(self):
        base = {"a": {"nested": "dict"}}
        _deep_merge(base, {"a": "string"})
        assert base == {"a": "string"}


class TestFindConfigFiles:
    def test_returns_empty_when_no_files(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        files = find_config_files()
        assert files == []

    def test_finds_cwd_config(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / "usaf.yaml"
        config_file.write_text("general:\n  scan_name: test\n")
        files = find_config_files()
        assert config_file in files


class TestLoadConfig:
    def test_loads_defaults_when_no_file(self, monkeypatch):
        monkeypatch.setattr("usaf.config.loader.find_config_files", lambda: [])
        config = load_config()
        assert config.general.scan_name == "usaf-scan"

    def test_loads_from_path(self, tmp_path):
        config_file = tmp_path / "test-config.yaml"
        config_file.write_text("general:\n  scan_name: my-custom-scan\n")
        config = load_config(str(config_file))
        assert config.general.scan_name == "my-custom-scan"

    def test_merges_with_defaults(self, tmp_path):
        config_file = tmp_path / "test-config.yaml"
        config_file.write_text("general:\n  scan_name: custom\n")
        config = load_config(str(config_file))
        assert config.general.scan_name == "custom"
        assert config.general.max_workers == 8

    def test_raises_on_invalid_yaml(self, tmp_path):
        config_file = tmp_path / "bad.yaml"
        config_file.write_text("{invalid: yaml: stuff\n  broken")
        with pytest.raises(ConfigurationError):
            load_config(str(config_file))

    def test_raises_on_os_error(self, tmp_path):
        config_file = tmp_path / "nonexistent_dir" / "config.yaml"
        with pytest.raises(ConfigurationError, match="Cannot read"):
            load_config(str(config_file))

    def test_loads_from_yaml_specifying_path(self, tmp_path, monkeypatch):
        monkeypatch.setattr("usaf.config.loader.find_config_files", lambda: [])
        config_file = tmp_path / "cfg.yaml"
        config_file.write_text("general:\n  scan_name: explicit\n")
        config = load_config(str(config_file))
        assert config.general.scan_name == "explicit"


class TestFindConfigFiles:
    def test_finds_xdg_config(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "home", lambda: Path("/nonexistent"))
        monkeypatch.setenv("XDG_CONFIG_HOME", "/custom/config")
        files = find_config_files()
        assert any("/custom/config/usaf/config.yaml" in str(f) for f in files)
