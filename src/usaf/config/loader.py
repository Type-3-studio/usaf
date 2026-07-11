from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from usaf.config.defaults import DEFAULT_CONFIG_YAML
from usaf.config.model import USAFConfig
from usaf.core.exceptions import ConfigurationError


def find_config_files() -> list[Path]:
    """Find configuration files in standard locations, in priority order."""
    paths: list[Path] = []

    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        paths.append(Path(xdg_config) / "usaf" / "config.yaml")
    else:
        paths.append(Path.home() / ".config" / "usaf" / "config.yaml")

    paths.append(Path.home() / ".usaf.yaml")
    paths.append(Path.cwd() / "usaf.yaml")
    paths.append(Path.cwd() / ".usaf.yaml")
    paths.append(Path.cwd() / "usaf.yml")
    paths.append(Path.cwd() / ".usaf.yml")

    return [p for p in paths if p.exists()]


def load_config(path: str | Path | None = None) -> USAFConfig:
    """Load configuration from file, merging defaults and overrides."""
    config_data: dict[str, Any] = yaml.safe_load(DEFAULT_CONFIG_YAML) or {}

    if path:
        file_paths = [Path(path)]
    else:
        file_paths = find_config_files()

    for config_path in file_paths:
        try:
            with open(config_path) as f:
                overrides = yaml.safe_load(f) or {}
            _deep_merge(config_data, overrides)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in {config_path}: {e}") from e
        except OSError as e:
            raise ConfigurationError(f"Cannot read {config_path}: {e}") from e

    return USAFConfig(**config_data)


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> None:
    """Deep merge overrides into base dict (mutates base)."""
    for key, value in overrides.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
