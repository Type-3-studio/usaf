from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from usaf.core.exceptions import PolicyError


class Policy(BaseModel):
    name: str
    description: str = ""
    check_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)
    ignore_patterns: list[str] = Field(default_factory=list)
    severity_overrides: dict[str, str] = Field(default_factory=dict)

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class PolicyEngine:
    def load(self, path: str) -> Policy:
        path_obj = Path(path)
        if not path_obj.exists():
            raise PolicyError(f"Policy file not found: {path}")
        try:
            data = yaml.safe_load(path_obj.read_text())
            return Policy(**data)
        except yaml.YAMLError as e:
            raise PolicyError(f"Invalid YAML in policy {path}: {e}") from e

    def load_all(self, directory: str) -> list[Policy]:
        dir_path = Path(directory)
        if not dir_path.is_dir():
            raise PolicyError(f"Policy directory not found: {directory}")
        policies: list[Policy] = []
        for entry in sorted(dir_path.iterdir()):
            if entry.suffix in (".yaml", ".yml"):
                try:
                    policies.append(self.load(str(entry)))
                except PolicyError:
                    pass
        return policies

    @staticmethod
    def get_override(policy: Policy, check_id: str, key: str) -> Any:
        overrides = policy.check_overrides.get(check_id)
        if overrides is None:
            return None
        return overrides.get(key)

    @staticmethod
    def apply_to_config(policy: Policy, config: Any) -> Any:
        if policy.severity_overrides:
            if hasattr(config, "severity_overrides"):
                config.severity_overrides.update(policy.severity_overrides)
            elif hasattr(config, "plugins") and hasattr(config.plugins, "overrides"):
                for check_id, severity in policy.severity_overrides.items():
                    if check_id not in config.plugins.overrides:
                        from usaf.config.model import PluginOverride
                        config.plugins.overrides[check_id] = PluginOverride(
                            severity=severity, enabled=None
                        )
        if policy.ignore_patterns:
            if hasattr(config, "ignore"):
                existing = list(config.ignore) if config.ignore else []
                config.ignore = existing + [
                    p for p in policy.ignore_patterns if p not in existing
                ]
        return config

    @staticmethod
    def validate(policy: Policy) -> list[str]:
        errors: list[str] = []
        if not policy.name:
            errors.append("Policy name is required")
        if policy.severity_overrides:
            valid_severities = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
            for check_id, severity in policy.severity_overrides.items():
                if severity.upper() not in valid_severities:
                    errors.append(
                        f"Invalid severity '{severity}' for check '{check_id}': "
                        f"must be one of {', '.join(sorted(valid_severities))}"
                    )
        return errors
