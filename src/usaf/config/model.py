from __future__ import annotations

from pydantic import BaseModel, Field

from usaf.models.severity import Severity


class SeverityConfig(BaseModel):
    CRITICAL: float = 10.0
    HIGH: float = 7.5
    MEDIUM: float = 5.0
    LOW: float = 2.5
    INFO: float = 0.0


class PluginOverride(BaseModel):
    severity: Severity | None = None
    enabled: bool | None = None
    timeout: int | None = None
    max_findings: int | None = None


class PluginConfig(BaseModel):
    enabled: list[str] = Field(default_factory=lambda: ["*"])
    disabled: list[str] = Field(default_factory=list)
    overrides: dict[str, PluginOverride] = Field(default_factory=dict)


class GeneralConfig(BaseModel):
    scan_name: str = "usaf-scan"
    parallel: bool = True
    max_workers: int = 8
    timeout: int = 300
    cache: bool = True
    cache_dir: str = "~/.cache/usaf"
    offline: bool = False


class BaselineConfig(BaseModel):
    path: str | None = None
    compare: bool = True
    fail_on_drift: bool = False
    auto_baseline: bool = False


class ReportingConfig(BaseModel):
    format: str = "terminal"
    verbose: bool = False
    output: str | None = None
    sections: list[str] = Field(default_factory=lambda: ["summary", "findings", "remediation"])
    color: bool = True
    show_passed: bool = False


class PolicyConfig(BaseModel):
    name: str = ""
    path: str = ""


class CorrelationConfig(BaseModel):
    enabled: bool = True
    rules: list[str] = Field(default_factory=lambda: ["*"])


class SeverityContextConfig(BaseModel):
    enabled: bool = True
    rules: dict[str, dict[str, str]] = Field(default_factory=dict)


class ComplianceConfig(BaseModel):
    enabled: bool = False
    frameworks: list[str] = Field(default_factory=lambda: ["cis"])


class ProfileConfig(BaseModel):
    name: str | None = None
    auto_detect: bool = True
    path: str | None = None


class USAFConfig(BaseModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    plugins: PluginConfig = Field(default_factory=PluginConfig)
    severity: SeverityConfig = Field(default_factory=SeverityConfig)
    ignore: list[str] = Field(default_factory=list)
    ignore_paths: list[str] = Field(
        default_factory=list, description="Glob patterns for paths to ignore (e.g., /var/log/**)"
    )
    baseline: BaselineConfig = Field(default_factory=BaselineConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    policies: list[PolicyConfig] = Field(default_factory=list)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)
    severity_context: SeverityContextConfig = Field(default_factory=SeverityContextConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    profile: ProfileConfig = Field(default_factory=ProfileConfig)
    suid_allowlist: list[str] = Field(
        default_factory=list, description="Additional SUID binary paths to consider expected"
    )
