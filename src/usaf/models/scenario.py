from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from usaf.models.severity import Severity


class KillChainPhase(StrEnum):
    """MITRE ATT&CK kill chain phases mapped from findings."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class AttackScenario(BaseModel):
    """A pre-built attack scenario grouping related correlation rules.

    Scenarios represent real-world attack patterns (ransomware,
    cryptominer, persistence, etc.) and are scored as a unit.
    """

    id: str = Field(description="Scenario identifier (e.g., SCEN-RANSOM)")
    name: str = Field(description="Human-readable scenario name")
    description: str = Field(description="What this scenario detects")
    severity: Severity = Field(default=Severity.HIGH, description="Base scenario severity")
    rule_ids: list[str] = Field(
        description="Correlation rule IDs that contribute to this scenario"
    )
    kill_chain_phases: list[KillChainPhase] = Field(
        default_factory=list,
        description="Kill chain phases this scenario covers",
    )
    min_rules_triggered: int = Field(
        default=1,
        ge=1,
        description="Minimum rules that must trigger for scenario to fire",
    )
    tags: list[str] = Field(default_factory=list)
    mitre_attack_ids: list[str] = Field(default_factory=list)


class ScenarioResult(BaseModel):
    """Evaluation result for a single attack scenario."""

    scenario_id: str
    scenario_name: str
    triggered: bool
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    rules_triggered: int = Field(default=0)
    total_rules: int = Field(default=0)
    severity: Severity = Field(default=Severity.MEDIUM)
    source_finding_ids: list[str] = Field(default_factory=list)
    kill_chain_phases: list[KillChainPhase] = Field(default_factory=list)
    description: str = ""

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class CounterEvidence(BaseModel):
    """Known-good entries that reduce confidence in correlation findings."""

    package_names: list[str] = Field(
        default_factory=list,
        description="Known-safe package names that reduce suspicion",
    )
    binary_paths: list[str] = Field(
        default_factory=list,
        description="Known-safe binary paths",
    )
    service_names: list[str] = Field(
        default_factory=list,
        description="Known-safe service names",
    )
    user_names: list[str] = Field(
        default_factory=list,
        description="Known-safe usernames",
    )
    file_paths: list[str] = Field(
        default_factory=list,
        description="Known-safe file path patterns (fnmatch)",
    )

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)
