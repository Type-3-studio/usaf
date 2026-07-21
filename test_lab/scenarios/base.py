from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from test_lab.scenarios.registry import ScenarioRegistry


@dataclass
class ExpectedFinding:
    check_id: str
    finding_id: str | None = None
    title_contains: str | None = None
    severity: str | None = None
    count_min: int = 1
    count_max: int | None = None
    tags: list[str] = field(default_factory=list)


@dataclass
class ExpectedFindings:
    scenario: str
    description: str
    expected_findings: list[ExpectedFinding]
    minimum_detection_rate: float = 0.9
    notes: str | None = None


class BaseScenario(ABC):
    name: str = ""
    description: str = ""
    vm_memory: int = 2048
    vm_cpus: int = 2

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.name:
            ScenarioRegistry.register(cls)

    @property
    @abstractmethod
    def expected_findings(self) -> ExpectedFindings:
        ...

    @property
    def scenario_dir(self) -> Path:
        import test_lab.scenarios as pkg

        return Path(pkg.__file__).resolve().parent / self.name.replace("-", "_")

    @property
    def provision_script(self) -> Path:
        return self.scenario_dir / "provision.sh"

    @property
    def expected_yaml(self) -> Path:
        return self.scenario_dir / "expected.yaml"
