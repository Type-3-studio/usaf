from __future__ import annotations

import importlib
import pkgutil
from contextlib import suppress
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from test_lab.scenarios.base import BaseScenario


class ScenarioRegistry:
    _scenarios: dict[str, type[BaseScenario]] = {}

    @classmethod
    def register(cls, scenario_cls: type[BaseScenario]) -> type[BaseScenario]:
        key = scenario_cls.name.replace("_", "-")
        cls._scenarios[key] = scenario_cls
        return scenario_cls

    @classmethod
    def get(cls, name: str) -> type[BaseScenario]:
        key = name.replace("_", "-")
        if key not in cls._scenarios:
            msg = f"Scenario '{name}' not found. Available: {', '.join(cls.list_names())}"
            raise KeyError(msg)
        return cls._scenarios[key]

    @classmethod
    def list_names(cls) -> list[str]:
        return sorted(cls._scenarios.keys())

    @classmethod
    def list_details(cls) -> list[dict[str, str]]:
        return [
            {"name": name, "description": cls.description}
            for name, cls in sorted(cls._scenarios.items())
        ]

    @classmethod
    def discover(cls) -> None:
        import test_lab.scenarios as scenarios_pkg

        for _importer, modname, ispkg in pkgutil.iter_modules(
            scenarios_pkg.__path__
        ):
            if ispkg and modname not in ("__init__",):
                full_module = f"test_lab.scenarios.{modname}.scenario"
                with suppress(ModuleNotFoundError):
                    importlib.import_module(full_module)
