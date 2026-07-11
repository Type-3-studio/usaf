from __future__ import annotations

from typing import Any

from usaf.core.interfaces import ReporterInterface
from usaf.models.result import ScanResult
from usaf.models.score import ScanScore


class BaseReporter(ReporterInterface):
    """Base class for all reporters."""

    name: str = ""
    description: str = ""

    def generate(self, result: ScanResult, score: ScanScore | None = None, **kwargs: Any) -> str:
        raise NotImplementedError

    def write(self, content: str, path: str) -> None:
        with open(path, "w") as f:
            f.write(content)
