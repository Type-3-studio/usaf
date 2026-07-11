from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class CVEReference(BaseModel):
    id: str
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    url: str | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class CISBenchmark(BaseModel):
    id: str
    title: str | None = None
    description: str | None = None
    level: str | None = None  # Level 1, Level 2

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class MITREAttack(BaseModel):
    technique_id: str
    technique_name: str | None = None
    tactic: str | None = None
    url: str | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class OWASPMapping(BaseModel):
    id: str
    name: str | None = None
    category: str | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)
