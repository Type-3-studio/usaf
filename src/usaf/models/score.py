from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from usaf.models.severity import CheckCategory, Severity


class CategoryScore(BaseModel):
    category: CheckCategory
    score: float = Field(ge=0.0, le=10.0)
    finding_count: int = Field(default=0)
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    info_count: int = Field(default=0)
    max_severity: Severity | None = None
    weight: float = Field(default=1.0)

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class ScanScore(BaseModel):
    overall_score: float = Field(
        ge=0.0, le=10.0, description="Overall security posture score (0=perfect, 10=worst)"
    )
    overall_grade: str = Field(default="A+", description="Letter grade")
    categories: list[CategoryScore] = Field(default_factory=list)
    total_findings: int = Field(default=0)
    critical_count: int = Field(default=0)
    high_count: int = Field(default=0)
    medium_count: int = Field(default=0)
    low_count: int = Field(default=0)
    info_count: int = Field(default=0)

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)
