from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from usaf.models.evidence import Evidence
from usaf.models.severity import CheckCategory, Confidence, Severity


class Finding(BaseModel):
    id: str = Field(description="Unique finding identifier (e.g., SSH-001-001)")
    check_id: str = Field(description="Parent check plugin ID")
    category: CheckCategory = Field(description="Finding category")
    severity: Severity = Field(description="Severity level")
    risk_score: float = Field(ge=0.0, le=10.0, description="Computed risk score")
    title: str = Field(description="Short human-readable title")
    description: str = Field(description="What was found")
    rationale: str = Field(description="Why this matters from a security perspective")
    evidence: Evidence | None = Field(default=None, description="Supporting evidence")
    detected_value: str | None = Field(default=None, description="Actual value detected")
    expected_value: str | None = Field(default=None, description="Expected/correct value")
    affected_component: str | None = Field(
        default=None, description="Affected file, process, socket, etc."
    )
    remediation: str = Field(description="How to fix this finding")
    reference: str | None = Field(
        default=None, description="URL or document reference for more information"
    )
    confidence: Confidence = Field(
        default=Confidence.HIGH, description="Confidence in this finding"
    )
    false_positive_probability: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Estimated false positive probability"
    )
    source: str = Field(description="Plugin class name that generated this finding")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="When this finding was created"
    )
    cve_ids: list[str] = Field(default_factory=list, description="Related CVE identifiers")
    cis_benchmarks: list[str] = Field(default_factory=list, description="CIS Benchmark mappings")
    mitre_attack_ids: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs"
    )
    owasp_ids: list[str] = Field(default_factory=list, description="OWASP mappings")
    tags: list[str] = Field(default_factory=list, description="Arbitrary tags for filtering")

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)
