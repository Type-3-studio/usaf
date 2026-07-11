from __future__ import annotations

from usaf.models.evidence import Evidence
from usaf.models.finding import Finding
from usaf.models.severity import Confidence


class TrustScorer:
    """Computes trust-adjusted confidence for findings based on evidence quality.

    Builds on P1-1's confidence*FP model with evidence quality bonuses:
    - File/Process/User evidence present  → +0.15 to effective confidence
    - Network/Package/Registry evidence   → +0.10
    - Command evidence                    → +0.05
    - Multiple evidence types present     → +0.10 extra
    - No evidence                         → clamp to LOW max

    This incentivizes check authors to include evidence and automatically
    penalizes findings that lack supporting data.
    """

    EVIDENCE_QUALITY_BONUS: dict[str, float] = {
        "FileEvidence": 0.15,
        "ProcessEvidence": 0.15,
        "UserEvidence": 0.15,
        "NetworkEvidence": 0.10,
        "PackageEvidence": 0.10,
        "RegistryEvidence": 0.10,
        "LogEvidence": 0.08,
        "CommandEvidence": 0.05,
    }

    MULTIPLE_EVIDENCE_TYPES_BONUS = 0.10
    NO_EVIDENCE_PENALTY = 0.0
    NO_EVIDENCE_MAX_EFFECTIVE = 0.3  # Clamp to LOW if no evidence

    def score(self, finding: Finding) -> tuple[Confidence, float]:
        """Compute trust-adjusted confidence for a single finding.

        Returns:
            Tuple of (adjusted Confidence, effective multiplier as float 0-1)
        """
        base = finding.confidence.multiplier

        if finding.evidence is None:
            effective = min(self.NO_EVIDENCE_MAX_EFFECTIVE, base * 0.5)
            return Confidence.LOW, round(effective, 2)

        evidence_bonus = self._compute_evidence_quality(finding.evidence)
        fp_factor = 1.0 - finding.false_positive_probability
        effective = min(1.0, (base + evidence_bonus) * fp_factor)

        confidence = self._effective_to_confidence(effective)
        return confidence, round(effective, 2)

    def score_many(
        self, findings: list[Finding]
    ) -> dict[str, tuple[Confidence, float]]:
        """Score multiple findings at once.

        Returns dict of finding_id -> (Confidence, effective_score).
        """
        return {f.id: self.score(f) for f in findings}

    def apply_finding(self, finding: Finding) -> Finding:
        """Mutate a finding's confidence in-place using trust scoring."""
        confidence, _ = self.score(finding)
        finding.confidence = confidence
        return finding

    def apply_all(self, findings: list[Finding]) -> list[Finding]:
        """Apply trust scoring to all findings in a list."""
        return [self.apply_finding(f) for f in findings]

    @classmethod
    def _compute_evidence_quality(cls, evidence: Evidence) -> float:
        ev_type = type(evidence).__name__
        bonus = cls.EVIDENCE_QUALITY_BONUS.get(ev_type, 0.0)

        # Count distinct evidence types present (multi-evidence bonus)
        # Since we have a single evidence object, this checks richness
        fields_present = sum(
            1 for v in evidence.model_dump().values() if v is not None
        )
        if fields_present >= 5:
            bonus += 0.05

        return bonus

    @staticmethod
    def _effective_to_confidence(effective: float) -> Confidence:
        if effective >= 0.8:
            return Confidence.HIGH
        if effective >= 0.5:
            return Confidence.MEDIUM
        return Confidence.LOW


def adjust_finding_trust(finding: Finding) -> Finding:
    """Convenience function to adjust a single finding's trust."""
    return TrustScorer().apply_finding(finding)


def adjust_all_trust(findings: list[Finding]) -> list[Finding]:
    """Convenience function to adjust all findings' trust."""
    return TrustScorer().apply_all(findings)
