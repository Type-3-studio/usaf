from __future__ import annotations

from usaf.core.interfaces import ScoringEngineInterface
from usaf.models.finding import Finding
from usaf.models.result import ScanResult
from usaf.models.score import CategoryScore, ScanScore
from usaf.models.severity import CheckCategory, Severity


class ScoringEngine(ScoringEngineInterface):
    """Weighted scoring engine that computes overall and category-level security scores.

    Score philosophy:
      - 0.0 = perfect (no findings)
      - 10.0 = worst possible security posture
      - Score is driven by severity, confidence, false-positive probability,
        and finding count — each finding contributes proportionally to its trustworthiness
    """

    # Severity weights: critical findings penalise more per-unit than low
    SEVERITY_WEIGHTS: dict[Severity, float] = {
        Severity.CRITICAL: 1.0,
        Severity.HIGH: 0.8,
        Severity.MEDIUM: 0.6,
        Severity.LOW: 0.3,
        Severity.INFO: 0.0,
    }

    # Category weights: compromise and critical infrastructure weighted higher
    CATEGORY_WEIGHTS: dict[CheckCategory, float] = {
        CheckCategory.COMPROMISE: 3.0,
        CheckCategory.COMPLIANCE: 1.5,
        CheckCategory.KERNEL: 1.5,
        CheckCategory.AUTHENTICATION: 1.5,
        CheckCategory.USERS: 1.2,
        CheckCategory.PERMISSIONS: 1.2,
        CheckCategory.NETWORK: 1.2,
        CheckCategory.PERSISTENCE: 2.0,
        CheckCategory.PROCESSES: 1.0,
        CheckCategory.SECURITY: 1.0,
        CheckCategory.BOOT: 1.0,
        CheckCategory.FILESYSTEM: 1.0,
        CheckCategory.SERVICES: 0.8,
        CheckCategory.PACKAGES: 0.8,
        CheckCategory.SYSTEM: 0.8,
        CheckCategory.CONTAINERS: 1.0,
        CheckCategory.CRYPTOGRAPHY: 1.2,
        CheckCategory.AUDIT: 1.0,
        CheckCategory.FORENSICS: 1.0,
        CheckCategory.GENERAL: 0.5,
    }

    def calculate(self, result: ScanResult) -> ScanScore:
        all_findings = result.findings

        if not all_findings:
            return ScanScore(
                overall_score=0.0,
                overall_grade="A+",
                categories=[],
                total_findings=0,
            )

        categories = self._calculate_categories(all_findings)
        overall = self._calculate_overall(categories)

        return ScanScore(
            overall_score=overall,
            overall_grade=self._score_to_grade(overall),
            categories=categories,
            total_findings=len(all_findings),
            critical_count=sum(1 for f in all_findings if f.severity == Severity.CRITICAL),
            high_count=sum(1 for f in all_findings if f.severity == Severity.HIGH),
            medium_count=sum(1 for f in all_findings if f.severity == Severity.MEDIUM),
            low_count=sum(1 for f in all_findings if f.severity == Severity.LOW),
            info_count=sum(1 for f in all_findings if f.severity == Severity.INFO),
        )

    def _calculate_categories(self, findings: list[Finding]) -> list[CategoryScore]:
        by_category: dict[CheckCategory, list[Finding]] = {}
        for f in findings:
            by_category.setdefault(f.category, []).append(f)

        scores: list[CategoryScore] = []
        for category, cat_findings in by_category.items():
            critical = high = medium = low = info = 0
            total_penalty = 0.0

            for f in cat_findings:
                sev_weight = self.SEVERITY_WEIGHTS.get(f.severity, 0.5)
                base_penalty = f.severity.score * sev_weight
                confidence_factor = f.confidence.multiplier
                fp_factor = 1.0 - f.false_positive_probability
                effective_penalty = base_penalty * confidence_factor * fp_factor
                total_penalty += effective_penalty

                if f.severity == Severity.CRITICAL:
                    critical += 1
                elif f.severity == Severity.HIGH:
                    high += 1
                elif f.severity == Severity.MEDIUM:
                    medium += 1
                elif f.severity == Severity.LOW:
                    low += 1
                else:
                    info += 1

            max_sev = max(f.severity for f in cat_findings) if cat_findings else None

            # Normalize: cap at 10.0, penalise proportionally to finding count
            total_findings = len(cat_findings)
            normalized = min(
                10.0, total_penalty / max(1, total_findings) * (1.0 + total_findings * 0.1)
            )
            score = min(10.0, max(0.0, normalized))

            weight = self.CATEGORY_WEIGHTS.get(category, 1.0)

            scores.append(
                CategoryScore(
                    category=category,
                    score=round(score, 2),
                    finding_count=total_findings,
                    critical_count=critical,
                    high_count=high,
                    medium_count=medium,
                    low_count=low,
                    info_count=info,
                    max_severity=max_sev,
                    weight=weight,
                )
            )

        return sorted(scores, key=lambda s: s.score, reverse=True)

    def _calculate_overall(self, categories: list[CategoryScore]) -> float:
        if not categories:
            return 0.0

        total_weight = sum(c.weight for c in categories)
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(c.score * c.weight for c in categories)
        return round(min(10.0, weighted_sum / total_weight), 2)

    @staticmethod
    def _score_to_grade(score: float) -> str:
        if score == 0.0:
            return "A+"
        if score < 1.0:
            return "A"
        if score < 2.5:
            return "B"
        if score < 5.0:
            return "C"
        if score < 7.0:
            return "D"
        if score < 8.5:
            return "F"
        return "F-"
