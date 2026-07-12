from __future__ import annotations

from typing import Any

from test_lab.scenarios.base import ExpectedFinding, ExpectedFindings


class ValidationResult:
    def __init__(self, scenario_name: str) -> None:
        self.scenario_name = scenario_name
        self.matched: list[dict[str, Any]] = []
        self.missed: list[ExpectedFinding] = []
        self.false_positives: list[dict[str, Any]] = []
        self.total_expected: int = 0
        self.total_detected: int = 0
        self.total_findings: int = 0

    @property
    def detection_rate(self) -> float:
        if self.total_expected == 0:
            return 1.0
        return self.total_detected / self.total_expected

    @property
    def passed(self) -> bool:
        return self.detection_rate >= 0.9

    @property
    def summary(self) -> str:
        return (
            f"  Detection Rate: {self.detection_rate:.1%} ({self.total_detected}/{self.total_expected})\n"
            f"  Matched:        {len(self.matched)}\n"
            f"  Missed:         {len(self.missed)}\n"
            f"  False Positives: {len(self.false_positives)}\n"
            f"  Total Findings: {self.total_findings}\n"
            f"  Status:         {'PASS' if self.passed else 'FAIL'}"
        )


class FindingsValidator:
    def __init__(self, expected: ExpectedFindings) -> None:
        self.expected = expected

    def validate(self, findings: list[dict[str, Any]]) -> ValidationResult:
        result = ValidationResult(self.expected.scenario)
        result.total_expected = len(self.expected.expected_findings)
        result.total_findings = len(findings)

        matched_check_ids: set[str] = set()

        for exp in self.expected.expected_findings:
            matching = self._find_matching(findings, exp)
            if matching:
                result.matched.append({"expected": exp, "actual": matching})
                result.total_detected += 1
                matched_check_ids.add(exp.check_id)
            else:
                result.missed.append(exp)

        # Identify false positives: findings for checks not in expected
        expected_ids = {f.check_id for f in self.expected.expected_findings}
        false_pos = [
            f
            for f in findings
            if f.get("_check_id", "").split("-")[0]
            not in {eid.split("-")[0] for eid in expected_ids}
        ]
        result.false_positives = false_pos[:20]

        return result

    def _find_matching(
        self, findings: list[dict[str, Any]], expected: ExpectedFinding
    ) -> list[dict[str, Any]]:
        matching = []
        for f in findings:
            check_id = f.get("_check_id", "")
            if check_id != expected.check_id:
                continue
            if expected.finding_id and f.get("finding_id") != expected.finding_id:
                continue
            if expected.title_contains:
                title = f.get("title", "")
                if expected.title_contains.lower() not in title.lower():
                    continue
            if expected.severity and f.get("severity") != expected.severity:
                continue
            matching.append(f)
        if len(matching) >= expected.count_min:
            return matching
        return []
