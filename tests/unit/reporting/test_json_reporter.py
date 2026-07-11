from __future__ import annotations

import json

from usaf.models.finding import Finding
from usaf.models.result import CheckResult, ScanResult
from usaf.models.severity import CheckCategory, Severity
from usaf.reporting.json import JSONReporter
from usaf.scoring.engine import ScoringEngine


class TestJSONReporter:
    def test_generates_valid_json(self, sample_scan_result: ScanResult):
        reporter = JSONReporter()
        output = reporter.generate(sample_scan_result)
        data = json.loads(output)
        assert "usaf_version" in data
        assert "scan" in data
        assert "summary" in data
        assert "findings" in data

    def test_no_findings(self):
        result = ScanResult()
        reporter = JSONReporter()
        output = reporter.generate(result)
        data = json.loads(output)
        assert data["summary"]["total_findings"] == 0
        assert "findings" not in data or data["findings"] == []

    def test_with_score(self, sample_scan_result: ScanResult):
        engine = ScoringEngine()
        score = engine.calculate(sample_scan_result)
        reporter = JSONReporter()
        output = reporter.generate(sample_scan_result, score)
        data = json.loads(output)
        assert "score" in data
        assert "overall_score" in data["score"]

    def test_with_multiple_findings(self):
        result = ScanResult(
            results=[
                CheckResult(
                    check_id="TEST-001",
                    name="Test",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="TEST-001-001",
                            check_id="TEST-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.HIGH,
                            risk_score=7.5,
                            title="Finding 1",
                            description="Desc 1",
                            rationale="Why 1",
                            remediation="Fix 1",
                            source="Test",
                        ),
                        Finding(
                            id="TEST-001-002",
                            check_id="TEST-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.LOW,
                            risk_score=2.5,
                            title="Finding 2",
                            description="Desc 2",
                            rationale="Why 2",
                            remediation="Fix 2",
                            source="Test",
                        ),
                    ],
                )
            ]
        )
        reporter = JSONReporter()
        output = reporter.generate(result)
        data = json.loads(output)
        assert len(data["findings"]) == 2
