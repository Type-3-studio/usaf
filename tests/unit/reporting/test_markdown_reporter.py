from __future__ import annotations

from pathlib import Path

from usaf.models.finding import Finding
from usaf.models.result import CheckResult, ScanResult
from usaf.models.severity import CheckCategory, Severity
from usaf.reporting.markdown import MarkdownReporter


class TestMarkdownReporter:
    def test_generates_output(self, sample_scan_result: ScanResult):
        reporter = MarkdownReporter()
        output = reporter.generate(sample_scan_result)
        assert len(output) > 0
        assert "USAF" in output

    def test_no_findings(self):
        result = ScanResult()
        reporter = MarkdownReporter()
        output = reporter.generate(result)
        assert "No findings" in output

    def test_with_score(self, sample_scan_result: ScanResult):
        from usaf.scoring.engine import ScoringEngine

        engine = ScoringEngine()
        score = engine.calculate(sample_scan_result)
        reporter = MarkdownReporter()
        output = reporter.generate(sample_scan_result, score)
        assert "Overall Score" in output

    def test_finding_header_format(self, sample_scan_result: ScanResult):
        reporter = MarkdownReporter()
        output = reporter.generate(sample_scan_result)
        assert "###" in output

    def test_write_creates_file(self, tmp_path):
        result = ScanResult()
        reporter = MarkdownReporter()
        output_path = str(tmp_path / "report.md")
        reporter.write("test markdown", output_path)
        assert Path(output_path).exists()
        assert Path(output_path).read_text() == "test markdown"
