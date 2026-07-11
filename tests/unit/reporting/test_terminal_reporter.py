from __future__ import annotations

from pathlib import Path

from usaf.models.finding import Finding
from usaf.models.result import CheckResult, ScanResult
from usaf.models.severity import CheckCategory, Severity
from usaf.reporting.terminal import TerminalReporter


class TestTerminalReporter:
    def test_generates_output(self, sample_scan_result: ScanResult):
        reporter = TerminalReporter()
        output = reporter.generate(sample_scan_result)
        assert len(output) > 0
        assert "USAF" in output

    def test_no_findings(self):
        result = ScanResult()
        reporter = TerminalReporter()
        output = reporter.generate(result)
        assert "No findings" in output

    def test_with_score(self, sample_scan_result: ScanResult):
        from usaf.scoring.engine import ScoringEngine

        engine = ScoringEngine()
        score = engine.calculate(sample_scan_result)
        reporter = TerminalReporter()
        output = reporter.generate(sample_scan_result, score)
        assert "Overall Score" in output

    def test_verbose_mode(self, sample_scan_result: ScanResult):
        reporter = TerminalReporter()
        output = reporter.generate(sample_scan_result, verbose=True)
        assert len(output) > 0

    def test_no_color_force(self, sample_scan_result: ScanResult):
        reporter = TerminalReporter()
        output = reporter.generate(sample_scan_result, color=False)
        assert len(output) > 0

    def test_write_creates_file(self, tmp_path):
        result = ScanResult()
        reporter = TerminalReporter()
        output_path = str(tmp_path / "report.txt")
        reporter.write("test content", output_path)
        assert Path(output_path).exists()
        assert Path(output_path).read_text() == "test content"
