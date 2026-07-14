from __future__ import annotations

from usaf.models.finding import Finding
from usaf.models.result import CheckResult, ScanMetadata, ScanResult
from usaf.models.score import ScanScore
from usaf.models.severity import CheckCategory, Severity
from usaf.reporting.json import JSONReporter
from usaf.reporting.markdown import MarkdownReporter
from usaf.reporting.terminal import TerminalReporter


class TestReportersIntegration:
    """Integration tests ensuring all reporters handle the same data."""

    def make_scan_result(self) -> ScanResult:
        return ScanResult(
            metadata=ScanMetadata(
                hostname="test-host",
                os_info="Ubuntu 24.04",
                scan_name="integration-test",
            ),
            results=[
                CheckResult(
                    check_id="TEST-001",
                    name="Test Check",
                    category=CheckCategory.SYSTEM,
                    passed=False,
                    findings=[
                        Finding(
                            id="TEST-001-001",
                            check_id="TEST-001",
                            category=CheckCategory.SYSTEM,
                            severity=Severity.HIGH,
                            risk_score=7.5,
                            title="Test finding",
                            description="A test finding",
                            rationale="Because security",
                            remediation="Fix it",
                            source="TestCheck",
                        ),
                    ],
                ),
            ],
        )

    def test_all_reporters_produce_output(self):
        result = self.make_scan_result()
        score = ScanScore(overall_score=5.0, overall_grade="C")

        json_output = JSONReporter().generate(result, score)
        md_output = MarkdownReporter().generate(result, score)
        term_output = TerminalReporter().generate(result, score)

        assert len(json_output) > 0
        assert len(md_output) > 0
        assert len(term_output) > 0

    def test_json_output_parseable(self):
        import json

        result = self.make_scan_result()
        output = JSONReporter().generate(result)
        data = json.loads(output)
        assert data["system"]["hostname"] == "test-host"
        assert len(data["findings"]) == 1

    def test_markdown_contains_key_sections(self):
        result = self.make_scan_result()
        output = MarkdownReporter().generate(result)
        assert "# USAF" in output
        assert "Test finding" in output
        assert "test-host" in output

    def test_terminal_contains_finding_info(self):
        result = self.make_scan_result()
        output = TerminalReporter().generate(result)
        assert "Test finding" in output
        assert "TEST-001" in output

    def test_reports_no_findings(self):
        result = ScanResult(metadata=ScanMetadata(hostname="clean-host"))
        for reporter_cls in [JSONReporter, MarkdownReporter, TerminalReporter]:
            output = reporter_cls().generate(result)
            assert len(output) > 0
