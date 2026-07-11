from __future__ import annotations

from pathlib import Path

from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Severity
from usaf.reporting.base import BaseReporter


class TestBaseReporter:
    def test_enrich_finding_no_kb_entry(self):
        reporter = BaseReporter()
        finding = Finding(
            id="TEST-001",
            check_id="TEST-001",
            category=CheckCategory.SYSTEM,
            severity=Severity.HIGH,
            risk_score=5.0,
            title="Test",
            description="Test",
            rationale="Test",
            remediation="Test",
            source="Test",
        )
        result = reporter.enrich_finding(finding)
        assert result == {}

    def test_enrich_findings_empty_list(self):
        reporter = BaseReporter()
        result = reporter.enrich_findings([])
        assert result == []

    def test_knowledge_base_lazy_loaded(self):
        reporter = BaseReporter()
        assert reporter._kb is None
        _ = reporter.knowledge_base
        assert reporter._kb is not None

    def test_write_creates_file(self, tmp_path):
        reporter = BaseReporter()
        output_path = str(tmp_path / "output.txt")
        reporter.write("hello world", output_path)
        assert Path(output_path).exists()
        assert Path(output_path).read_text() == "hello world"

    def test_generate_raises_not_implemented(self):
        reporter = BaseReporter()
        from usaf.models.result import ScanResult

        try:
            reporter.generate(ScanResult())
            assert False, "Should have raised NotImplementedError"
        except NotImplementedError:
            pass
