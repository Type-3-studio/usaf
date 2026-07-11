from __future__ import annotations

"""Golden report tests: verify reporter output matches expected snapshots."""

from pathlib import Path

import pytest

from usaf.models.evidence import RegistryEvidence
from usaf.models.finding import Finding
from usaf.models.result import CheckResult, ScanResult, ScanMetadata
from usaf.models.severity import CheckCategory, Severity
from usaf.reporting.json import JSONReporter
from usaf.reporting.markdown import MarkdownReporter

GOLDEN_DIR = Path(__file__).parent / "reports"


@pytest.mark.golden
def test_json_golden_report():
    result = _make_sample_result()
    reporter = JSONReporter()
    output = reporter.generate(result)
    golden_file = GOLDEN_DIR / "sample_report.json"

    if not golden_file.exists():
        golden_file.write_text(output)
        pytest.skip(f"Golden file created at {golden_file}")

    import json
    output_data = json.loads(output)
    golden_data = json.loads(golden_file.read_text())

    assert output_data["system"] == golden_data["system"]
    assert len(output_data["findings"]) == len(golden_data["findings"])
    assert output_data["summary"] == golden_data["summary"]


@pytest.mark.golden
def test_markdown_golden_report():
    result = _make_sample_result()
    reporter = MarkdownReporter()
    output = reporter.generate(result)
    golden_file = GOLDEN_DIR / "sample_report.md"

    if not golden_file.exists():
        golden_file.write_text(output)
        pytest.skip(f"Golden file created at {golden_file}")

    import re
    ts_pattern = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC"
    output_clean = re.sub(ts_pattern, "TIMESTAMP", output)
    golden_clean = re.sub(ts_pattern, "TIMESTAMP", golden_file.read_text())
    assert output_clean.strip() == golden_clean.strip()


def _make_sample_result() -> ScanResult:
    return ScanResult(
        metadata=ScanMetadata(
            hostname="golden-test-host",
            os_info="Ubuntu 24.04",
            scan_name="golden-test",
        ),
        results=[
            CheckResult(
                check_id="KERN-101",
                name="Kernel ASLR Status",
                category=CheckCategory.SYSTEM,
                passed=False,
                findings=[
                    Finding(
                        id="KERN-101-001",
                        check_id="KERN-101",
                        category=CheckCategory.SYSTEM,
                        severity=Severity.HIGH,
                        risk_score=7.5,
                        title="ASLR is not fully enabled",
                        description="kernel.randomize_va_space=0 (expected 2)",
                        rationale="ASLR prevents exploitation of memory corruption vulnerabilities",
                        remediation="Set kernel.randomize_va_space=2 in /etc/sysctl.d/",
                        evidence=RegistryEvidence(
                            key="kernel.randomize_va_space",
                            value="0",
                            expected="2",
                            source="/proc/sys/kernel/randomize_va_space",
                        ),
                        detected_value="0",
                        expected_value="2",
                        affected_component="kernel",
                        source="KernelASLRCheck",
                        mitre_attack_ids=["T1620"],
                        tags=["hardening", "aslr"],
                    ),
                ],
            ),
            CheckResult(
                check_id="SSH-101",
                name="SSH Protocol Version",
                category=CheckCategory.SYSTEM,
                passed=True,
                findings=[],
            ),
        ],
    )
