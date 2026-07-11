from __future__ import annotations

from datetime import datetime
from typing import Any

from usaf.models.evidence import (
    CommandEvidence,
    FileEvidence,
    NetworkEvidence,
    ProcessEvidence,
    UserEvidence,
)
from usaf.models.finding import Finding
from usaf.models.result import ScanResult
from usaf.models.score import ScanScore
from usaf.models.severity import Severity
from usaf.reporting.base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Generates Markdown reports for documentation and sharing."""

    name = "markdown"
    description = "Markdown-formatted security audit report"

    def generate(self, result: ScanResult, score: ScanScore | None = None, **kwargs: Any) -> str:
        lines: list[str] = []
        verbose = kwargs.get("verbose", False)
        show_passed = kwargs.get("show_passed", False)

        lines.append(f"# USAF Security Audit Report")
        lines.append(f"")
        lines.append(f"- **Scan:** {result.metadata.scan_name}")
        lines.append(f"- **Date:** {result.metadata.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"- **Host:** {result.metadata.hostname}")
        lines.append(f"- **OS:** {result.metadata.os_info}")
        lines.append(f"- **Kernel:** {result.metadata.kernel_info}")
        lines.append(f"- **Duration:** {result.metadata.duration_seconds:.1f}s")

        if score:
            lines.append(f"- **Overall Score:** {score.overall_score}/10 ({score.overall_grade})")
            lines.append(f"- **Total Findings:** {result.total_findings}")
            lines.append(f"  - Critical: {score.critical_count} | High: {score.high_count} | "
                         f"Medium: {score.medium_count} | Low: {score.low_count} | "
                         f"Info: {score.info_count}")

        lines.append(f"")
        lines.append(f"---")
        lines.append(f"")

        findings = result.findings

        if not findings:
            lines.append("## Results")
            lines.append("")
            lines.append("✅ **No findings. System is well-configured.**")
            lines.append("")
            return "\n".join(lines)

        lines.append(f"## Findings by Severity")
        lines.append(f"")

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            sev_findings = [f for f in findings if f.severity == severity]
            if not sev_findings:
                continue

            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
            lines.append(f"### {emoji.get(severity.value, '')} {severity.value} ({len(sev_findings)})")
            lines.append(f"")

            for finding in sev_findings:
                lines.append(f"#### {finding.id}: {finding.title}")
                lines.append(f"")
                lines.append(f"| Field | Value |")
                lines.append(f"|---|---|")
                lines.append(f"| **Severity** | {finding.severity.value} |")
                lines.append(f"| **Risk Score** | {finding.risk_score}/10 |")
                lines.append(f"| **Confidence** | {finding.confidence.value} |")
                lines.append(f"| **Category** | {finding.category.value} |")
                lines.append(f"| **Component** | {finding.affected_component or 'N/A'} |")

                if finding.mitre_attack_ids:
                    lines.append(f"| **MITRE ATT&CK** | {', '.join(finding.mitre_attack_ids)} |")

                lines.append(f"")
                lines.append(f"**Description:** {finding.description}")
                lines.append(f"")
                lines.append(f"**Why It Matters:** {finding.rationale}")
                lines.append(f"")
                lines.append(f"**Remediation:** {finding.remediation}")
                lines.append(f"")

                if finding.detected_value:
                    lines.append(f"> **Detected:** `{finding.detected_value}`")
                if finding.expected_value:
                    lines.append(f"> **Expected:** `{finding.expected_value}`")

                if finding.evidence:
                    ev = finding.evidence
                    lines.append(f"")
                    lines.append(f"**Evidence:**")
                    lines.append(f"")
                    lines.append(f"```")
                    if isinstance(ev, FileEvidence):
                        lines.append(f"  File: {ev.path}")
                        if ev.permission:
                            lines.append(f"  Permissions: {ev.permission}")
                        if ev.owner:
                            lines.append(f"  Owner: {ev.owner}")
                        if ev.content:
                            lines.append(f"  Content: {ev.content[:500]}")
                    elif isinstance(ev, NetworkEvidence):
                        lines.append(f"  Protocol: {ev.protocol}")
                        lines.append(f"  Address: {ev.local_address}:{ev.local_port}")
                        if ev.remote_address:
                            lines.append(f"  Remote: {ev.remote_address}:{ev.remote_port}")
                        if ev.state:
                            lines.append(f"  State: {ev.state}")
                    elif isinstance(ev, ProcessEvidence):
                        lines.append(f"  PID: {ev.pid}")
                        lines.append(f"  Name: {ev.name}")
                        if ev.binary:
                            lines.append(f"  Binary: {ev.binary}")
                        if ev.cmdline:
                            lines.append(f"  Cmdline: {ev.cmdline}")
                    elif isinstance(ev, UserEvidence):
                        lines.append(f"  Username: {ev.username}")
                        lines.append(f"  UID: {ev.uid}")
                        if ev.home:
                            lines.append(f"  Home: {ev.home}")
                        if ev.groups:
                            lines.append(f"  Groups: {', '.join(ev.groups)}")
                    else:
                        lines.append(f"  {ev.model_dump()}")
                    lines.append(f"```")

                lines.append(f"")
                lines.append(f"---")
                lines.append(f"")

        # Category breakdown
        if score and score.categories:
            lines.append(f"## Category Scores")
            lines.append(f"")
            lines.append(f"| Category | Score | Findings | Critical | High | Medium |")
            lines.append(f"|---|---|---|---|---|---|")
            for cat in sorted(score.categories, key=lambda c: c.score, reverse=True):
                lines.append(
                    f"| {cat.category.value} | {cat.score}/10 | {cat.finding_count} | "
                    f"{cat.critical_count} | {cat.high_count} | {cat.medium_count} |"
                )
            lines.append(f"")

        # Checks summary
        if verbose or show_passed:
            lines.append(f"## Checks Summary")
            lines.append(f"")
            lines.append(f"| Check | Status | Findings | Time |")
            lines.append(f"|---|---|---|---|")
            for check_result in sorted(result.results, key=lambda r: r.check_id):
                status = "✅" if check_result.passed else "❌"
                lines.append(
                    f"| {check_result.check_id} | {status} | {check_result.finding_count} | "
                    f"{check_result.execution_time_ms:.0f}ms |"
                )
            lines.append(f"")

        lines.append(f"---")
        lines.append(f"*Report generated by USAF v{result.metadata.usaf_version or '0.1.0'} "
                     f"at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")

        return "\n".join(lines)
