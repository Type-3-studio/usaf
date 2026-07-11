from __future__ import annotations

import datetime
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from usaf.models.evidence import (
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

_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "red",
    Severity.HIGH: "orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "white",
}

_SEVERITY_BADGES: dict[Severity, str] = {
    Severity.CRITICAL: "[red bold]CRITICAL[/]",
    Severity.HIGH: "[orange3 bold]HIGH[/]",
    Severity.MEDIUM: "[yellow bold]MEDIUM[/]",
    Severity.LOW: "[blue bold]LOW[/]",
    Severity.INFO: "[white bold]INFO[/]",
}


class TerminalReporter(BaseReporter):
    """Generates rich terminal output for human consumption."""

    name = "terminal"
    description = "Color-coded terminal output with Rich formatting"

    def __init__(self) -> None:
        super().__init__()
        self.console = Console()

    def generate(self, result: ScanResult, score: ScanScore | None = None, **kwargs: Any) -> str:
        import io

        from rich.console import Console as RichConsole

        buf = io.StringIO()
        c = RichConsole(file=buf, force_terminal=kwargs.get("color", True))
        verbose = kwargs.get("verbose", False)
        show_passed = kwargs.get("show_passed", False)

        self._print_header(c, result, score)
        self._print_score(c, score)
        self._print_findings(c, result, verbose)
        self._print_category_scores(c, score)
        self._print_checks_summary(c, result, show_passed)
        self._print_footer(c, result)

        return buf.getvalue()

    def write(self, content: str, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def print_to_console(
        self, result: ScanResult, score: ScanScore | None = None, **kwargs: Any
    ) -> None:
        self._print_header(self.console, result, score)
        self._print_score(self.console, score)
        self._print_findings(self.console, result, kwargs.get("verbose", False))
        self._print_category_scores(self.console, score)
        self._print_checks_summary(self.console, result, kwargs.get("show_passed", False))
        self._print_footer(self.console, result)

    def _print_header(self, console: Console, result: ScanResult, score: ScanScore | None) -> None:
        console.print()
        title = Text("USAF - Ubuntu Security Audit Framework", style="bold cyan")
        console.print(Panel(title, width=60))
        console.print(f"  Scan:   [bold]{result.metadata.scan_name}[/]")
        console.print(f"  Host:   {result.metadata.hostname or 'unknown'}")
        console.print(f"  OS:     {result.metadata.os_info or 'unknown'}")
        console.print(f"  Kernel: {result.metadata.kernel_info or 'unknown'}")
        console.print(f"  Time:   {result.metadata.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        console.print(f"  Duration: {result.metadata.duration_seconds:.1f}s")
        console.print()

    def _print_score(self, console: Console, score: ScanScore | None) -> None:
        if score is None:
            return

        grade_color = (
            "green" if score.overall_score < 2 else ("yellow" if score.overall_score < 5 else "red")
        )
        score_text = Text.assemble(
            ("Overall Score: ", ""),
            (f"{score.overall_score}/10", f"bold {grade_color}"),
            ("  ", ""),
            (f"{score.overall_grade}", f"bold {grade_color}"),
        )
        console.print(Panel(score_text, style=grade_color if score.overall_score < 2 else ""))

        summary = (
            f"Total Findings: {score.total_findings} | "
            f"🔴 Critical: {score.critical_count} | "
            f"🟠 High: {score.high_count} | "
            f"🟡 Medium: {score.medium_count} | "
            f"🔵 Low: {score.low_count} | "
            f"⚪ Info: {score.info_count}"
        )
        console.print(f"  {summary}")
        console.print()

    def _print_findings(self, console: Console, result: ScanResult, verbose: bool) -> None:
        if not result.findings:
            console.print("[bold green]✅ No findings. System is well-configured.[/]")
            console.print()
            return

        for severity in [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]:
            sev_findings = [f for f in result.findings if f.severity == severity]
            if not sev_findings:
                continue
            color = _SEVERITY_COLORS[severity]
            badge = _SEVERITY_BADGES[severity]
            console.print(f"[bold {color}]━━━ {severity.value} ({len(sev_findings)}) ━━━[/]")
            console.print()
            for finding in sev_findings:
                self._print_finding(console, finding)
            console.print()

    def _print_finding(self, console: Console, finding: Finding) -> None:
        color = _SEVERITY_COLORS[finding.severity]
        badge = _SEVERITY_BADGES[finding.severity]

        title = Text.assemble(
            (f"  [{color}]{finding.id}[/] ", ""),
            (f"{finding.title}", f"bold {color}"),
        )
        console.print(title)

        console.print(
            f"    [dim]Score:[/] {finding.risk_score}  [dim]Confidence:[/] {finding.confidence.value}  "
            f"[dim]Category:[/] {finding.category.value}  [dim]Component:[/] {finding.affected_component or 'N/A'}"
        )

        if finding.mitre_attack_ids:
            console.print(f"    [dim]MITRE:[/] {', '.join(finding.mitre_attack_ids)}")

        # Knowledge Base enrichment (P3-2)
        kb = self.enrich_finding(finding)
        if kb:
            if kb.get("kb_cvss"):
                console.print(f"    [dim]CVSS:[/] {kb['kb_cvss']}")
            if kb.get("kb_exploit"):
                console.print(f"    [dim]Exploit:[/] {kb['kb_exploit']}")
            if kb.get("kb_breakage"):
                console.print(f"    [dim]Breakage:[/] {kb['kb_breakage']}")
            if kb.get("kb_known_exceptions"):
                exceptions = kb["kb_known_exceptions"]
                console.print(f"    [dim]Exceptions ({len(exceptions)}):[/] {exceptions[0]}")

        console.print(f"    [bold]Why:[/] {finding.rationale}")
        console.print(f"    [bold]Fix:[/] {finding.remediation}")

        if finding.detected_value:
            console.print(f"    [bold red]Detected:[/] {finding.detected_value}")
        if finding.expected_value:
            console.print(f"    [bold green]Expected:[/] {finding.expected_value}")

        if finding.evidence:
            console.print("    [dim]Evidence:[/]")
            ev = finding.evidence
            if isinstance(ev, FileEvidence):
                console.print(f"      File: {ev.path}")
                if ev.permission:
                    console.print(f"      Permissions: {ev.permission}")
                if ev.owner:
                    console.print(f"      Owner: {ev.owner}")
                if ev.content:
                    console.print(f"      Content: {ev.content[:300]}")
            elif isinstance(ev, NetworkEvidence):
                console.print(
                    f"      {ev.protocol} {ev.local_address}:{ev.local_port} → "
                    f"{ev.remote_address or '*'}:{ev.remote_port or '*'}"
                )
            elif isinstance(ev, ProcessEvidence):
                console.print(f"      PID {ev.pid}: {ev.name} ({ev.binary})")
            elif isinstance(ev, UserEvidence):
                console.print(f"      User: {ev.username} (UID: {ev.uid})")
            else:
                console.print(f"      {ev.model_dump()}")

        console.print()

    def _print_category_scores(self, console: Console, score: ScanScore | None) -> None:
        if not score or not score.categories:
            return

        table = Table(title="Category Scores", box=box.ROUNDED)
        table.add_column("Category", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Findings", justify="right")
        table.add_column("Critical", style="red", justify="right")
        table.add_column("High", style="orange3", justify="right")
        table.add_column("Medium", style="yellow", justify="right")

        for cat in sorted(score.categories, key=lambda c: c.score, reverse=True):
            color = "green" if cat.score < 2 else ("yellow" if cat.score < 5 else "red")
            table.add_row(
                cat.category.value,
                f"[{color}]{cat.score}[/]",
                str(cat.finding_count),
                str(cat.critical_count),
                str(cat.high_count),
                str(cat.medium_count),
            )
        console.print(table)
        console.print()

    def _print_checks_summary(
        self, console: Console, result: ScanResult, show_passed: bool
    ) -> None:
        if not show_passed:
            return

        table = Table(title="Checks Summary", box=box.SIMPLE)
        table.add_column("Check ID", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Findings", justify="right")
        table.add_column("Time", justify="right")

        for check_result in sorted(result.results, key=lambda r: r.check_id):
            status = "[green]✅ PASS[/]" if check_result.passed else "[red]❌ FAIL[/]"
            table.add_row(
                check_result.check_id,
                status,
                str(check_result.finding_count),
                f"{check_result.execution_time_ms:.0f}ms",
            )
        console.print(table)
        console.print()

    def _print_footer(self, console: Console, result: ScanResult) -> None:
        console.print(
            f"[dim]Report generated by USAF v{result.metadata.usaf_version or '0.1.0'} "
            f"at {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC[/]"
        )
        console.print()
