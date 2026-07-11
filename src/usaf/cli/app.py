from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer

from usaf.__about__ import __version__
from usaf.config.loader import load_config
from usaf.core.runner import ScanRunner
from usaf.reporting import REPORTERS

# Import checks to trigger plugin registration
import usaf.checks  # noqa: F401

app = typer.Typer(
    name="usaf",
    help="Ubuntu Security Audit Framework - Production-grade security auditing for Ubuntu Linux",
    add_completion=False,
    no_args_is_help=True,
)


@app.callback(invoke_without_command=True)
def callback(
    version: Annotated[
        bool,
        typer.Option("--version", "-V", help="Show version and exit"),
    ] = False,
) -> None:
    if version:
        print(f"usaf v{__version__}")
        raise typer.Exit()


@app.command()
def scan(
    config: Annotated[
        Optional[str],
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
    output: Annotated[
        Optional[str],
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Report format (terminal, json, markdown)"),
    ] = "terminal",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Verbose output (show progress and passed checks)"),
    ] = False,
    show_passed: Annotated[
        bool,
        typer.Option("--show-passed", help="Show passed checks in report"),
    ] = False,
    checks: Annotated[
        Optional[list[str]],
        typer.Option("--checks", help="Specific checks to run (e.g., SSH-001 SSH-002)"),
    ] = None,
) -> None:
    """Run a security audit scan."""
    runner = ScanRunner(config_path=config)
    result = runner.run(check_ids=checks, verbose=verbose)
    score = runner.score(result)

    reporter_cls = REPORTERS.get(fmt)
    if reporter_cls is None:
        print(f"Error: Unknown format '{fmt}'. Available: {', '.join(REPORTERS.keys())}",
              file=sys.stderr)
        raise typer.Exit(1)

    reporter = reporter_cls()

    # Generate report content
    if fmt == "terminal":
        reporter.print_to_console(result, score, verbose=verbose, show_passed=show_passed)
        report_content = reporter.generate(result, score, verbose=verbose, show_passed=show_passed)
    else:
        report_content = reporter.generate(result, score, verbose=verbose, show_passed=show_passed)
        print(report_content)

    # Determine save path
    if output:
        save_path = output
    else:
        report_dir = Path("reports")
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = {"terminal": "txt", "json": "json", "markdown": "md"}[fmt]
        save_path = str(report_dir / f"usaf-report-{timestamp}.{ext}")

    reporter.write(report_content, save_path)
    print(f"Report saved to {save_path}", file=sys.stderr)


@app.command()
def list_checks(
    config: Annotated[
        Optional[str],
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
    category: Annotated[
        Optional[str],
        typer.Option("--category", help="Filter by category"),
    ] = None,
) -> None:
    """List all available security checks."""
    from usaf.core.registry import registry

    runner = ScanRunner(config_path=config)
    all_ids = registry.get_all_ids()
    all_instances = registry.get_all_instances()

    if category:
        all_ids = [
            cid for cid in all_ids
            if hasattr(registry.get_class(cid), "category")
            and str(registry.get_class(cid).category.value).upper() == category.upper()
        ]

    if not all_ids:
        print("No checks found.")
        return

    print(f"\nAvailable Checks ({len(all_ids)}):")
    print("=" * 80)
    for cid in sorted(all_ids):
        cls = registry.get_class(cid)
        instance = all_instances.get(cid)
        sev = instance.severity.value if instance else "N/A"
        cat = instance.category.value if instance else "N/A"
        desc = instance.description if instance else "N/A"
        print(f"  {cid:<12} [{sev:<8}] [{cat:<15}] {desc}")
    print()


@app.command()
def init(
    path: Annotated[
        Optional[str],
        typer.Argument(help="Directory to initialize"),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Overwrite existing configuration"),
    ] = False,
) -> None:
    """Initialize a USAF configuration file in the current directory."""
    target_dir = Path(path) if path else Path.cwd()
    target_dir = target_dir.resolve()
    config_path = target_dir / "usaf.yaml"

    if config_path.exists() and not force:
        print(f"Configuration already exists at {config_path}. Use --force to overwrite.")
        raise typer.Exit(1)

    from usaf.config.defaults import DEFAULT_CONFIG_YAML

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(DEFAULT_CONFIG_YAML)
    print(f"Initialized configuration at {config_path}")


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
