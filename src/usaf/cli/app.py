from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer

# Import checks to trigger plugin registration
import usaf.checks  # noqa: F401
from usaf.__about__ import __version__
from usaf.baseline.manager import BaselineManager
from usaf.compliance.framework import ComplianceFramework
from usaf.core.runner import ScanRunner
from usaf.profiles.manager import ProfileManager
from usaf.reporting import REPORTERS

app = typer.Typer(
    name="usaf",
    help="Ubuntu Security Audit Framework - Production-grade security auditing for Ubuntu Linux",
    add_completion=False,
    no_args_is_help=True,
)

# Sub-apps for Phase 2 features
baseline_app = typer.Typer(help="Manage baseline snapshots for change detection")
compliance_app = typer.Typer(help="Compliance framework queries and gap analysis")
profile_app = typer.Typer(help="System profile management")
app.add_typer(baseline_app, name="baseline")
app.add_typer(compliance_app, name="compliance")
app.add_typer(profile_app, name="profile")


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
        str | None,
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", "-o", help="Output file path"),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Report format (terminal, json, markdown)"),
    ] = "terminal",
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Verbose output (show detailed progress and passed checks)"),
    ] = False,
    no_progress: Annotated[
        bool,
        typer.Option("--no-progress", help="Disable progress bar"),
    ] = False,
    show_passed: Annotated[
        bool,
        typer.Option("--show-passed", help="Show passed checks in report"),
    ] = False,
    checks: Annotated[
        list[str] | None,
        typer.Option("--checks", help="Specific checks to run (e.g., SSH-101 SSH-102)"),
    ] = None,
    baseline_diff: Annotated[
        bool,
        typer.Option(
            "--baseline-diff",
            help="Compare scan results against the default baseline",
        ),
    ] = False,
    compliance_framework: Annotated[
        str | None,
        typer.Option(
            "--compliance",
            help="Evaluate compliance against a framework (e.g., cis, nist)",
        ),
    ] = None,
    profile_name: Annotated[
        str | None,
        typer.Option(
            "--profile",
            help="System profile name to match against",
        ),
    ] = None,
) -> None:
    """Run a security audit scan with optional Phase 2 features."""
    runner = ScanRunner(config_path=config)
    result = runner.run(check_ids=checks, verbose=verbose, show_progress=not no_progress)

    # Baseline diff (P2-2) — triggered by --baseline-diff flag or config.baseline.compare
    should_compare = baseline_diff or runner.config.baseline.compare
    if should_compare:
        baseline_result = runner.compare_baseline(result, verbose=verbose)
        if runner.config.baseline.fail_on_drift:
            diff = baseline_result.get("diff")
            if diff and diff.has_changes:
                print(
                    "  [!] Drift detected and fail_on_drift is enabled. Exiting.",
                    file=sys.stderr,
                )
                raise typer.Exit(1)

    # Compliance evaluation (P2-4)
    if compliance_framework:
        compliance = ComplianceFramework()
        try:
            compliance_result = compliance.get_coverage(compliance_framework, result)
            if verbose:
                print(
                    f"  -> {compliance_framework.upper()} compliance: "
                    f"{compliance_result.passed}/{compliance_result.total_controls} passed, "
                    f"{compliance_result.failed} failed, "
                    f"{compliance_result.coverage_percent}% coverage"
                )
        except Exception as e:
            if verbose:
                print(f"  [!] Compliance evaluation skipped: {e}")

    # Profile matching (P2-5)
    if profile_name:
        profile_mgr = ProfileManager()
        try:
            profile_match = profile_mgr.match(result.collectors_data, profile_name=profile_name)
            if verbose:
                devs = profile_match.deviations
                if devs:
                    print(f"  -> Profile '{profile_name}': {len(devs)} deviation(s)")
                    for d in devs[:3]:
                        print(f"     - {d}")
                else:
                    print(f"  -> Profile '{profile_name}': matched ({profile_match.score:.0%})")
        except Exception as e:
            if verbose:
                print(f"  [!] Profile matching skipped: {e}")

    score = runner.score(result)

    reporter_cls = REPORTERS.get(fmt)
    if reporter_cls is None:
        print(
            f"Error: Unknown format '{fmt}'. Available: {', '.join(REPORTERS.keys())}",
            file=sys.stderr,
        )
        raise typer.Exit(1)

    reporter = reporter_cls()

    # Generate report content
    if fmt == "terminal":
        if hasattr(reporter, "print_to_console"):
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
        ext: dict[str, str] = {"terminal": "txt", "json": "json", "markdown": "md"}
        save_path = str(report_dir / f"usaf-report-{timestamp}.{ext.get(fmt, 'txt')}")

    reporter.write(report_content, save_path)
    print(f"Report saved to {save_path}", file=sys.stderr)


@baseline_app.command("init")
def baseline_init(
    name: Annotated[
        str,
        typer.Argument(help="Baseline name (default: default-baseline)"),
    ] = "default-baseline",
    config: Annotated[
        str | None,
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
) -> None:
    """Create an initial baseline snapshot from current system state."""
    runner = ScanRunner(config_path=config)
    result = runner.run(verbose=False)
    baseline_mgr = BaselineManager()
    snapshot = baseline_mgr.build_snapshot(result)
    path = baseline_mgr.store(name, snapshot)
    print(f"Baseline '{name}' created at {path}")
    print(f"  Packages:  {len(snapshot.packages)}")
    print(f"  Users:     {len(snapshot.users)}")
    print(f"  Services:  {len(snapshot.services)}")
    print(f"  Ports:     {len(snapshot.ports)}")
    print(f"  SUID:      {len(snapshot.suid_files)}")
    print(f"  Cron:      {len(snapshot.cron_jobs)}")


@baseline_app.command("update")
def baseline_update(
    name: Annotated[
        str,
        typer.Argument(help="Baseline name (default: default-baseline)"),
    ] = "default-baseline",
    config: Annotated[
        str | None,
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
) -> None:
    """Update an existing baseline to current system state."""
    runner = ScanRunner(config_path=config)
    baseline_mgr = BaselineManager()

    try:
        old = baseline_mgr.load(name)
    except Exception as e:
        print(f"Error: Baseline '{name}' not found ({e}). Use 'usaf baseline init' first.")
        raise typer.Exit(1) from e

    result = runner.run(verbose=False)
    snapshot = baseline_mgr.build_snapshot(result)
    path = baseline_mgr.store(name, snapshot)
    diff_result = baseline_mgr.diff(old, snapshot)

    print(f"Baseline '{name}' updated at {path}")
    if diff_result.has_changes:
        print(f"  Changes detected: {diff_result.total_changes}")
        for section, added_items in diff_result.added.items():
            print(f"    + {section}: {len(added_items)} added")
        for section, removed_items in diff_result.removed.items():
            print(f"    - {section}: {len(removed_items)} removed")
        for section, modified_items in diff_result.modified.items():
            print(f"    ~ {section}: {len(modified_items)} modified")
    else:
        print("  No changes detected.")


@baseline_app.command("diff")
def baseline_diff(
    name: Annotated[
        str,
        typer.Argument(help="Baseline name (default: default-baseline)"),
    ] = "default-baseline",
    config: Annotated[
        str | None,
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
) -> None:
    """Show changes between the stored baseline and current system state."""
    runner = ScanRunner(config_path=config)
    baseline_mgr = BaselineManager()

    try:
        baseline = baseline_mgr.load(name)
    except Exception as e:
        print(f"Error: Baseline '{name}' not found ({e}). Use 'usaf baseline init' first.")
        raise typer.Exit(1) from e

    result = runner.run(verbose=False)
    snapshot = baseline_mgr.build_snapshot(result)
    diff_result = baseline_mgr.diff(baseline, snapshot)

    if not diff_result.has_changes:
        print("No changes detected. System state matches baseline.")
        return

    print(f"\nBaseline Diff: '{name}'")
    print("=" * 60)

    for section, items in diff_result.added.items():
        print(f"\n  [+] {section.upper()} — {len(items)} added:")
        for item in items[:10]:
            print(f"      + {item['key']}")

    for section, items in diff_result.removed.items():
        print(f"\n  [-] {section.upper()} — {len(items)} removed:")
        for item in items[:10]:
            print(f"      - {item['key']}")

    for section, modified_items in diff_result.modified.items():
        print(f"\n  [~] {section.upper()} — {len(modified_items)} modified:")
        for key, change in list(modified_items.items())[:10]:
            print(f"      ~ {key}: {change['old']} -> {change['new']}")

    print(f"\nTotal changes: {diff_result.total_changes}")


@baseline_app.command("list")
def baseline_list() -> None:
    """List all stored baselines."""
    baseline_mgr = BaselineManager()
    baselines = baseline_mgr.list_baselines()
    if not baselines:
        print("No baselines found.")
        return
    print(f"\nStored Baselines ({len(baselines)}):")
    print("=" * 40)
    for b in baselines:
        print(f"  - {b}")


@app.command()
def list_checks(
    _config: Annotated[
        str | None,
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option("--category", help="Filter by category"),
    ] = None,
) -> None:
    """List all available security checks."""
    from usaf.core.registry import registry

    all_ids = registry.get_all_ids()
    all_instances = registry.get_all_instances()

    if category:
        all_ids = [
            cid
            for cid in all_ids
            if hasattr(registry.get_class(cid), "category")
            and str(registry.get_class(cid).category.value).upper() == category.upper()
        ]

    if not all_ids:
        print("No checks found.")
        return

    print(f"\nAvailable Checks ({len(all_ids)}):")
    print("=" * 80)
    for cid in sorted(all_ids):
        instance = all_instances.get(cid)
        sev = instance.severity.value if instance else "N/A"
        cat = instance.category.value if instance else "N/A"
        desc = instance.description if instance else "N/A"
        print(f"  {cid:<12} [{sev:<8}] [{cat:<15}] {desc}")
    print()


@baseline_app.command("delete")
def baseline_delete(
    name: Annotated[
        str,
        typer.Argument(help="Baseline name to delete"),
    ],
) -> None:
    """Delete a stored baseline."""
    baseline_mgr = BaselineManager()
    try:
        baseline_mgr.load(name)
        baseline_mgr.delete(name)
        print(f"Baseline '{name}' deleted.")
    except Exception as e:
        print(f"Error: {e}")
        raise typer.Exit(1)


@compliance_app.command("check")
def compliance_check(
    framework: Annotated[
        str,
        typer.Argument(help="Compliance framework (cis, nist)"),
    ] = "cis",
    config: Annotated[
        str | None,
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
) -> None:
    """Evaluate compliance against a security framework."""
    runner = ScanRunner(config_path=config)
    result = runner.run()
    compliance = ComplianceFramework()
    compliance_result = compliance.get_coverage(framework, result)

    print(f"\nCompliance Report: {framework.upper()}")
    print("=" * 60)
    print(f"  Total Controls:  {compliance_result.total_controls}")
    print(f"  Passed:          {compliance_result.passed}")
    print(f"  Failed:          {compliance_result.failed}")
    print(f"  Not Checked:     {compliance_result.not_checked}")
    print(f"  Coverage:        {compliance_result.coverage_percent}%")
    print(f"  Pass Rate:       {compliance_result.pass_percent}%")
    print()

    failed_controls = [c for c in compliance_result.controls if c.status == "failed"]
    if failed_controls:
        print(f"Failed Controls ({len(failed_controls)}):")
        print("-" * 40)
        for ctrl in failed_controls:
            print(f"  {ctrl.control_id}: {ctrl.title}")
            if ctrl.finding_ids:
                print(f"    Findings: {', '.join(ctrl.finding_ids)}")


@compliance_app.command("gaps")
def compliance_gaps(
    framework: Annotated[
        str,
        typer.Argument(help="Compliance framework (cis, nist)"),
    ] = "cis",
    config: Annotated[
        str | None,
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
) -> None:
    """Identify compliance gaps — controls with no check coverage."""
    runner = ScanRunner(config_path=config)
    # We need a ScanResult to pass; this is for gap analysis
    result = runner.run()
    compliance = ComplianceFramework()
    analysis = compliance.report_gap_analysis(framework, result)

    print(f"\nGap Analysis: {framework.upper()}")
    print("=" * 60)
    print(f"  Covered:  {len(analysis['covered'])} controls")
    print(f"  Gaps:     {len(analysis['gaps'])} controls")

    if analysis["gaps"]:
        print(f"\nControls with No Coverage ({len(analysis['gaps'])}):")
        print("-" * 40)
        for gap in analysis["gaps"]:
            print(f"  {gap['control']}: {gap['title']}")


@profile_app.command("list")
def profile_list() -> None:
    """List all available system profiles."""
    mgr = ProfileManager()
    profiles = mgr.all_profiles
    if not profiles:
        print("No profiles available.")
        return
    print(f"\nAvailable Profiles ({len(profiles)}):")
    print("=" * 60)
    for name, profile in sorted(profiles.items()):
        print(f"  {name:<30} {profile.description}")


@profile_app.command("match")
def profile_match(
    profile_name: Annotated[
        str | None,
        typer.Argument(help="Profile name (omit for auto-detect)"),
    ] = None,
    config: Annotated[
        str | None,
        typer.Option("--config", "-c", help="Path to configuration file"),
    ] = None,
) -> None:
    """Match the current system against a profile."""
    runner = ScanRunner(config_path=config)
    result = runner.run(verbose=False)
    mgr = ProfileManager()

    if profile_name:
        match = mgr.match(result.collectors_data, profile_name=profile_name)
    else:
        match = mgr.match(result.collectors_data)

    print(f"\nProfile Match: {match.profile.name}")
    print("=" * 60)
    print(f"  Match Score:  {match.score:.1%}")
    print(f"  Match Status: {'✓ MATCHED' if match.is_match else '✗ DOES NOT MATCH'}")
    print()

    devs = match.deviations
    if devs:
        print("  Deviations:")
        for d in devs:
            print(f"    - {d}")
    else:
        print("  No deviations found — system matches profile exactly.")


@profile_app.command("load")
def profile_load(
    path: Annotated[
        str,
        typer.Argument(help="Path to YAML profile file"),
    ],
) -> None:
    """Load a custom profile from a YAML file."""
    mgr = ProfileManager()
    try:
        profile = mgr.load_from_file(path)
        print(f"Loaded profile '{profile.name}' from {path}")
    except Exception as e:
        print(f"Error loading profile: {e}")
        raise typer.Exit(1)


@app.command()
def init(
    path: Annotated[
        str | None,
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
