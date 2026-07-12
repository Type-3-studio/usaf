#!/usr/bin/env python3
"""
USAF Validation Lab — CLI

Usage:
    python run.py list
    python run.py provision <scenario>
    python run.py validate <scenario>
    python run.py run <scenario>
    python run.py destroy <scenario>
    python run.py run-all
    python run.py install <scenario>
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Ensure test_lab package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from test_lab.harness.provisioner import VagrantProvisioner
from test_lab.harness.reporter import print_gap_report, print_validation_summary
from test_lab.harness.runner import USAFRunner
from test_lab.harness.validator import FindingsValidator
from test_lab.scenarios.expected_schema import load_expected_yaml
from test_lab.scenarios.registry import ScenarioRegistry


def cmd_list() -> None:
    ScenarioRegistry.discover()
    details = ScenarioRegistry.list_details()
    print(f"\nUSAF Validation Lab — Available Scenarios ({len(details)}):")
    print("=" * 60)
    for d in details:
        print(f"  {d['name']:<25} {d['description']}")
    print()


def cmd_provision(scenario_name: str) -> None:
    ScenarioRegistry.discover()
    scenario_cls = ScenarioRegistry.get(scenario_name)
    scenario = scenario_cls()
    print(f"\nProvisioning scenario: {scenario_name}")
    print("=" * 60)
    provisioner = VagrantProvisioner(scenario.scenario_dir, scenario_name)
    success = provisioner.up()
    if success:
        print(f"\n  [+] Scenario '{scenario_name}' provisioned")
    else:
        print(f"\n  [!] Failed to provision '{scenario_name}'")
        sys.exit(1)


def cmd_validate(scenario_name: str) -> None:
    ScenarioRegistry.discover()
    scenario_cls = ScenarioRegistry.get(scenario_name)
    scenario = scenario_cls()

    print(f"\nValidating scenario: {scenario_name}")
    print("=" * 60)

    # Load expected findings
    expected_yaml = scenario.expected_yaml
    if not expected_yaml.exists():
        print(f"  [!] Expected findings file not found: {expected_yaml}")
        print(f"  [!] Run 'python run.py run {scenario_name}' to provision and scan first")
        sys.exit(1)

    expected = load_expected_yaml(expected_yaml)

    # Run scan
    provisioner = VagrantProvisioner(scenario.scenario_dir, scenario_name)
    runner = USAFRunner(provisioner)

    print("  [+] Installing/running USAF scan on VM...")
    runner.install_usaf()
    scan_result = runner.run_scan()
    findings = runner.get_findings(scan_result)

    print(f"  [+] Found {len(findings)} total findings from {scan_result.get('check_count', 0)} checks")

    # Validate
    validator = FindingsValidator(expected)
    result = validator.validate(findings)

    print_gap_report(result)
    return result


def cmd_run(scenario_name: str) -> None:
    ScenarioRegistry.discover()
    scenario_cls = ScenarioRegistry.get(scenario_name)
    scenario = scenario_cls()

    print(f"\nFull run: {scenario_name}")
    print("=" * 60)
    print("  Phase 1: Provision VM")
    provisioner = VagrantProvisioner(scenario.scenario_dir, scenario_name)
    provisioner.up()

    print("\n  Phase 2: Install USAF and scan")
    runner = USAFRunner(provisioner)
    runner.install_usaf()
    scan_result = runner.run_scan()
    findings = runner.get_findings(scan_result)
    print(f"  Found {len(findings)} findings")

    print("\n  Phase 3: Validate against expected findings")
    expected_yaml = scenario.expected_yaml
    if expected_yaml.exists():
        expected = load_expected_yaml(expected_yaml)
        validator = FindingsValidator(expected)
        result = validator.validate(findings)
        print_gap_report(result)
    else:
        print(f"  [!] No expected.yaml at {expected_yaml}")
        print("  [!] Run with findings as baseline to create expected.yaml")
        result = None

    print("\n  Phase 4: Cleanup")
    provisioner.destroy()
    print("  Done")
    return result


def cmd_destroy(scenario_name: str) -> None:
    ScenarioRegistry.discover()
    scenario_cls = ScenarioRegistry.get(scenario_name)
    scenario = scenario_cls()
    print(f"\nDestroying scenario: {scenario_name}")
    provisioner = VagrantProvisioner(scenario.scenario_dir, scenario_name)
    provisioner.destroy()
    print(f"  [+] Scenario '{scenario_name}' destroyed")


def cmd_run_all() -> None:
    ScenarioRegistry.discover()
    names = ScenarioRegistry.list_names()
    results: list[tuple[str, any]] = []

    for name in names:
        print(f"\n{'#' * 60}")
        print(f"  Running scenario: {name}")
        print(f"{'#' * 60}")
        try:
            result = cmd_run(name)
            if result:
                results.append((name, result))
        except Exception as e:
            print(f"  [!] Scenario '{name}' failed: {e}")
        time.sleep(2)

    print_validation_summary(results)


def cmd_install(scenario_name: str) -> None:
    ScenarioRegistry.discover()
    scenario_cls = ScenarioRegistry.get(scenario_name)
    scenario = scenario_cls()
    provisioner = VagrantProvisioner(scenario.scenario_dir, scenario_name)
    runner = USAFRunner(provisioner)
    runner.install_usaf()


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)

    command = sys.argv[1]

    if command == "list":
        cmd_list()
    elif command == "provision" and len(sys.argv) >= 3:
        cmd_provision(sys.argv[2])
    elif command == "validate" and len(sys.argv) >= 3:
        cmd_validate(sys.argv[2])
    elif command == "run" and len(sys.argv) >= 3:
        cmd_run(sys.argv[2])
    elif command == "destroy" and len(sys.argv) >= 3:
        cmd_destroy(sys.argv[2])
    elif command == "run-all":
        cmd_run_all()
    elif command == "install" and len(sys.argv) >= 3:
        cmd_install(sys.argv[2])
    else:
        print(f"Unknown command or missing argument: {command}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
