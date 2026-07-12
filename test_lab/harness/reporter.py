from __future__ import annotations

import sys
from datetime import datetime

from test_lab.harness.validator import ValidationResult


def print_gap_report(result: ValidationResult) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'=' * 60}")
    print(f"  Gap Analysis Report — {result.scenario_name}")
    print(f"  {timestamp}")
    print(f"{'=' * 60}")
    print()
    print(result.summary)
    print()

    if result.missed:
        print(f"  Missed Findings ({len(result.missed)}):")
        print(f"  {'-' * 60}")
        for exp in result.missed:
            tags = f" [{', '.join(exp.tags)}]" if exp.tags else ""
            title = f" ({exp.title_contains})" if exp.title_contains else ""
            print(f"    ✗ {exp.check_id}{title}{tags}")
            if exp.severity:
                print(f"      Expected severity: {exp.severity}")
        print()

    if result.false_positives:
        print(f"  Potential False Positives ({len(result.false_positives)}):")
        print(f"  {'-' * 60}")
        for fp in result.false_positives[:10]:
            check_id = fp.get("_check_id", "?")
            title = fp.get("title", "?")
            sev = fp.get("severity", "?")
            print(f"    ? {check_id}: {title} [{sev}]")
        if len(result.false_positives) > 10:
            print(f"    ... and {len(result.false_positives) - 10} more")
        print()

    if result.matched:
        print(f"  Matched Findings ({len(result.matched)}):")
        print(f"  {'-' * 60}")
        for m in result.matched:
            exp = m["expected"]
            actual = m["actual"]
            print(f"    ✓ {exp.check_id} ({len(actual)} finding(s))")
        print()

    print(f"{'=' * 60}")
    status = "PASS" if result.passed else "FAIL"
    color = "" if result.passed else "  [!] "
    print(f"{color}Validation: {status} (detection rate: {result.detection_rate:.1%})")
    if result.missed:
        print(f"  {len(result.missed)} missed finding(s) to investigate")
    print(f"{'=' * 60}")
    print()


def print_validation_summary(results: list[tuple[str, ValidationResult]]) -> None:
    print(f"\n\n{'#' * 60}")
    print("  VALIDATION SUMMARY — ALL SCENARIOS")
    print(f"{'#' * 60}")
    print()

    passed = 0
    failed = 0
    for name, result in results:
        icon = "PASS" if result.passed else "FAIL"
        print(f"  [{icon}] {name}: {result.detection_rate:.1%} ({result.total_detected}/{result.total_expected})")
        if result.passed:
            passed += 1
        else:
            failed += 1
        if result.missed:
            for exp in result.missed:
                print(f"         ✗ {exp.check_id}")

    print()
    print(f"  Total: {passed} passed, {failed} failed")
    print(f"{'#' * 60}")
    print()

    if failed > 0:
        sys.exit(1)
