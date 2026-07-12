from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from test_lab.scenarios.base import ExpectedFinding, ExpectedFindings


def load_expected_yaml(path: Path) -> ExpectedFindings:
    with open(path) as f:
        data: dict[str, Any] = yaml.safe_load(f)

    findings = [
        ExpectedFinding(
            check_id=f["check_id"],
            finding_id=f.get("finding_id"),
            title_contains=f.get("title_contains"),
            severity=f.get("severity"),
            count_min=f.get("count_min", 1),
            count_max=f.get("count_max"),
            tags=f.get("tags", []),
        )
        for f in data.get("expected_findings", [])
    ]

    return ExpectedFindings(
        scenario=data.get("scenario", path.stem),
        description=data.get("description", ""),
        expected_findings=findings,
        minimum_detection_rate=data.get("minimum_detection_rate", 0.9),
        notes=data.get("notes"),
    )
