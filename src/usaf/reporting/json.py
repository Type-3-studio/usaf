from __future__ import annotations

import json
from typing import Any

from usaf.models.result import ScanResult
from usaf.models.score import ScanScore
from usaf.reporting.base import BaseReporter


class JSONReporter(BaseReporter):
    """Generates JSON output for machine consumption."""

    name = "json"
    description = "JSON-formatted report for CI/CD pipelines and automation"

    def generate(self, result: ScanResult, score: ScanScore | None = None, **_kwargs: Any) -> str:
        output: dict[str, Any] = {
            "usaf_version": result.metadata.usaf_version or "unknown",
            "scan": {
                "name": result.metadata.scan_name,
                "id": result.metadata.scan_id,
                "start_time": result.metadata.start_time.isoformat()
                if result.metadata.start_time
                else None,
                "end_time": result.metadata.end_time.isoformat()
                if result.metadata.end_time
                else None,
                "duration_seconds": result.metadata.duration_seconds,
            },
            "system": {
                "hostname": result.metadata.hostname,
                "os": result.metadata.os_info,
                "kernel": result.metadata.kernel_info,
            },
            "summary": {
                "total_checks": result.check_count,
                "passed": result.passed_count,
                "failed": result.failed_count,
                "total_findings": result.total_findings,
            },
        }

        if score:
            output["score"] = score.model_dump()

        if result.findings:
            enriched = self.enrich_findings(result.findings)
            output["findings"] = enriched

        if result.collectors_data:
            output["collectors"] = {k: v for k, v in result.collectors_data.items() if v}

        return json.dumps(output, indent=2, default=str)
