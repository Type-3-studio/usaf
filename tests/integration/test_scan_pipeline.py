from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from usaf.collectors.registry import collector_registry
from usaf.core.registry import registry
from usaf.core.runner import ScanRunner
from usaf.models.result import ScanResult
from usaf.models.score import ScanScore

SKIP_LINUX = pytest.mark.skipif(
    not os.path.exists("/proc"),
    reason="Requires /proc filesystem (Linux)",
)


class TestScanPipeline:
    """Integration tests for the full scan pipeline."""

    EXPECTED_COLLECTOR_COUNT = 26
    EXPECTED_CHECK_COUNT = 389

    def test_collector_discovery_registers_all(self):
        collector_registry.discover()
        names = sorted(collector_registry.get_all_names())
        assert len(names) == self.EXPECTED_COLLECTOR_COUNT
        assert names == [
            "apt",
            "auditd",
            "boot",
            "certificates",
            "cloud",
            "containers",
            "cron",
            "dns",
            "filesystem",
            "firewall",
            "flatpak",
            "groups",
            "interfaces",
            "journald",
            "kernel",
            "kernel_params",
            "mounts",
            "pam",
            "processes",
            "secrets",
            "snap",
            "sockets",
            "ssh_config",
            "sudo",
            "systemd",
            "users",
        ]

    def test_check_discovery_registers_all(self):
        check_ids = sorted(registry.get_all_ids())
        assert len(check_ids) == self.EXPECTED_CHECK_COUNT
        assert all(isinstance(cid, str) and "-" in cid for cid in check_ids)

    @pytest.mark.slow
    @SKIP_LINUX
    def test_full_pipeline_runs_without_error(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner()
            result = runner.run()
        assert result is not None

    @pytest.mark.slow
    @SKIP_LINUX
    def test_runner_returns_scan_result(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner()
            result = runner.run()
        assert isinstance(result, ScanResult)
        assert result.metadata is not None
        assert result.metadata.hostname != ""
        assert result.metadata.os_info != ""
        assert result.metadata.collector_count == self.EXPECTED_COLLECTOR_COUNT
        assert len(result.results) >= 1
        assert result.total_findings >= 0

    @pytest.mark.slow
    @SKIP_LINUX
    def test_scoring_produces_valid_score(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner()
            result = runner.run()
        score = runner.score(result)
        assert isinstance(score, ScanScore)
        assert 0.0 <= score.overall_score <= 10.0
        assert score.overall_grade in ("A+", "A", "B", "C", "D", "F", "F-")
        assert score.total_findings >= 0
        assert score.total_findings == result.total_findings
