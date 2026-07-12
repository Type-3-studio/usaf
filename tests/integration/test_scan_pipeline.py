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
    EXPECTED_CHECK_COUNT = 128

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
        assert check_ids == [
            "BOOT-101",
            "BOOT-201",
            "BOOT-301",
            "BOOT-401",
            "BOOT-501",
            "CLD-101",
            "CLD-102",
            "CLD-201",
            "CLD-301",
            "CLD-401",
            "CLD-501",
            "CMP-101",
            "COM-101",
            "CTN-101",
            "CTN-102",
            "CTN-201",
            "CTN-202",
            "CTN-203",
            "CTN-204",
            "CTN-301",
            "CTN-302",
            "CTN-401",
            "CTN-402",
            "FOR-101",
            "FS-101",
            "FS-102",
            "FS-201",
            "FS-202",
            "FS-301",
            "FS-302",
            "FS-401",
            "FS-402",
            "FS-403",
            "FS-501",
            "FW-101",
            "KERN-101",
            "KERN-201",
            "KERN-301",
            "KERN-401",
            "KERN-501",
            "LOG-101",
            "LOG-201",
            "LOG-301",
            "LOG-302",
            "LOG-401",
            "LOG-402",
            "LOG-501",
            "LOG-502",
            "LOG-503",
            "NET-101",
            "NET-201",
            "NET-301",
            "NET-302",
            "NET-401",
            "NET-402",
            "NET-501",
            "NET-550",
            "PER-101",
            "PER-102",
            "PER-103",
            "PER-201",
            "PER-202",
            "PER-203",
            "PER-204",
            "PER-301",
            "PER-302",
            "PER-303",
            "PER-401",
            "PER-402",
            "PER-403",
            "PER-501",
            "PER-502",
            "PER-503",
            "PER-601",
            "PER-602",
            "PER-603",
            "PER-701",
            "PER-702",
            "PER-801",
            "PER-802",
            "PER-803",
            "PER-804",
            "PER-805",
            "PKG-101",
            "PKG-201",
            "PKG-202",
            "PKG-210",
            "PKG-301",
            "PKG-302",
            "PKG-310",
            "PKG-401",
            "PKG-402",
            "PRM-101",
            "PRM-201",
            "PWD-101",
            "SEC-101",
            "SEC-102",
            "SECR-101",
            "SECR-102",
            "SECR-201",
            "SECR-202",
            "SECR-203",
            "SECR-301",
            "SECR-302",
            "SECR-401",
            "SECR-501",
            "SECR-502",
            "SSH-101",
            "SSH-102",
            "SSH-201",
            "SVC-101",
            "SVC-102",
            "SVC-201",
            "SVC-202",
            "SVC-301",
            "SVC-302",
            "SVC-401",
            "SVC-402",
            "USB-101",
            "USR-101",
            "USR-102",
            "USR-103",
            "USR-104",
            "USR-105",
            "USR-201",
            "USR-202",
            "USR-301",
            "USR-401",
        ]

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
