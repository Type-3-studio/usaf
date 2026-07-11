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


class TestPipelineErrorHandling:
    """Integration tests for error handling in the scan pipeline."""

    def test_runner_handles_empty_config(self):
        runner = ScanRunner()
        assert runner.config is not None

    def test_runner_discovery_counts(self):
        collector_registry.discover()
        check_ids = registry.get_all_ids()
        collector_names = collector_registry.get_all_names()
        assert len(collector_names) == 25
        assert len(check_ids) == 122

    @pytest.mark.slow
    @SKIP_LINUX
    def test_pipeline_with_empty_collector_data(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner()
            result = runner.run()
        assert isinstance(result, ScanResult)
        assert result.metadata.collector_count == 25

    @pytest.mark.slow
    @SKIP_LINUX
    def test_pipeline_handles_partial_collector_failures(self):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = RuntimeError("collector failed")
            runner = ScanRunner()
            result = runner.run()
        assert isinstance(result, ScanResult)
        assert len(result.metadata.errors) > 0

    @pytest.mark.slow
    @SKIP_LINUX
    def test_pipeline_parallel_flag_does_not_crash(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner()
            runner.config.general.parallel = True
            runner.config.general.max_workers = 4
            result = runner.run()
        assert isinstance(result, ScanResult)
        assert result.metadata.collector_count == 25

    @pytest.mark.slow
    @SKIP_LINUX
    def test_pipeline_scoring_with_partial_data(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner()
            result = runner.run()
        score = runner.score(result)
        assert isinstance(score, ScanScore)
        assert 0.0 <= score.overall_score <= 10.0
        assert score.total_findings == result.total_findings


class TestPipelineConfigIntegration:
    """Integration tests for config influencing the pipeline."""

    @pytest.mark.slow
    @SKIP_LINUX
    def test_runner_uses_config_path(self, tmp_path):
        config_file = tmp_path / "usaf.yaml"
        config_file.write_text("general:\n  scan_name: test-scan\n  parallel: false\nplugins:\n  enabled: ['*']\n  disabled: []\nignore: []\nsuid_allowlist: []\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner(str(config_file))
            result = runner.run()
        assert result.metadata.scan_name == "test-scan"


class TestPipelineCheckFiltering:
    """Integration tests for check filtering in the pipeline."""

    @pytest.mark.slow
    @SKIP_LINUX
    def test_disabled_check_not_executed(self, tmp_path):
        config_file = tmp_path / "usaf.yaml"
        config_file.write_text("general:\n  scan_name: filtered-test\n  parallel: false\nplugins:\n  enabled: ['*']\n  disabled: ['SSH-101', 'SSH-102']\nignore: []\nsuid_allowlist: []\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner(str(config_file))
            result = runner.run()
        check_ids = {r.check_id for r in result.results}
        assert "SSH-101" not in check_ids
        assert "SSH-102" not in check_ids
        assert "KERN-101" in check_ids

    @pytest.mark.slow
    @SKIP_LINUX
    def test_ignore_pattern_filters_findings(self, tmp_path):
        config_file = tmp_path / "usaf.yaml"
        config_file.write_text("general:\n  scan_name: ignore-test\n  parallel: false\nplugins:\n  enabled: ['*']\n  disabled: []\nignore: ['KERN-201-*']\nsuid_allowlist: []\n")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner(str(config_file))
            result = runner.run()
        for r in result.results:
            for f in r.findings:
                assert not f.id.startswith("KERN-201-")


class TestPipelineScoreConsistency:
    """Integration tests for score consistency across runs."""

    @pytest.mark.slow
    @SKIP_LINUX
    def test_runner_produces_valid_score(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = ""
            mock_run.return_value.returncode = 0
            runner = ScanRunner()
            result = runner.run()
            score = runner.score(result)
        assert 0.0 <= score.overall_score <= 10.0
        assert score.overall_grade in ("A+", "A", "B", "C", "D", "F", "F-")
        assert score.total_findings == result.total_findings
