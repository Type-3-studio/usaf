from __future__ import annotations

import tempfile
from pathlib import Path

from usaf.checks.secrets.env_files import EnvFilesCheck


class TestEnvFilesCheck:
    def test_no_findings_when_no_env_files(self):
        check = EnvFilesCheck()
        collectors = {"secrets": {"scanned_dirs": ["/tmp"]}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_empty_scanned_dirs(self):
        check = EnvFilesCheck()
        collectors = {"secrets": {"scanned_dirs": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_skips_non_home_dirs(self):
        check = EnvFilesCheck()
        collectors = {"secrets": {"scanned_dirs": ["/var", "/etc"]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_check_env_file_sensitive_keys(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("DB_PASSWORD=super_secret\n")
            f.write("API_KEY=sk-1234567890abcdef\n")
            f.write("NODE_ENV=production\n")
            fname = f.name
        try:
            sensitive = EnvFilesCheck._check_env_file(fname)
            assert "db_password" in sensitive
            assert "api_key" in sensitive
            assert "node_env" not in sensitive
        finally:
            Path(fname).unlink(missing_ok=True)

    def test_check_env_file_empty_values(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("EMPTY_KEY=\n")
            f.write("API_KEY=\n")
            fname = f.name
        try:
            sensitive = EnvFilesCheck._check_env_file(fname)
            assert len(sensitive) == 0
        finally:
            Path(fname).unlink(missing_ok=True)

    def test_check_id(self):
        assert EnvFilesCheck.id == "SECR-202"
