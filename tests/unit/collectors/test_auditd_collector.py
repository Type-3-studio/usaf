from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.collectors.security.auditd import AuditdCollector


class TestAuditdCollector:
    def test_auditd_not_installed(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: False)
        collector = AuditdCollector()
        data = collector.collect()
        assert data["status"]["installed"] is False
        assert data["status"]["running"] is False

    def test_auditd_installed_and_running(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p).endswith("auditd"))

        with patch("subprocess.run") as mock_run:
            call_count = [0]

            def side_effect(cmd, **kwargs):
                call_count[0] += 1
                class MockResult:
                    returncode = 0
                    stdout = ""
                if "is-active" in cmd:
                    MockResult.stdout = "active\n"
                elif "is-enabled" in cmd:
                    MockResult.stdout = "enabled\n"
                elif "auditctl -s" in cmd or all(c in str(cmd) for c in ["auditctl", "-s"]):
                    MockResult.stdout = "pid=1234\nversion=3.1.2\n"
                elif "auditctl -l" in cmd or all(c in str(cmd) for c in ["auditctl", "-l"]):
                    MockResult.stdout = "-w /etc/passwd -p wa -k passwd_changes\n"
                return MockResult()
            mock_run.side_effect = side_effect

            collector = AuditdCollector()
            data = collector.collect()

        assert data["status"]["installed"] is True
        assert data["status"]["running"] is True
        assert data["status"]["enabled"] is True
        assert data["status"]["pid"] == 1234
        assert data["status"]["version"] == "3.1.2"
        assert len(data["rules"]) >= 1

    def test_audit_rules_from_file(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p).endswith("auditd") or "audit.rules" in str(p))
        monkeypatch.setattr(Path, "read_text", lambda _: "-w /etc/shadow -p wa -k shadow_changes\n")
        monkeypatch.setattr(Path, "is_dir", lambda _: False)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            collector = AuditdCollector()
            data = collector.collect()

        assert len(data["rules"]) >= 1
        assert any("shadow_changes" in r["rule"] for r in data["rules"])

    def test_log_stats(self, monkeypatch):
        def fake_exists(p):
            s = str(p)
            return "auditd" in s or "audit.log" in s or "audit" in s

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(Path, "is_dir", lambda p: str(p).endswith("audit"))
        monkeypatch.setattr(Path, "glob", lambda p, pattern: [Path("/var/log/audit/audit.log")])
        monkeypatch.setattr(Path, "stat", lambda _: type("Stat", (), {"st_size": 65536})())

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            collector = AuditdCollector()
            data = collector.collect()

        assert data["log_stats"]["log_exists"] is True
        assert data["log_stats"]["log_size_bytes"] == 65536
        assert data["log_stats"]["log_count"] == 1

    def test_handles_subprocess_error(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p).endswith("auditd"))
        with patch("subprocess.run", side_effect=OSError("not found")):
            collector = AuditdCollector()
            data = collector.collect()

        assert data["status"]["installed"] is True
        assert data["status"]["running"] is False

    def test_not_enabled(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p).endswith("auditd"))

        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                class MockResult:
                    returncode = 0
                    stdout = ""
                if "is-active" in cmd:
                    MockResult.stdout = "inactive\n"
                elif "is-enabled" in cmd:
                    MockResult.stdout = "disabled\n"
                return MockResult()
            mock_run.side_effect = side_effect

            collector = AuditdCollector()
            data = collector.collect()

        assert data["status"]["running"] is False
        assert data["status"]["enabled"] is False
