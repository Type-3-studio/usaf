from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.collectors.services.systemd import CronCollector, SystemdCollector

FAKE_SYSTEMCTL = """\
 ssh.service                    loaded    active   running   OpenSSH server
 ufw.service                    loaded    active   exited    Uncomplicated firewall
 cron.service                   loaded    inactive dead      Regular background program
"""


class TestSystemdCollector:
    def test_list_units(self):
        collector = SystemdCollector()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = FAKE_SYSTEMCTL
            mock_run.return_value.returncode = 0
            data = collector.collect()

        assert len(data["services"]) == 3
        assert data["services"][0]["name"] == "ssh.service"
        assert data["services"][0]["active"] == "active"
        assert data["services"][1]["name"] == "ufw.service"
        assert data["services"][2]["active"] == "inactive"

    def test_handles_subprocess_error(self):
        collector = SystemdCollector()
        with patch("subprocess.run", side_effect=OSError("not found")):
            data = collector.collect()
        assert data["services"] == []


class TestCronCollector:
    FAKE_CRONTAB = """\
# Test file
0 5 * * 1 root apt update
30 2 * * * root /usr/bin/security-check
"""

    FAKE_CRON_DAILY = """\
#!/bin/bash
/usr/sbin/logrotate
"""

    def test_parse_crontab(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: self.FAKE_CRONTAB)
        collector = CronCollector()
        data = collector.collect()

        assert len(data["system_crontab"]) == 2
        assert "apt update" in data["system_crontab"][0]["content"]

    def test_parse_cron_dirs(self, monkeypatch):
        def fake_is_dir(p):
            return str(p).endswith("cron.daily")

        class FakeEntry:
            name = "logrotate"
            is_file = lambda self: True
            def __str__(self):
                return "/etc/cron.daily/logrotate"
            def read_text(self):
                return self.FAKE_CRON_DAILY
        FakeEntry.FAKE_CRON_DAILY = self.FAKE_CRON_DAILY

        def fake_iterdir(_):
            return [FakeEntry()]

        monkeypatch.setattr(Path, "is_dir", fake_is_dir)
        monkeypatch.setattr(Path, "iterdir", fake_iterdir)

        collector = CronCollector()
        data = collector.collect()

        assert len(data["cron_dirs"]) >= 1
        assert "logrotate" in data["cron_dirs"][0]["file"]

    def test_handles_os_error(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: (_ for _ in ()).throw(OSError))
        monkeypatch.setattr(Path, "is_dir", lambda _: False)

        collector = CronCollector()
        data = collector.collect()
        assert data["system_crontab"] == []
