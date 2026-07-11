from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.collectors.security.firewall import FirewallCollector


class TestFirewallCollector:
    def test_check_ufw_installed_and_active(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p).endswith("ufw"))

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "Status: active\nDefault: deny (incoming)\n"
            mock_run.return_value.returncode = 0
            collector = FirewallCollector()
            data = collector.collect()

        assert data["ufw"]["installed"] is True
        assert data["ufw"]["active"] is True
        assert data["ufw"]["default_policy"] == "deny (incoming)"

    def test_check_ufw_not_installed(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        collector = FirewallCollector()
        data = collector.collect()
        assert data["ufw"]["installed"] is False
        assert data["ufw"]["active"] is False

    def test_check_nftables_active(self, monkeypatch):
        def fake_exists(p):
            return str(p).endswith("nft")

        monkeypatch.setattr(Path, "exists", fake_exists)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "table inet filter {\n  chain input { type filter hook input priority 0; policy drop; }\n}\n"
            mock_run.return_value.returncode = 0
            collector = FirewallCollector()
            data = collector.collect()

        assert data["nftables"]["installed"] is True
        assert data["nftables"]["active"] is True

    def test_check_iptables_inactive(self, monkeypatch):
        def fake_exists(p):
            return str(p).endswith("iptables")

        monkeypatch.setattr(Path, "exists", fake_exists)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "Chain INPUT (policy ACCEPT)\n"
            mock_run.return_value.returncode = 0
            collector = FirewallCollector()
            data = collector.collect()

        assert data["iptables"]["installed"] is True
        assert data["iptables"]["active"] is False

    def test_handles_subprocess_error(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)

        with patch("subprocess.run", side_effect=OSError("not found")):
            collector = FirewallCollector()
            data = collector.collect()

        assert data["ufw"]["installed"] is True
        assert data["ufw"]["active"] is False
