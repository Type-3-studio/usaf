from __future__ import annotations

import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class FirewallCollector(BaseCollector):
    """Collects firewall status and rules."""

    name = "firewall"
    description = "UFW, nftables, and iptables status and rules"

    def _do_collect(self) -> dict:
        return {
            "ufw": self._check_ufw(),
            "nftables": self._check_nftables(),
            "iptables": self._check_iptables(),
        }

    def _check_ufw(self) -> dict:
        result: dict = {"installed": False, "active": False, "default_policy": None}
        ufw_path = Path("/usr/sbin/ufw")
        if not ufw_path.exists():
            return result
        result["installed"] = True
        try:
            r = subprocess.run(
                ["ufw", "status", "verbose"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["active"] = "Status: active" in r.stdout
            for line in r.stdout.splitlines():
                if "Default:" in line:
                    result["default_policy"] = line.split("Default:", 1)[1].strip()
            result["raw"] = r.stdout
        except (OSError, subprocess.SubprocessError):
            pass
        return result

    def _check_nftables(self) -> dict:
        result: dict = {"installed": False, "active": False, "rulesets": []}
        if not Path("/usr/sbin/nft").exists():
            return result
        result["installed"] = True
        try:
            r = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode == 0 and r.stdout.strip():
                result["active"] = True
                result["rulesets"] = [line.strip() for line in r.stdout.splitlines() if line.strip()]
        except (OSError, subprocess.SubprocessError):
            pass
        return result

    def _check_iptables(self) -> dict:
        result: dict = {"installed": False, "active": False, "rules": []}
        if not Path("/usr/sbin/iptables").exists():
            return result
        result["installed"] = True
        try:
            r = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode == 0:
                lines = [line for line in r.stdout.splitlines() if line.strip() and not line.startswith("Chain")]
                result["active"] = len(lines) > 0
                result["rules"] = lines
        except (OSError, subprocess.SubprocessError):
            pass
        return result
