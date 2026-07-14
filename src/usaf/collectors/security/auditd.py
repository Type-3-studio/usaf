from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class AuditdCollector(BaseCollector):
    """Collects audit daemon status, rules, and configuration."""

    name = "auditd"
    description = "Auditd service status, rules, and log statistics"

    def _do_collect(self) -> dict:
        return {
            "status": self._check_auditd_status(),
            "rules": self._get_rules(),
            "log_stats": self._get_log_stats(),
        }

    def _check_auditd_status(self) -> dict:
        result: dict = {
            "installed": False,
            "running": False,
            "enabled": False,
            "pid": None,
            "version": None,
        }
        auditd_path = Path("/usr/sbin/auditd")
        if not auditd_path.exists():
            return result
        result["installed"] = True
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "auditd"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["running"] = r.stdout.strip() == "active"
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["systemctl", "is-enabled", "auditd"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["enabled"] = r.stdout.strip() == "enabled"
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["auditctl", "-s"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if line.startswith("pid"):
                        result["pid"] = int(line.split("=", 1)[1].strip())
                    if line.startswith("version"):
                        result["version"] = line.split("=", 1)[1].strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return result

    def _get_rules(self) -> list[dict]:
        rules: list[dict] = []
        try:
            r = subprocess.run(
                ["auditctl", "-l"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode == 0:
                for raw_line in r.stdout.splitlines():
                    line = raw_line.strip()
                    if line:
                        rules.append({"rule": line, "source": "auditctl"})
        except (OSError, subprocess.SubprocessError):
            pass
        rules_file = Path("/etc/audit/rules.d/audit.rules")
        if rules_file.exists():
            try:
                content = rules_file.read_text()
                for raw_line in content.splitlines():
                    line = raw_line.strip()
                    if line and not line.startswith("#"):
                        rules.append({"rule": line, "source": str(rules_file)})
            except OSError:
                pass
        return rules

    def _get_log_stats(self) -> dict:
        stats: dict = {
            "log_exists": False,
            "log_size_bytes": None,
            "log_count": None,
        }
        audit_log = Path("/var/log/audit/audit.log")
        if audit_log.exists():
            stats["log_exists"] = True
            with contextlib.suppress(OSError):
                stats["log_size_bytes"] = audit_log.stat().st_size
        log_dir = Path("/var/log/audit")
        if log_dir.is_dir():
            try:
                log_files = sorted(log_dir.glob("audit.log*"))
                stats["log_count"] = len(log_files)
            except OSError:
                pass
        return stats
