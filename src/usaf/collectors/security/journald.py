from __future__ import annotations

import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class JournaldCollector(BaseCollector):
    name = "journald"
    description = "Systemd journald configuration and log state"

    def _do_collect(self) -> dict:
        return {
            "config": self._parse_config(),
            "usage": self._get_journal_usage(),
            "persistence": self._check_persistence(),
            "log_files": self._list_log_files(),
        }

    def _parse_config(self) -> dict:
        result: dict = {
            "storage": None,
            "max_use": None,
            "keep_free": None,
            "max_file_size": None,
            "max_retention_sec": None,
            "sync_interval_sec": None,
            "compress": None,
            "forward_to_syslog": None,
            "forward_to_kmsg": None,
            "forward_to_console": None,
            "max_level_console": None,
        }
        config_paths = [
            "/etc/systemd/journald.conf",
            "/etc/systemd/journald.conf.d",
            "/run/systemd/journald.conf.d",
            "/usr/lib/systemd/journald.conf.d",
        ]
        for base in config_paths:
            bp = Path(base)
            if bp.is_file():
                self._parse_journald_conf(bp, result)
            elif bp.is_dir():
                try:
                    for f in sorted(bp.iterdir()):
                        if f.suffix == ".conf":
                            self._parse_journald_conf(f, result)
                except OSError:
                    pass
        return result

    def _parse_journald_conf(self, path: Path, result: dict) -> None:
        try:
            for line in path.read_text().splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    key, val = stripped.split("=", 1)
                    key = key.strip().lower()
                    val = val.strip()
                    if key == "storage":
                        result["storage"] = val.lower()
                    elif key == "systemmaxuse":
                        result["max_use"] = val
                    elif key == "systemkeepfree":
                        result["keep_free"] = val
                    elif key == "systemmaxfilesize":
                        result["max_file_size"] = val
                    elif key == "maxretentionsec":
                        result["max_retention_sec"] = val
                    elif key == "synceverysec":
                        result["sync_interval_sec"] = val
                    elif key == "compress":
                        result["compress"] = val.lower() == "yes"
                    elif key == "forwardtosyslog":
                        result["forward_to_syslog"] = val.lower() == "yes"
                    elif key == "forwardtokmsg":
                        result["forward_to_kmsg"] = val.lower() == "yes"
                    elif key == "forwardtoconsole":
                        result["forward_to_console"] = val.lower() == "yes"
                    elif key == "maxlevelconsole":
                        result["max_level_console"] = val.lower()
        except OSError:
            pass

    def _get_journal_usage(self) -> dict:
        result: dict = {
            "disk_usage_bytes": None,
            "oldest_entry": None,
            "newest_entry": None,
        }
        try:
            r = subprocess.run(
                ["journalctl", "--disk-usage"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            for line in r.stdout.splitlines():
                if "archived" in line and "used" in line:
                    import re
                    m = re.search(r"(\d+\.?\d*)\s*([KMGTP]?)", line)
                    if m:
                        result["disk_usage_bytes"] = line.strip()
                    break
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["journalctl", "--list-boots", "--no-pager"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            lines = r.stdout.splitlines()
            if len(lines) >= 2:
                parts = lines[-1].split()
                if len(parts) >= 3:
                    result["oldest_entry"] = f"{parts[2]} {parts[3] if len(parts) > 3 else ''}"
                parts = lines[1].split()
                if len(parts) >= 3:
                    result["newest_entry"] = f"{parts[2]} {parts[3] if len(parts) > 3 else ''}"
        except (OSError, subprocess.SubprocessError):
            pass
        return result

    def _check_persistence(self) -> dict:
        result: dict = {
            "persistent_logs": False,
            "runtime_logs_only": False,
            "log_dir_exists": False,
            "log_dir_size": None,
        }
        log_dir = Path("/var/log/journal")
        if log_dir.is_dir():
            result["log_dir_exists"] = True
            result["persistent_logs"] = True
            try:
                total = sum(f.stat().st_size for f in log_dir.rglob("*") if f.is_file())
                result["log_dir_size"] = total
            except OSError:
                pass
        else:
            runtime = Path("/run/systemd/journal")
            if runtime.is_dir():
                result["runtime_logs_only"] = True
        return result

    def _list_log_files(self) -> list[dict]:
        files: list[dict] = []
        for base in ["/var/log/journal", "/run/systemd/journal"]:
            bp = Path(base)
            if bp.is_dir():
                try:
                    for f in bp.rglob("*.journal"):
                        if f.is_file():
                            files.append({
                                "path": str(f),
                                "size": f.stat().st_size,
                                "modified": f.stat().st_mtime,
                            })
                except OSError:
                    pass
        return files
