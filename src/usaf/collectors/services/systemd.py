from __future__ import annotations

import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class SystemdCollector(BaseCollector):
    """Collects systemd unit information."""

    name = "systemd"
    description = "Systemd services, timers, and socket units"

    def _do_collect(self) -> dict[str, list[dict[str, str | bool]]]:
        return {
            "services": self._list_units("service"),
            "timers": self._list_units("timer"),
            "sockets": self._list_units("socket"),
        }

    def _list_units(self, unit_type: str) -> list[dict[str, str | bool]]:
        units: list[dict[str, str | bool]] = []
        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "list-units",
                    "--type=" + unit_type,
                    "--all",
                    "--no-pager",
                    "--no-legend",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            for line in result.stdout.splitlines():
                parts = line.split(maxsplit=4)
                if len(parts) >= 4:
                    units.append(
                        {
                            "name": parts[0],
                            "load": parts[1],
                            "active": parts[2],
                            "sub": parts[3],
                            "description": parts[4] if len(parts) > 4 else "",
                        }
                    )
        except (OSError, subprocess.SubprocessError):
            pass
        return units

    def _parse_dropin(self, unit_name: str) -> dict[str, str] | None:
        """Read systemd drop-in configuration for a unit."""
        override_paths = [
            Path(f"/etc/systemd/system/{unit_name}.d/override.conf"),
            Path(f"/run/systemd/system/{unit_name}.d/override.conf"),
        ]
        for path in override_paths:
            if path.exists():
                try:
                    return {"path": str(path), "content": path.read_text()}
                except OSError:
                    continue
        return None


@register_collector
class CronCollector(BaseCollector):
    """Collects cron job configurations."""

    name = "cron"
    description = "Cron jobs from system crontabs and user crontabs"

    def _do_collect(self) -> dict[str, list[dict[str, str | None]]]:
        return {
            "system_crontab": self._parse_crontab("/etc/crontab"),
            "cron_dirs": self._parse_cron_dirs(),
            "user_crontabs": self._get_user_crontabs(),
        }

    def _parse_crontab(self, path: str) -> list[dict[str, str | None]]:
        entries: list[dict[str, str | None]] = []
        try:
            for line in Path(path).read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entries.append(
                    {
                        "file": path,
                        "content": line,
                    }
                )
        except OSError:
            pass
        return entries

    def _parse_cron_dirs(self) -> list[dict[str, str | None]]:
        entries: list[dict[str, str | None]] = []
        cron_dirs = [
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
            "/etc/cron.d",
        ]
        for cron_dir in cron_dirs:
            d = Path(cron_dir)
            if d.is_dir():
                try:
                    for f in sorted(d.iterdir()):
                        if f.is_file() and not f.name.startswith("."):
                            try:
                                content = f.read_text()
                            except OSError:
                                content = ""
                            entries.append(
                                {
                                    "file": str(f),
                                    "content": content,
                                }
                            )
                except PermissionError:
                    pass
        return entries

    def _get_user_crontabs(self) -> list[dict[str, str | None]]:
        entries: list[dict[str, str | None]] = []
        cron_dir = Path("/var/spool/cron/crontabs")
        if cron_dir.is_dir():
            try:
                for f in cron_dir.iterdir():
                    if f.is_file():
                        try:
                            content = f.read_text()
                        except OSError:
                            content = ""
                        entries.append(
                            {
                                "file": str(f),
                                "content": content,
                            }
                        )
            except PermissionError:
                pass
        return entries
