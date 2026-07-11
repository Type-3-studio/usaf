from __future__ import annotations

from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class MountCollector(BaseCollector):
    """Collects filesystem mount information."""

    name = "mounts"
    description = "Mounted filesystems and fstab entries"

    def _do_collect(self) -> dict:
        return {
            "mounts": self._parse_mounts(),
            "fstab": self._parse_fstab(),
            "disk_usage": self._get_disk_usage(),
        }

    def _parse_mounts(self) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        try:
            for line in Path("/proc/mounts").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    entries.append({
                        "device": parts[0],
                        "mount_point": parts[1],
                        "fstype": parts[2],
                        "options": parts[3],
                    })
        except OSError:
            pass
        return entries

    def _parse_fstab(self) -> list[dict[str, str]]:
        entries: list[dict[str, str]] = []
        try:
            for raw in Path("/etc/fstab").read_text().splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    entries.append({
                        "device": parts[0],
                        "mount_point": parts[1],
                        "fstype": parts[2],
                        "options": parts[3],
                        "dump": parts[4] if len(parts) > 4 else "0",
                        "pass": parts[5] if len(parts) > 5 else "0",
                    })
        except OSError:
            pass
        return entries

    def _get_disk_usage(self) -> dict[str, float]:
        usage: dict[str, float] = {}
        try:
            for line in Path("/proc/self/mountinfo").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    mount_point = parts[4]
                    try:
                        s = Path(mount_point).stat()
                        usage[mount_point] = s.st_size
                    except OSError:
                        continue
        except OSError:
            pass
        return usage
