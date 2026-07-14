from __future__ import annotations

import contextlib
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class ProcessCollector(BaseCollector):
    """Collects running process information from /proc."""

    name = "processes"
    description = "Running processes, binary paths, and process metadata"

    def _do_collect(self) -> dict[str, list[dict[str, str | int | None]]]:
        return {
            "processes": self._list_processes(),
        }

    def _list_processes(self) -> list[dict[str, str | int | None]]:
        processes: list[dict[str, str | int | None]] = []
        proc = Path("/proc")
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            info = self._get_process_info(pid)
            if info:
                processes.append(info)
        return sorted(processes, key=lambda p: int(str(p["pid"])))

    def _get_process_info(self, pid: int) -> dict[str, str | int | None] | None:
        proc_dir = Path(f"/proc/{pid}")
        if not proc_dir.is_dir():
            return None

        try:
            status_lines = (proc_dir / "status").read_text().splitlines()
        except OSError:
            return None

        info: dict[str, str | int | None] = {
            "pid": pid,
            "name": None,
            "state": None,
            "ppid": None,
            "uid": None,
            "gid": None,
            "threads": None,
            "vm_rss_kb": None,
        }

        for line in status_lines:
            if line.startswith("Name:"):
                info["name"] = line.split(":", 1)[1].strip()
            elif line.startswith("State:"):
                info["state"] = line.split(":", 1)[1].strip()
            elif line.startswith("Ppid:"):
                info["ppid"] = int(line.split()[1])
            elif line.startswith("Uid:"):
                info["uid"] = int(line.split()[1])
            elif line.startswith("Gid:"):
                info["gid"] = int(line.split()[1])
            elif line.startswith("Threads:"):
                info["threads"] = int(line.split()[1])
            elif line.startswith("VmRSS:"):
                with contextlib.suppress(ValueError, IndexError):
                    info["vm_rss_kb"] = int(line.split()[1])

        try:
            cmdline = (proc_dir / "cmdline").read_bytes().replace(b"\x00", b" ").strip()
            info["cmdline"] = cmdline.decode("utf-8", errors="replace")
        except OSError:
            info["cmdline"] = None

        try:
            exe_path = (proc_dir / "exe").resolve()
            info["binary"] = str(exe_path)
        except OSError:
            info["binary"] = None

        return info
