from __future__ import annotations

import os
import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector

_file_owner_cache: dict[str, str] | None = None


def _build_file_owner_cache() -> dict[str, str]:
    """Build a mapping of file path → package name from dpkg info database.

    Reads /var/lib/dpkg/info/*.list files which list every file owned by
    each installed package. This is more efficient and more Pythonic than
    shelling out to ``dpkg -S`` for each file.
    """
    cache: dict[str, str] = {}
    info_dir = Path("/var/lib/dpkg/info")
    if not info_dir.is_dir():
        return cache
    for list_file in sorted(info_dir.glob("*.list")):
        package_name = list_file.stem
        try:
            for line in list_file.read_text().splitlines():
                cache[line.rstrip("/")] = package_name
        except OSError:
            continue
    return cache


def get_package_for_file(filepath: str) -> str | None:
    """Return the dpkg package name that owns *filepath*, or *None*.

    Lazily builds a full file→package mapping on first call.  Subsequent
    calls are O(1) dict lookups.
    """
    global _file_owner_cache
    if _file_owner_cache is None:
        _file_owner_cache = _build_file_owner_cache()
    real_path = os.path.realpath(filepath)
    return _file_owner_cache.get(real_path.rstrip("/"))


@register_collector
class APTCollector(BaseCollector):
    """Collects APT package information, repositories, and available updates."""

    name = "apt"
    description = "Installed packages, repositories, and available updates"

    def _do_collect(self) -> dict[str, list[dict[str, str | bool | None]]]:
        return {
            "packages": self._get_installed_packages(),
            "repositories": self._get_repositories(),
            "updates": self._get_available_updates(),
        }

    def _get_installed_packages(self) -> list[dict[str, str | bool | None]]:
        packages: list[dict[str, str | bool | None]] = []
        try:
            result = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\t${Architecture}\n"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 4:
                    status = parts[2]
                    packages.append(
                        {
                            "name": parts[0],
                            "version": parts[1],
                            "status": status,
                            "architecture": parts[3],
                            "is_update_available": None,
                        }
                    )
        except (OSError, subprocess.SubprocessError):
            pass
        return packages

    def _get_repositories(self) -> list[dict[str, str | bool | None]]:
        repos: list[dict[str, str | bool | None]] = []
        sources_dir = Path("/etc/apt")
        try:
            for sources_file in sources_dir.rglob("*.list"):
                if not sources_file.is_file():
                    continue
                for line in sources_file.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("deb ") or line.startswith("deb-src "):
                        parts = line.split()
                        if len(parts) >= 3:
                            repos.append(
                                {
                                    "type": parts[0],
                                    "url": parts[1],
                                    "suite": parts[2] if len(parts) > 2 else "",
                                    "components": " ".join(parts[3:]),
                                    "source": str(sources_file),
                                    "enabled": True,
                                }
                            )
        except OSError:
            pass
        return repos

    def _get_available_updates(self) -> list[dict[str, str | bool | None]]:
        updates: list[dict[str, str | bool | None]] = []
        try:
            result = subprocess.run(
                ["apt-get", "--just-print", "upgrade"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            for line in result.stdout.splitlines():
                if "Inst " in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        updates.append(
                            {
                                "name": parts[1],
                                "old_version": None,
                                "new_version": parts[2].strip("[]") if len(parts) > 2 else None,
                            }
                        )
        except (OSError, subprocess.SubprocessError):
            pass
        return updates
