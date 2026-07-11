from __future__ import annotations

import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector


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
                capture_output=True, text=True, timeout=30, check=False,
            )
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 4:
                    status = parts[2]
                    packages.append({
                        "name": parts[0],
                        "version": parts[1],
                        "status": status,
                        "architecture": parts[3],
                        "is_update_available": None,
                    })
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
                            repos.append({
                                "type": parts[0],
                                "url": parts[1],
                                "suite": parts[2] if len(parts) > 2 else "",
                                "components": " ".join(parts[3:]),
                                "source": str(sources_file),
                                "enabled": True,
                            })
        except OSError:
            pass
        return repos

    def _get_available_updates(self) -> list[dict[str, str | bool | None]]:
        updates: list[dict[str, str | bool | None]] = []
        try:
            result = subprocess.run(
                ["apt-get", "--just-print", "upgrade"],
                capture_output=True, text=True, timeout=60, check=False,
            )
            for line in result.stdout.splitlines():
                if "Inst " in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        updates.append({
                            "name": parts[1],
                            "old_version": None,
                            "new_version": parts[2].strip("[]") if len(parts) > 2 else None,
                        })
        except (OSError, subprocess.SubprocessError):
            pass
        return updates
