from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector

SNAP_DIR = Path("/snap")
SNAPD_DATA_DIR = Path("/var/lib/snapd/snap")

_snap_root_cache: set[str] | None = None


def _build_snap_root_cache() -> set[str]:
    roots: set[str] = set()
    for base_dir in (SNAP_DIR, SNAPD_DATA_DIR):
        if not base_dir.is_dir():
            continue
        try:
            for snap_dir in base_dir.iterdir():
                if not snap_dir.is_dir():
                    continue
                current = snap_dir / "current"
                try:
                    target = os.path.realpath(str(current))
                    if os.path.isdir(target):
                        roots.add(target)
                except OSError:
                    for child in snap_dir.iterdir():
                        if child.is_dir():
                            roots.add(str(child.resolve()))
                            break
        except PermissionError:
            continue
    return roots


def get_snap_package_for_file(filepath: str) -> str | None:
    global _snap_root_cache
    if _snap_root_cache is None:
        _snap_root_cache = _build_snap_root_cache()
    resolved = os.path.realpath(filepath)
    for root in _snap_root_cache:
        if resolved.startswith(root):
            parts = resolved[len(root):].lstrip("/").split("/")
            snap_name = parts[0] if parts else None
            if snap_name:
                return f"snap:{snap_name}"
    return None


@register_collector
class SnapCollector(BaseCollector):
    name = "snap"
    description = "Snap package inventory"

    def _do_collect(self) -> dict[str, Any]:
        installed: list[dict[str, str]] = []
        for base_dir in (SNAP_DIR, SNAPD_DATA_DIR):
            if not base_dir.is_dir():
                continue
            try:
                for snap_dir in base_dir.iterdir():
                    if not snap_dir.is_dir():
                        continue
                    snap_name = snap_dir.name
                    revisions: list[str] = []
                    current_target = ""
                    try:
                        for child in snap_dir.iterdir():
                            if child.is_dir():
                                revisions.append(child.name)
                    except PermissionError:
                        pass
                    current = snap_dir / "current"
                    try:
                        if current.is_symlink():
                            current_target = os.path.basename(os.path.realpath(str(current)))
                    except OSError:
                        pass
                    installed.append({
                        "name": snap_name,
                        "revisions": ",".join(revisions),
                        "current_revision": current_target,
                    })
            except PermissionError:
                continue
        return {"installed": installed}
