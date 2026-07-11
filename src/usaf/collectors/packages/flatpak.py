from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector

FLATPAK_BASE = Path("/var/lib/flatpak")

_flatpak_root_cache: set[str] | None = None


def _build_flatpak_root_cache() -> set[str]:
    roots: set[str] = set()
    if not FLATPAK_BASE.is_dir():
        return roots
    for kind in ("app", "runtime"):
        kind_dir = FLATPAK_BASE / kind
        if not kind_dir.is_dir():
            continue
        try:
            for app_dir in kind_dir.iterdir():
                if not app_dir.is_dir():
                    continue
                _walk_flatpak_branches(app_dir, roots)
        except PermissionError:
            continue
    return roots


def _walk_flatpak_branches(app_dir: Path, roots: set[str]) -> None:
    try:
        for arch_dir in app_dir.iterdir():
            if not arch_dir.is_dir():
                continue
            for branch_dir in arch_dir.iterdir():
                if not branch_dir.is_dir():
                    continue
                _add_active_deploy(branch_dir, roots)
    except PermissionError:
        pass


def _add_active_deploy(branch_dir: Path, roots: set[str]) -> None:
    active_file = branch_dir / "active"
    deploy_dir: Path | None = None
    try:
        if active_file.is_file():
            commit = active_file.read_text().strip()
            if commit:
                deploy_dir = branch_dir / commit / "files"
        elif branch_dir / "files" in branch_dir.iterdir():
            deploy_dir = branch_dir / "files"
        if deploy_dir and deploy_dir.is_dir():
            roots.add(str(deploy_dir.resolve()))
    except OSError:
        pass


def get_flatpak_package_for_file(filepath: str) -> str | None:
    global _flatpak_root_cache
    if _flatpak_root_cache is None:
        _flatpak_root_cache = _build_flatpak_root_cache()
    resolved = os.path.realpath(filepath)
    for root in _flatpak_root_cache:
        if resolved.startswith(root):
            parts = resolved[len(root):].lstrip("/").split("/")
            app_id = parts[0] if parts else None
            if app_id:
                return f"flatpak:{app_id}"
    return None


@register_collector
class FlatpakCollector(BaseCollector):
    name = "flatpak"
    description = "Flatpak application and runtime inventory"

    def _do_collect(self) -> dict[str, Any]:
        installed: list[dict[str, str]] = []
        if not FLATPAK_BASE.is_dir():
            return {"installed": installed}

        for kind in ("app", "runtime"):
            kind_dir = FLATPAK_BASE / kind
            if not kind_dir.is_dir():
                continue
            try:
                for app_dir in kind_dir.iterdir():
                    if not app_dir.is_dir():
                        continue
                    self._collect_app(app_dir, kind, installed)
            except PermissionError:
                continue

        return {"installed": installed}

    def _collect_app(self, app_dir: Path, kind: str, installed: list[dict[str, str]]) -> None:
        try:
            for arch_dir in app_dir.iterdir():
                if not arch_dir.is_dir():
                    continue
                for branch_dir in arch_dir.iterdir():
                    if not branch_dir.is_dir():
                        continue
                    active_commit = ""
                    active_file = branch_dir / "active"
                    try:
                        if active_file.is_file():
                            active_commit = active_file.read_text().strip()
                    except OSError:
                        pass
                    installed.append({
                        "id": app_dir.name,
                        "kind": kind,
                        "arch": arch_dir.name,
                        "branch": branch_dir.name,
                        "active_commit": active_commit,
                    })
        except PermissionError:
            pass
