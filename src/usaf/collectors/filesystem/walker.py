from __future__ import annotations

import os
import stat as stat_module
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class FilesystemCollector(BaseCollector):
    name = "filesystem"
    description = "Filesystem walker for SUID, world-writable files, capabilities, and hidden files"

    SUID_PATHS = [
        "/bin", "/sbin", "/usr/bin", "/usr/sbin",
        "/usr/local/bin", "/usr/local/sbin",
    ]
    WW_PATHS = [
        "/etc", "/home", "/opt", "/tmp", "/var",
    ]
    CAPS_PATHS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    HIDDEN_PATHS = ["/etc", "/home", "/opt"]

    def _do_collect(self) -> dict:
        return {
            "suid_files": self._find_suid(),
            "world_writable": self._find_world_writable(),
            "capabilities": self._find_capabilities(),
            "hidden_entries": self._find_hidden(),
            "etc_snapshots": self._snapshot_etc(),
            "path_executables": self._check_path_dirs(),
        }

    def _walk_files(self, paths: list[str], max_files: int = 50000) -> list[Path]:
        files: list[Path] = []
        for base in paths:
            bp = Path(base)
            if not bp.is_dir():
                continue
            try:
                for root, dirs, names in os.walk(str(bp)):
                    root_p = Path(root)
                    if _is_virtual_fs(root_p):
                        dirs.clear()
                        continue
                    for name in names:
                        full = root_p / name
                        try:
                            if full.is_file() and not full.is_symlink():
                                files.append(full)
                                if len(files) >= max_files:
                                    return files
                        except OSError:
                            continue
                    if len(files) >= max_files:
                        return files
            except PermissionError:
                continue
        return files

    def _find_suid(self) -> list[dict]:
        results: list[dict] = []
        for base in self.SUID_PATHS:
            bp = Path(base)
            if not bp.is_dir():
                continue
            try:
                for root, dirs, names in os.walk(str(bp)):
                    root_p = Path(root)
                    if _is_virtual_fs(root_p):
                        dirs.clear()
                        continue
                    for name in names:
                        full = root_p / name
                        try:
                            st = full.lstat()
                            if st.st_mode & (stat_module.S_ISUID | stat_module.S_ISGID):
                                results.append({
                                    "path": str(full),
                                    "mode": oct(st.st_mode),
                                    "uid": st.st_uid,
                                    "gid": st.st_gid,
                                    "size": st.st_size,
                                    "modified": st.st_mtime,
                                })
                        except OSError:
                            continue
            except PermissionError:
                continue
        return results

    def _find_world_writable(self) -> list[dict]:
        results: list[dict] = []
        checked: set[str] = set()
        for base in self.WW_PATHS:
            bp = Path(base)
            if not bp.is_dir():
                continue
            try:
                for root, dirs, names in os.walk(str(bp)):
                    root_p = Path(root)
                    if _is_virtual_fs(root_p):
                        dirs.clear()
                        continue
                    for name in names + dirs:
                        full = root_p / name
                        try:
                            sp = str(full)
                            if sp in checked:
                                continue
                            checked.add(sp)
                            st = full.lstat()
                            if full.is_symlink():
                                continue
                            if st.st_mode & stat_module.S_IWOTH:
                                results.append({
                                    "path": sp,
                                    "mode": oct(st.st_mode),
                                    "uid": st.st_uid,
                                    "gid": st.st_gid,
                                    "is_dir": full.is_dir(),
                                    "is_symlink": False,
                                    "size": st.st_size if full.is_file() else None,
                                    "modified": st.st_mtime,
                                })
                        except OSError:
                            continue
            except PermissionError:
                continue
        return results

    def _find_capabilities(self) -> list[dict]:
        results: list[dict] = []
        for f in self._walk_files(self.CAPS_PATHS, max_files=20000):
            try:
                import subprocess
                r = subprocess.run(
                    ["getcap", str(f)],
                    capture_output=True, text=True, timeout=5, check=False,
                )
                if r.stdout.strip():
                    results.append({
                        "path": str(f),
                        "capabilities": r.stdout.strip(),
                    })
            except (OSError, subprocess.SubprocessError):
                pass
        return results

    def _find_hidden(self) -> list[dict]:
        results: list[dict] = []
        for base in self.HIDDEN_PATHS:
            bp = Path(base)
            if not bp.is_dir():
                continue
            try:
                for entry in bp.iterdir():
                    if entry.name.startswith(".") and entry.name not in (".", ".."):
                        try:
                            st = entry.lstat()
                            results.append({
                                "path": str(entry),
                                "name": entry.name,
                                "type": "dir" if entry.is_dir() else "file",
                                "mode": oct(st.st_mode),
                                "uid": st.st_uid,
                                "size": st.st_size if entry.is_file() else None,
                                "modified": st.st_mtime,
                            })
                        except OSError:
                            continue
            except PermissionError:
                continue
        return results

    def _snapshot_etc(self) -> dict:
        result: dict = {"files": [], "total": 0}
        etc = Path("/etc")
        if not etc.is_dir():
            return result
        try:
            for entry in sorted(etc.iterdir()):
                try:
                    st = entry.lstat()
                    info = {
                        "name": entry.name,
                        "path": str(entry),
                        "mode": oct(st.st_mode),
                        "uid": st.st_uid,
                        "gid": st.st_gid,
                        "size": st.st_size,
                        "modified": st.st_mtime,
                        "is_file": entry.is_file(),
                        "is_dir": entry.is_dir(),
                        "is_symlink": entry.is_symlink(),
                    }
                    result["files"].append(info)
                    result["total"] += 1
                except OSError:
                    continue
        except PermissionError:
            pass
        return result

    def _check_path_dirs(self) -> list[dict]:
        results: list[dict] = []
        path = os.environ.get("PATH", "/usr/bin:/bin")
        for d in path.split(":"):
            dp = Path(d)
            if not dp.is_dir():
                continue
            try:
                for f in dp.iterdir():
                    if f.is_file() and os.access(str(f), os.X_OK):
                        try:
                            st = f.stat()
                            results.append({
                                "path": str(f),
                                "mode": oct(st.st_mode),
                                "uid": st.st_uid,
                                "gid": st.st_gid,
                                "size": st.st_size,
                                "modified": st.st_mtime,
                            })
                        except OSError:
                            continue
            except PermissionError:
                continue
        return results


def _is_virtual_fs(path: Path) -> bool:
    name = path.name
    return name in (
        "proc", "sys", "dev", "run", "snap", "lost+found",
    ) or name.startswith(".")
