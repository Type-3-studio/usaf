from __future__ import annotations

import contextlib
import pwd
import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class SSHConfigCollector(BaseCollector):
    name = "ssh_config"
    description = "SSH server and client configuration parsing"

    def _do_collect(self) -> dict:
        return {
            "sshd_config": self._parse_sshd_config(),
            "ssh_config": self._parse_ssh_config(),
            "host_keys": self._list_host_keys(),
            "authorized_keys_dirs": self._scan_authorized_keys(),
            "sshd_binary": self._get_sshd_info(),
        }

    def _parse_sshd_config(self) -> dict:
        result: dict = {"lines": [], "directives": {}, "includes": [], "path": None}
        main = Path("/etc/ssh/sshd_config")
        if main.exists():
            result["path"] = str(main)
            try:
                for line in main.read_text().splitlines():
                    result["lines"].append(line)
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        parts = stripped.split(None, 1)
                        if len(parts) >= 2:
                            key = parts[0].lower()
                            val = parts[1]
                            if key == "include":
                                result["includes"].append(val)
                            elif key not in result["directives"]:
                                result["directives"][key] = val
                            elif isinstance(result["directives"][key], list):
                                result["directives"][key].append(val)
                            else:
                                result["directives"][key] = [result["directives"][key], val]
            except OSError:
                pass
        conf_d = Path("/etc/ssh/sshd_config.d")
        if conf_d.is_dir():
            try:
                for f in sorted(conf_d.iterdir()):
                    if f.suffix in (".conf",):
                        try:
                            content = f.read_text()
                            result["includes"].append(str(f))
                            for line in content.splitlines():
                                stripped = line.strip()
                                if stripped and not stripped.startswith("#"):
                                    parts = stripped.split(None, 1)
                                    if len(parts) >= 2:
                                        result["directives"][parts[0].lower()] = parts[1]
                        except OSError:
                            pass
            except OSError:
                pass
        return result

    def _parse_ssh_config(self) -> dict:
        result: dict = {"lines": [], "directives": {}, "path": None}
        paths: list[Path] = [Path("/etc/ssh/ssh_config")]
        home_ssh = Path.home() / ".ssh/config"
        if home_ssh.exists():
            paths.append(home_ssh)
        for cp in paths:
            if cp.exists():
                result["path"] = str(cp)
                try:
                    for line in cp.read_text().splitlines():
                        result["lines"].append(line)
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            parts = stripped.split(None, 1)
                            if len(parts) >= 2:
                                result["directives"][parts[0].lower()] = parts[1]
                except OSError:
                    pass
                break
        return result

    def _list_host_keys(self) -> list[dict]:
        keys: list[dict] = []
        key_dir = Path("/etc/ssh")
        if key_dir.is_dir():
            try:
                for f in key_dir.iterdir():
                    if f.name.startswith("ssh_host_") and f.name.endswith("_key"):
                        keys.append({
                            "name": f.name,
                            "path": str(f),
                            "type": f.name.replace("ssh_host_", "").replace("_key", ""),
                            "size": f.stat().st_size,
                            "modified": f.stat().st_mtime,
                        })
                    elif f.name.startswith("ssh_host_") and f.name.endswith("_key.pub"):
                        keys.append({
                            "name": f.name,
                            "path": str(f),
                            "type": f.name.replace("ssh_host_", "").replace("_key.pub", ""),
                            "public": True,
                            "size": f.stat().st_size,
                        })
            except OSError:
                pass
        return keys

    def _scan_authorized_keys(self) -> list[dict]:
        result: list[dict] = []
        try:
            for user in pwd.getpwall():
                if user.pw_dir and Path(user.pw_dir).exists():
                    ak = Path(user.pw_dir) / ".ssh" / "authorized_keys"
                    if ak.exists():
                        with contextlib.suppress(OSError):
                            result.append({
                                "user": user.pw_name,
                                "path": str(ak),
                                "key_count": len([entry for entry in ak.read_text().splitlines()
                                                  if entry.strip() and not entry.strip().startswith("#")]),
                                "modified": ak.stat().st_mtime,
                                "permissions": oct(ak.stat().st_mode),
                            })
        except ImportError:
            pass
        return result

    def _get_sshd_info(self) -> dict:
        result: dict = {"installed": False, "running": False, "version": None, "path": None}
        try:
            r = subprocess.run(
                ["which", "sshd"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode == 0:
                result["installed"] = True
                result["path"] = r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "ssh", "sshd"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["running"] = "active" in r.stdout
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["sshd", "--version"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            version_line = r.stderr.splitlines()[0] if r.stderr else r.stdout.splitlines()[0] if r.stdout else ""
            if version_line:
                result["version"] = version_line.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return result
