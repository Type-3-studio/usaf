from __future__ import annotations

from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class PAMCollector(BaseCollector):
    name = "pam"
    description = "PAM configuration files and module inventory"

    PAM_DIRS = [
        "/etc/pam.d",
        "/usr/share/pam-configs",
    ]

    def _do_collect(self) -> dict:
        return {
            "config_files": self._parse_pam_configs(),
            "modules": self._list_pam_modules(),
            "pam_auth_lines": self._get_critical_auth_lines(),
        }

    def _parse_pam_configs(self) -> list[dict]:
        configs: list[dict] = []
        for d in self.PAM_DIRS:
            dp = Path(d)
            if dp.is_dir():
                try:
                    for f in sorted(dp.iterdir()):
                        if f.is_file() and not f.name.startswith("."):
                            try:
                                content = f.read_text()
                            except OSError:
                                content = ""
                            configs.append({
                                "file": str(f),
                                "content": content,
                                "type": "pam-config" if "pam-configs" in d else "pam.d",
                            })
                except PermissionError:
                    pass
        return configs

    def _list_pam_modules(self) -> list[dict]:
        modules: list[dict] = []
        lib_dirs = ["/lib/x86_64-linux-gnu/security", "/lib/aarch64-linux-gnu/security", "/lib/security"]
        for d in lib_dirs:
            dp = Path(d)
            if dp.is_dir():
                try:
                    for f in dp.iterdir():
                        if f.is_file() and f.name.startswith("pam_"):
                            modules.append({
                                "name": f.name,
                                "path": str(f),
                                "modified": f.stat().st_mtime,
                            })
                except OSError:
                    pass
        return modules

    def _get_critical_auth_lines(self) -> list[str]:
        lines: list[str] = []
        for conf in ["/etc/pam.d/common-auth", "/etc/pam.d/common-password",
                       "/etc/pam.d/common-session", "/etc/pam.d/common-account"]:
            cp = Path(conf)
            if cp.exists():
                try:
                    for line in cp.read_text().splitlines():
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            lines.append(f"{conf}: {stripped}")
                except OSError:
                    pass
        return lines
