from __future__ import annotations

from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class UserCollector(BaseCollector):
    """Collects user account information from /etc/passwd and /etc/shadow."""

    name = "users"
    description = "User accounts from /etc/passwd and /etc/shadow"

    def _do_collect(self) -> dict[str, list[dict[str, str | int | None]]]:
        return {
            "users": self._parse_passwd(),
            "shadow": self._parse_shadow(),
        }

    def _parse_passwd(self) -> list[dict[str, str | int | None]]:
        users: list[dict[str, str | int | None]] = []
        try:
            for line in Path("/etc/passwd").read_text().splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 7:
                    users.append(
                        {
                            "username": parts[0],
                            "password": parts[1],
                            "uid": int(parts[2]),
                            "gid": int(parts[3]),
                            "gecos": parts[4],
                            "home": parts[5],
                            "shell": parts[6],
                        }
                    )
        except OSError:
            pass
        return users

    def _parse_shadow(self) -> list[dict[str, str | int | None]]:
        accounts: list[dict[str, str | int | None]] = []
        try:
            for line in Path("/etc/shadow").read_text().splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 9:
                    account: dict[str, str | int | None] = {
                        "username": parts[0],
                        "password_hash": parts[1],
                        "last_changed": int(parts[2]) if parts[2] else None,
                        "min_days": int(parts[3]) if parts[3] else None,
                        "max_days": int(parts[4]) if parts[4] else None,
                        "warn_days": int(parts[5]) if parts[5] else None,
                        "inactive_days": int(parts[6]) if parts[6] else None,
                        "expire_date": int(parts[7]) if parts[7] else None,
                    }
                    if account["password_hash"] in ("!", "!?", "*"):
                        account["locked"] = True
                    elif account["password_hash"] in ("", None):
                        account["locked"] = None
                    else:
                        account["locked"] = False
                    accounts.append(account)
        except OSError:
            pass
        return accounts


@register_collector
class GroupCollector(BaseCollector):
    """Collects group information from /etc/group."""

    name = "groups"
    description = "Group memberships from /etc/group"

    def _do_collect(self) -> dict[str, list[dict[str, str | int | list[str]]]]:
        return {"groups": self._parse_groups()}

    def _parse_groups(self) -> list[dict[str, str | int | list[str]]]:
        groups: list[dict[str, str | int | list[str]]] = []
        try:
            for line in Path("/etc/group").read_text().splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 4:
                    members = parts[3].split(",") if parts[3] else []
                    groups.append(
                        {
                            "name": parts[0],
                            "password": parts[1],
                            "gid": int(parts[2]),
                            "members": members,
                        }
                    )
        except OSError:
            pass
        return groups


@register_collector
class SudoCollector(BaseCollector):
    """Collects sudo configuration."""

    name = "sudo"
    description = "Sudoers configuration and privileges"

    def _do_collect(self) -> dict[str, list[str] | list[dict[str, str | None]]]:
        return {
            "sudoers_files": self._find_sudoers_files(),
            "sudoers_entries": self._parse_sudoers(),
        }

    def _find_sudoers_files(self) -> list[str]:
        files: list[str] = ["/etc/sudoers"]
        sudoers_d = Path("/etc/sudoers.d")
        if sudoers_d.is_dir():
            for f in sorted(sudoers_d.iterdir()):
                if f.is_file() and not f.name.startswith(".") and not f.name.endswith("~"):
                    files.append(str(f))
        return files

    def _parse_sudoers(self) -> list[dict[str, str | None]]:
        entries: list[dict[str, str | None]] = []
        for path_str in self._find_sudoers_files():
            try:
                for raw_line in Path(path_str).read_text().splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    entries.append(
                        {
                            "file": path_str,
                            "content": line,
                        }
                    )
            except OSError:
                entries.append(
                    {
                        "file": path_str,
                        "content": None,
                    }
                )
        return entries
