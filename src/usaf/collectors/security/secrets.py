from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector

_COMMON_SECRET_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "aws_keys": [
        re.compile(r"(?i)aws_access_key_id\s*[=:]\s*([A-Z0-9]{16,})"),
        re.compile(r"(?i)secret_access_key\s*[=:]\s*(\S+)"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ],
    "gcp_keys": [
        re.compile(r'"type"\s*:\s*"service_account"'),
        re.compile(r'"client_email"\s*:\s*"[^"]+@[^"]+\.iam\.gserviceaccount\.com"'),
        re.compile(r'"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----'),
    ],
    "github_tokens": [
        re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),
        re.compile(r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b"),
        re.compile(r"\bgho_[a-zA-Z0-9]{36}\b"),
        re.compile(r"\bghu_[a-zA-Z0-9]{36}\b"),
        re.compile(r"\bghs_[a-zA-Z0-9]{36}\b"),
        re.compile(r"\bghr_[a-zA-Z0-9]{36}\b"),
    ],
    "api_keys": [
        re.compile(r"(?i)(api[_-]?key|apikey|api_secret|api[_-]?token)\s*[=:]\s*['\"]?(\S{16,})['\"]?"),
    ],
    "db_credentials": [
        re.compile(r"(?i)(postgresql|mysql|mongodb|redis|sqlite|jdbc):\/\/[^\s]+"),
        re.compile(r"(?i)(database_url|database_host|db_host|db_password|db_user)\s*[=:]\s*(\S+)"),
    ],
    "private_keys": [
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ],
}

_SECRET_FILE_GLOBS: list[str] = [
    ".env", ".env.*", ".aws/credentials", ".aws/config",
    ".gitconfig", ".netrc", ".npmrc", ".docker/config.json",
    ".ssh/config", ".ssh/authorized_keys",
]

_SECRET_DIRS: list[tuple[str, bool]] = [
    ("/root", False),
    ("/etc", False),
]


def _get_home_dirs() -> set[str]:
    dirs: set[str] = set()
    try:
        with open("/etc/passwd") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 6 and parts[5]:
                    home = parts[5]
                    if home.startswith("/home/") or home == "/root":
                        dirs.add(home)
    except OSError:
        pass
    return dirs


def _scan_file_for_patterns(
    filepath: str, patterns: dict[str, list[re.Pattern[str]]]
) -> dict[str, list[dict[str, Any]]]:
    results: dict[str, list[dict[str, Any]]] = {}
    try:
        st = os.stat(filepath)
    except OSError:
        return results
    try:
        with open(filepath, errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                for category, pat_list in patterns.items():
                    for pat in pat_list:
                        m = pat.search(line)
                        if m:
                            results.setdefault(category, []).append({
                                "path": filepath,
                                "line": lineno,
                                "match": m.group(0)[:80],
                                "permission": oct(st.st_mode),
                                "owner": str(st.st_uid),
                                "size": st.st_size,
                            })
                            break
    except (OSError, UnicodeDecodeError):
        pass
    return results


def _is_secret_filename(name: str) -> bool:
    for g in _SECRET_FILE_GLOBS:
        if Path(name).match(g):
            return True
    return False


@register_collector
class SecretsCollector(BaseCollector):
    name = "secrets"
    description = "Scans common locations for exposed credentials and secret material"

    def _do_collect(self) -> dict[str, Any]:
        scanned_dirs: list[str] = []
        discovered_files: list[str] = []
        findings: dict[str, list[dict[str, Any]]] = {}

        homedirs = _get_home_dirs()
        for hd in homedirs:
            scanned_dirs.append(hd)
            hd_path = Path(hd)
            if not hd_path.is_dir():
                continue
            try:
                for entry in hd_path.iterdir():
                    if entry.name.startswith("."):
                        if entry.is_file() and _is_secret_filename(entry.name):
                            discovered_files.append(str(entry))
                        elif entry.is_dir():
                            secret_sub = self._scan_secret_subdir(entry)
                            discovered_files.extend(secret_sub)
            except PermissionError:
                continue

        for d, rec in _SECRET_DIRS:
            scanned_dirs.append(d)
            d_path = Path(d)
            if not d_path.is_dir():
                continue
            try:
                for entry in d_path.iterdir():
                    if entry.is_file() and _is_secret_filename(entry.name):
                        discovered_files.append(str(entry))
            except PermissionError:
                continue

        for fp in discovered_files:
            file_findings = _scan_file_for_patterns(fp, _COMMON_SECRET_PATTERNS)
            for cat, items in file_findings.items():
                findings.setdefault(cat, []).extend(items)

        return {
            "scanned_dirs": scanned_dirs,
            "total_scanned_files": len(discovered_files),
            **findings,
        }

    @staticmethod
    def _scan_secret_subdir(dir_entry: Path) -> list[str]:
        files: list[str] = []
        try:
            for child in dir_entry.iterdir():
                if child.is_file() and _is_secret_filename(str(child.relative_to(dir_entry.parent))):
                    files.append(str(child))
        except PermissionError:
            pass
        return files
