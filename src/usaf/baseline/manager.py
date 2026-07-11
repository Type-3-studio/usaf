from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from usaf.core.exceptions import BaselineError
from usaf.models.result import ScanResult


class BaselineSnapshot(BaseModel):
    """A point-in-time snapshot of system state for change detection."""

    created: str = Field(description="ISO 8601 timestamp of snapshot creation")
    hostname: str = Field(description="Hostname at snapshot time")
    os_info: str = Field(description="OS release info")
    kernel_info: str = Field(description="Kernel release")
    packages: dict[str, str] = Field(
        default_factory=dict, description="Package name -> version mapping"
    )
    users: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="Username -> user attributes"
    )
    services: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="Service name -> state"
    )
    ports: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="protocol:port:addr -> process info"
    )
    suid_files: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="SUID file path -> attributes"
    )
    cron_jobs: dict[str, list[str]] = Field(
        default_factory=dict, description="Cron file -> list of job lines"
    )
    kernel_params: dict[str, str] = Field(
        default_factory=dict, description="Kernel parameter -> value"
    )
    sshd_config: dict[str, str] = Field(
        default_factory=dict, description="sshd config directive -> value"
    )

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return json.loads(super().model_dump_json(**kwargs))


class BaselineDiff(BaseModel):
    """Structured diff between two baseline snapshots."""

    added: dict[str, list[Any]] = Field(default_factory=dict)
    removed: dict[str, list[Any]] = Field(default_factory=dict)
    modified: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)

    @property
    def total_changes(self) -> int:
        added = sum(len(v) for v in self.added.values())
        removed = sum(len(v) for v in self.removed.values())
        modified = sum(len(v) for v in self.modified.values())
        return added + removed + modified

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return json.loads(super().model_dump_json(exclude_none=True, **kwargs))


class BaselineManager:
    """Manages baseline snapshots — store, load, diff.

    Baselines are deterministic JSON snapshots of system state.
    They enable change detection across scans and over time.
    """

    def __init__(self, baseline_dir: str | Path | None = None) -> None:
        self.baseline_dir = Path(baseline_dir or self._default_dir())
        self.baseline_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _default_dir() -> str:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) / "usaf" / "baselines" if xdg else Path.home() / ".config" / "usaf" / "baselines"
        profiles_dir = base / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        return str(base)

    def store(self, name: str, snapshot: BaselineSnapshot) -> Path:
        """Save a baseline snapshot to disk."""
        path = self._resolve_path(name)
        data = snapshot.model_dump()
        data.pop("created", None)
        snapshot_with_ts = BaselineSnapshot(created=datetime.now(UTC).isoformat(), **data)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(snapshot_with_ts.model_dump(), indent=2, sort_keys=True, default=str)
        )
        return path

    def load(self, name: str) -> BaselineSnapshot:
        """Load a baseline snapshot from disk."""
        path = self._resolve_path(name)
        if not path.exists():
            raise BaselineError(f"Baseline '{name}' not found at {path}")
        try:
            data = json.loads(path.read_text())
            return BaselineSnapshot(**data)
        except (json.JSONDecodeError, ValueError) as e:
            raise BaselineError(f"Invalid baseline file '{name}': {e}") from e

    def diff(self, baseline: BaselineSnapshot, current: BaselineSnapshot) -> BaselineDiff:
        """Compare two snapshots and return structured diff."""
        diff = BaselineDiff()

        all_sections = [
            "packages",
            "users",
            "services",
            "ports",
            "suid_files",
            "cron_jobs",
            "kernel_params",
            "sshd_config",
        ]

        for section in all_sections:
            old_items: dict = getattr(baseline, section, {})
            new_items: dict = getattr(current, section, {})

            old_keys = set(old_items.keys())
            new_keys = set(new_items.keys())

            added_keys = new_keys - old_keys
            removed_keys = old_keys - new_keys
            common_keys = old_keys & new_keys

            if added_keys:
                diff.added[section] = []
                for k in sorted(added_keys):
                    diff.added[section].append({"key": k, "value": new_items[k]})

            if removed_keys:
                diff.removed[section] = []
                for k in sorted(removed_keys):
                    diff.removed[section].append({"key": k, "value": old_items[k]})

            modified_items: dict[str, dict[str, Any]] = {}
            for k in sorted(common_keys):
                if old_items[k] != new_items[k]:
                    modified_items[k] = {
                        "old": old_items[k],
                        "new": new_items[k],
                    }
            if modified_items:
                diff.modified[section] = modified_items

        return diff

    def delete(self, name: str) -> None:
        """Delete a baseline snapshot."""
        path = self._resolve_path(name)
        if path.exists():
            path.unlink()

    def list_baselines(self) -> list[str]:
        """List all stored baseline names."""
        files = []
        for f in sorted(self.baseline_dir.iterdir()):
            if f.suffix == ".json" and f.stem != "profiles":
                files.append(f.stem)
        return files

    def _resolve_path(self, name: str) -> Path:
        if "/" in name or "\\" in name:
            return Path(name)
        return self.baseline_dir / f"{name}.json"

    def build_snapshot(self, result: ScanResult) -> BaselineSnapshot:
        """Build a baseline snapshot from scan collector data."""
        data = result.collectors_data
        return BaselineSnapshot(
            created=datetime.now(UTC).isoformat(),
            hostname=result.metadata.hostname,
            os_info=result.metadata.os_info,
            kernel_info=result.metadata.kernel_info,
            packages=self._extract_packages(data),
            users=self._extract_users(data),
            services=self._extract_services(data),
            ports=self._extract_ports(data),
            suid_files=self._extract_suid(data),
            cron_jobs=self._extract_cron(data),
            kernel_params=self._extract_kernel_params(data),
            sshd_config=self._extract_sshd_config(data),
        )

    @staticmethod
    def _extract_packages(data: dict[str, Any]) -> dict[str, str]:
        pkgs = data.get("apt", {})
        if isinstance(pkgs, dict):
            return {
                k: v.get("version", "?") if isinstance(v, dict) else str(v)
                for k, v in pkgs.items()
                if isinstance(v, (dict, str))
            }
        return {}

    @staticmethod
    def _extract_users(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        users = data.get("users", {})
        if isinstance(users, dict):
            return {
                u: {
                    k: v for k, v in attrs.items() if k in ("uid", "gid", "groups", "shell")
                }
                for u, attrs in users.items()
                if isinstance(attrs, dict)
            }
        return {}

    @staticmethod
    def _extract_services(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        services = data.get("systemd", {})
        services_data = services.get("services", {}) if isinstance(services, dict) else {}
        if isinstance(services_data, dict):
            return {
                s: {
                    k: v
                    for k, v in attrs.items()
                    if k in ("state", "enabled", "exec_start", "description")
                }
                for s, attrs in services_data.items()
                if isinstance(attrs, dict)
            }
        return {}

    @staticmethod
    def _extract_ports(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        sockets = data.get("sockets", {})
        connections = sockets.get("connections", []) if isinstance(sockets, dict) else []
        result: dict[str, dict[str, Any]] = {}
        for conn in connections:
            if isinstance(conn, dict):
                proto = conn.get("protocol", "tcp")
                port = conn.get("local_port", 0)
                addr = conn.get("local_address", "0.0.0.0")
                key = f"{proto}:{port}:{addr}"
                result[key] = {
                    "pid": conn.get("pid"),
                    "process": conn.get("process_name"),
                    "state": conn.get("state"),
                }
        return result

    @staticmethod
    def _extract_suid(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        suid = data.get("suid", {})
        suid_list = suid.get("files", []) if isinstance(suid, dict) else []
        result: dict[str, dict[str, Any]] = {}
        for entry in suid_list:
            if isinstance(entry, dict):
                path = entry.get("path", "")
                if path:
                    result[path] = {
                        "owner": entry.get("owner"),
                        "group": entry.get("group"),
                        "permissions": entry.get("permissions"),
                    }
        return result

    @staticmethod
    def _extract_cron(data: dict[str, Any]) -> dict[str, list[str]]:
        cron_data = data.get("cron", {})
        jobs = cron_data.get("jobs", []) if isinstance(cron_data, dict) else []
        result: dict[str, list[str]] = {}
        for entry in jobs:
            if isinstance(entry, dict):
                file_path = entry.get("file", "unknown")
                result.setdefault(file_path, []).append(entry.get("command", ""))
        return result

    @staticmethod
    def _extract_kernel_params(data: dict[str, Any]) -> dict[str, str]:
        params = data.get("kernel_params", {})
        if isinstance(params, dict):
            return {k: str(v) for k, v in params.items() if not k.startswith("_")}
        return {}

    @staticmethod
    def _extract_sshd_config(data: dict[str, Any]) -> dict[str, str]:
        sshd = data.get("sshd_config", {})
        if isinstance(sshd, dict):
            return {k: str(v) for k, v in sshd.items()}
        return {}
