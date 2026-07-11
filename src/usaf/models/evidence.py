from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FileEvidence(BaseModel):
    path: str
    line: int | None = None
    content: str | None = None
    permission: str | None = None
    owner: str | None = None
    group: str | None = None
    size: int | None = None
    modified: datetime | None = None
    hash_sha256: str | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class ProcessEvidence(BaseModel):
    pid: int
    name: str
    binary: str | None = None
    cmdline: str | None = None
    user: str | None = None
    state: str | None = None
    ppid: int | None = None
    threads: int | None = None
    memory_mbytes: float | None = None
    cpu_percent: float | None = None
    started: datetime | None = None
    environment: dict[str, str] | None = None
    open_fds: list[str] | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class NetworkEvidence(BaseModel):
    protocol: str
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    state: str | None = None
    pid: int | None = None
    process_name: str | None = None
    uid: int | None = None
    inode: int | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class CommandEvidence(BaseModel):
    command: str
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    executed_at: datetime | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class RegistryEvidence(BaseModel):
    key: str
    value: str | None = None
    expected: str | None = None
    source: str | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class LogEvidence(BaseModel):
    log_path: str
    lines: list[str] = Field(default_factory=list)
    pattern: str | None = None
    match_count: int | None = None
    time_range: tuple[datetime, datetime] | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class UserEvidence(BaseModel):
    username: str
    uid: int
    gid: int
    home: str | None = None
    shell: str | None = None
    groups: list[str] | None = None
    ssh_keys: list[str] | None = None
    last_login: datetime | None = None
    password_expires: datetime | None = None
    is_locked: bool | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class PackageEvidence(BaseModel):
    name: str
    version: str | None = None
    architecture: str | None = None
    repository: str | None = None
    status: str | None = None
    installed_size: int | None = None
    is_update_available: bool | None = None

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


Evidence = (
    FileEvidence
    | ProcessEvidence
    | NetworkEvidence
    | CommandEvidence
    | RegistryEvidence
    | LogEvidence
    | UserEvidence
    | PackageEvidence
)
