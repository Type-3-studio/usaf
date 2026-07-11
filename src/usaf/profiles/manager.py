from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from usaf.core.exceptions import PolicyError


class Profile(BaseModel):
    """Defines the expected state of a system based on its role.

    Profiles dramatically reduce false positives by distinguishing
    expected from unexpected system states.
    """

    name: str = Field(description="Profile name, e.g., 'Ubuntu Desktop 24.04'")
    description: str = Field(default="", description="Human-readable description")
    distro: str = Field(default="ubuntu", description="Target distribution")
    version: str = Field(default="", description="Target version, e.g., '24.04'")
    expected_packages: list[str] = Field(
        default_factory=list, description="Package name patterns expected"
    )
    expected_services: list[str] = Field(
        default_factory=list, description="Systemd service names expected"
    )
    expected_suid: list[str] = Field(
        default_factory=list, description="SUID binary paths expected"
    )
    expected_ports: list[dict[str, Any]] = Field(
        default_factory=list, description="Expected listening ports with purpose"
    )
    expected_cron_jobs: list[str] = Field(
        default_factory=list, description="Expected cron job command patterns"
    )
    expected_users: list[str] = Field(
        default_factory=list, description="Expected system user names"
    )
    expected_groups: list[str] = Field(
        default_factory=list, description="Expected system group names"
    )
    severity_overrides: dict[str, str] = Field(
        default_factory=dict, description="Check ID -> severity override"
    )
    tags: list[str] = Field(default_factory=list, description="Profile tags for filtering")

    def model_dump(self, **kwargs: Any) -> dict[str, Any]:
        return super().model_dump(exclude_none=True, **kwargs)


class ProfileMatch(BaseModel):
    """Result of matching a system against a profile."""

    profile: Profile = Field(description="The matched profile")
    score: float = Field(ge=0.0, le=1.0, description="Match confidence (0-1)")
    missing_packages: list[str] = Field(default_factory=list)
    unexpected_packages: list[str] = Field(default_factory=list)
    missing_services: list[str] = Field(default_factory=list)
    unexpected_services: list[str] = Field(default_factory=list)
    unexpected_suid: list[str] = Field(default_factory=list)
    missing_suid: list[str] = Field(default_factory=list)

    @property
    def is_match(self) -> bool:
        return self.score >= 0.5

    @property
    def deviations(self) -> list[str]:
        result: list[str] = []
        if self.missing_packages:
            result.append(f"missing packages: {', '.join(self.missing_packages[:5])}")
        if self.unexpected_packages:
            result.append(f"unexpected packages: {', '.join(self.unexpected_packages[:5])}")
        if self.missing_services:
            result.append(f"missing services: {', '.join(self.missing_services[:5])}")
        if self.unexpected_services:
            result.append(f"unexpected services: {', '.join(self.unexpected_services[:5])}")
        if self.unexpected_suid:
            result.append(f"unexpected SUID: {', '.join(self.unexpected_suid[:5])}")
        return result


# Built-in reference profiles
UBUNTU_DESKTOP_24_04 = Profile(
    name="Ubuntu Desktop 24.04",
    description="Standard Ubuntu 24.04 Desktop installation",
    distro="ubuntu",
    version="24.04",
    expected_packages=[
        "ubuntu-desktop",
        "firefox",
        "libreoffice",
        "thunderbird",
        "gnome-shell",
        "gdm3",
        "network-manager",
    ],
    expected_services=[
        "gdm3",
        "NetworkManager",
        "systemd-logind",
        "systemd-journald",
        "dbus",
        "accounts-daemon",
        "avahi-daemon",
        "cupsd",
        "bluetooth",
    ],
    expected_suid=[
        "/usr/bin/sudo",
        "/usr/bin/ping",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/usr/bin/passwd",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/su",
        "/usr/bin/pkexec",
        "/usr/lib/snapd/snap-confine",
        "/usr/libexec/polkit-agent-helper-1",
        "/usr/bin/fusermount3",
    ],
    expected_ports=[
        {"port": 631, "protocol": "tcp", "purpose": "CUPS printing"},
    ],
    expected_users=[
        "root",
        "daemon",
        "bin",
        "sys",
        "sync",
        "games",
        "man",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "www-data",
        "backup",
        "list",
        "irc",
        "gnats",
        "nobody",
        "systemd-network",
        "systemd-resolve",
        "messagebus",
        "systemd-timesync",
        "syslog",
        "_apt",
        "tss",
        "uuidd",
        "tcpdump",
        "usbmux",
        "dnsmasq",
        "avahi",
        "cups-pk-helper-master",
        "speech-dispatcher",
        "whoopsie",
        "kernoops",
        "saned",
        "pulse",
        "hplip",
        "gdm",
        "geoclue",
        "fwupd-refresh",
    ],
    expected_groups=[
        "root",
        "daemon",
        "bin",
        "sys",
        "adm",
        "tty",
        "disk",
        "lp",
        "mem",
        "kmem",
        "wheel",
        "cdrom",
        "floppy",
        "sudo",
        "audio",
        "dip",
        "video",
        "plugdev",
        "users",
        "systemd-journal",
    ],
    tags=["desktop", "ubuntu", "workstation"],
)

UBUNTU_SERVER_24_04 = Profile(
    name="Ubuntu Server 24.04",
    description="Minimal Ubuntu 24.04 Server installation",
    distro="ubuntu",
    version="24.04",
    expected_packages=[
        "ubuntu-server",
        "openssh-server",
        "systemd",
    ],
    expected_services=[
        "ssh",
        "systemd-logind",
        "systemd-journald",
        "dbus",
        "systemd-networkd",
        "systemd-resolved",
        "systemd-timesyncd",
    ],
    expected_suid=[
        "/usr/bin/sudo",
        "/usr/bin/ping",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/usr/bin/passwd",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/su",
        "/usr/bin/pkexec",
        "/usr/lib/snapd/snap-confine",
        "/usr/libexec/polkit-agent-helper-1",
        "/usr/bin/fusermount3",
    ],
    expected_ports=[
        {"port": 22, "protocol": "tcp", "purpose": "SSH"},
    ],
    expected_users=[
        "root",
        "daemon",
        "bin",
        "sys",
        "sync",
        "games",
        "man",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "www-data",
        "backup",
        "list",
        "irc",
        "gnats",
        "nobody",
        "systemd-network",
        "systemd-resolve",
        "messagebus",
        "systemd-timesync",
        "syslog",
        "_apt",
        "tss",
        "uuidd",
        "tcpdump",
        "usbmux",
        "dnsmasq",
    ],
    expected_groups=[
        "root",
        "daemon",
        "bin",
        "sys",
        "adm",
        "tty",
        "disk",
        "lp",
        "mem",
        "kmem",
        "wheel",
        "cdrom",
        "floppy",
        "sudo",
        "audio",
        "dip",
        "video",
        "plugdev",
        "users",
        "systemd-journal",
        "systemd-network",
    ],
    tags=["server", "ubuntu", "minimal"],
)


class ProfileManager:
    """Manages system profiles — load, match, compare.

    Profiles encode expected system states by role (desktop, server, container, etc.)
    and are used to reduce false positives by distinguishing expected from anomalous state.
    """

    BUILTIN_PROFILES: dict[str, Profile] = {
        "ubuntu-desktop-24-04": UBUNTU_DESKTOP_24_04,
        "ubuntu-server-24-04": UBUNTU_SERVER_24_04,
    }

    def __init__(self, profile_dir: str | Path | None = None) -> None:
        self.profile_dir = Path(profile_dir) if profile_dir else self._default_dir()
        self._custom_profiles: dict[str, Profile] = {}

    @staticmethod
    def _default_dir() -> Path:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) / "usaf" / "profiles" if xdg else Path.home() / ".config" / "usaf" / "profiles"
        base.mkdir(parents=True, exist_ok=True)
        return base

    @property
    def all_profiles(self) -> dict[str, Profile]:
        profiles = dict(self.BUILTIN_PROFILES)
        profiles.update(self._custom_profiles)
        return profiles

    def get_profile(self, name: str) -> Profile:
        if name in self.BUILTIN_PROFILES:
            return self.BUILTIN_PROFILES[name]
        if name in self._custom_profiles:
            return self._custom_profiles[name]
        raise KeyError(f"Profile '{name}' not found")

    def load_from_file(self, path: str | Path) -> Profile:
        """Load a profile from a YAML file."""
        path = Path(path)
        if not path.exists():
            raise PolicyError(f"Profile file not found: {path}")
        try:
            data = yaml.safe_load(path.read_text())
            profile = Profile(**data)
            self._custom_profiles[profile.name] = profile
            return profile
        except yaml.YAMLError as e:
            raise PolicyError(f"Invalid YAML in profile {path}: {e}") from e

    def match(
        self,
        collector_data: dict[str, dict[str, Any]],
        profile_name: str | None = None,
    ) -> ProfileMatch:
        """Match a system against the best-fit profile.

        If profile_name is specified, match against that specific profile.
        Otherwise, auto-detect based on installed packages.
        """
        if profile_name:
            profile = self.get_profile(profile_name)
        else:
            profile = self._auto_detect(collector_data)

        installed_packages = self._get_installed_packages(collector_data)
        installed_services = self._get_installed_services(collector_data)
        installed_suid = self._get_installed_suid(collector_data)

        missing_packages = [
            p for p in profile.expected_packages if p not in installed_packages
        ]
        unexpected_packages = [
            p for p in installed_packages if p not in profile.expected_packages
        ]
        missing_services = [
            s for s in profile.expected_services if s not in installed_services
        ]
        unexpected_services = [
            s for s in installed_services if s not in profile.expected_services
        ]
        missing_suid = [
            s for s in profile.expected_suid if not any(s.endswith(e) for e in installed_suid)
        ]
        unexpected_suid = [
            s for s in installed_suid if s not in profile.expected_suid
        ]

        max_possible = (
            len(profile.expected_packages)
            + len(profile.expected_services)
            + len(profile.expected_suid)
        )
        total_deviations = (
            len(missing_packages)
            + len(unexpected_packages)
            + len(missing_services)
            + len(unexpected_services)
            + len(unexpected_suid)
        )

        score = max(0.0, 1.0 - (total_deviations / max(1, max_possible)))

        return ProfileMatch(
            profile=profile,
            score=round(score, 2),
            missing_packages=missing_packages,
            unexpected_packages=unexpected_packages,
            missing_services=missing_services,
            unexpected_services=unexpected_services,
            unexpected_suid=unexpected_suid,
            missing_suid=missing_suid,
        )

    def _auto_detect(self, collector_data: dict[str, Any]) -> Profile:
        """Auto-detect the best profile match based on installed packages."""
        packages = self._get_installed_packages(collector_data)
        best_profile = list(self.BUILTIN_PROFILES.values())[0]
        best_score = 0.0

        for profile in self.BUILTIN_PROFILES.values():
            matched = sum(1 for p in profile.expected_packages if p in packages)
            total = max(1, len(profile.expected_packages))
            score = matched / total
            if score > best_score:
                best_score = score
                best_profile = profile

        return best_profile

    @staticmethod
    def _get_installed_packages(data: dict[str, Any]) -> set[str]:
        pkgs = data.get("apt", {})
        if isinstance(pkgs, dict):
            return set(pkgs.keys())
        if isinstance(pkgs, list):
            return {p.get("name", "") if isinstance(p, dict) else str(p) for p in pkgs}
        return set()

    @staticmethod
    def _get_installed_services(data: dict[str, Any]) -> set[str]:
        svcs = data.get("systemd", {})
        if isinstance(svcs, dict):
            services = svcs.get("services", {})
            if isinstance(services, dict):
                return set(services.keys())
        return set()

    @staticmethod
    def _get_installed_suid(data: dict[str, Any]) -> set[str]:
        suid = data.get("suid", {})
        if isinstance(suid, dict):
            files = suid.get("files", [])
            if isinstance(files, list):
                return {f.get("path", "") if isinstance(f, dict) else str(f) for f in files}
        return set()
