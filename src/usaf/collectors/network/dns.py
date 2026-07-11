from __future__ import annotations

import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class DNSCollector(BaseCollector):
    name = "dns"
    description = "DNS resolver configuration, resolv.conf, systemd-resolved status"

    def _do_collect(self) -> dict:
        return {
            "resolv_conf": self._parse_resolv_conf(),
            "resolved_status": self._get_resolved_status(),
            "hosts": self._parse_hosts(),
            "mdns": self._get_mdns_status(),
            "dnssec": self._get_dnssec_status(),
        }

    def _parse_resolv_conf(self) -> dict:
        result: dict = {
            "nameservers": [],
            "search_domains": [],
            "options": [],
            "symlink_target": None,
        }
        rp = Path("/etc/resolv.conf")
        if rp.is_symlink():
            try:
                result["symlink_target"] = str(rp.readlink())
            except OSError:
                pass
        try:
            for line in rp.read_text().splitlines():
                line = line.strip()
                if line.startswith("nameserver "):
                    result["nameservers"].append(line.split(None, 1)[1])
                elif line.startswith("search "):
                    result["search_domains"] = line.split(None, 1)[1].split()
                elif line.startswith("options "):
                    result["options"].append(line.split(None, 1)[1])
        except OSError:
            pass
        return result

    def _get_resolved_status(self) -> dict:
        result: dict = {
            "running": False,
            "enabled": False,
            "dns_servers": [],
            "fallback_dns": [],
            "current_dns": [],
            "mode": None,
        }
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "systemd-resolved"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["running"] = r.stdout.strip() == "active"
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["systemctl", "is-enabled", "systemd-resolved"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["enabled"] = r.stdout.strip() == "enabled"
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["resolvectl", "status"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if "DNS Servers:" in line:
                    result["current_dns"] = line.split(":", 1)[1].strip().split()
                elif "DNS Domain:" in line:
                    result["mode"] = line.split(":", 1)[1].strip()
        except (OSError, subprocess.SubprocessError):
            pass
        config = Path("/etc/systemd/resolved.conf")
        if config.exists():
            try:
                for line in config.read_text().splitlines():
                    line = line.strip()
                    if line.startswith("DNS="):
                        result["dns_servers"] = line.split("=", 1)[1].split()
                    elif line.startswith("FallbackDNS="):
                        result["fallback_dns"] = line.split("=", 1)[1].split()
            except OSError:
                pass
        return result

    def _parse_hosts(self) -> dict:
        result: dict = {"entries": [], "modified": None}
        hp = Path("/etc/hosts")
        try:
            stat = hp.stat()
            result["modified"] = stat.st_mtime
            for line in hp.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    result["entries"].append(line)
        except OSError:
            pass
        return result

    def _get_mdns_status(self) -> dict:
        result: dict = {"avahi_running": False, "avahi_enabled": False}
        try:
            r = subprocess.run(
                ["systemctl", "is-active", "avahi-daemon"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["avahi_running"] = r.stdout.strip() == "active"
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            r = subprocess.run(
                ["systemctl", "is-enabled", "avahi-daemon"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["avahi_enabled"] = r.stdout.strip() == "enabled"
        except (OSError, subprocess.SubprocessError):
            pass
        return result

    def _get_dnssec_status(self) -> dict:
        result: dict = {"dnssec": None, "supported": False}
        try:
            r = subprocess.run(
                ["resolvectl", "dnssec"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            result["dnssec"] = r.stdout.strip()
            result["supported"] = True
        except (OSError, subprocess.SubprocessError):
            pass
        return result
