from __future__ import annotations

import json
import subprocess
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class ContainerCollector(BaseCollector):
    """Collects information about container runtimes and running containers."""

    name = "containers"
    description = "Container runtime detection and running containers"

    def _do_collect(self) -> dict:
        return {
            "docker": self._check_docker(),
            "podman": self._check_podman(),
            "runtimes": self._detect_runtimes(),
        }

    def _check_docker(self) -> dict:
        result: dict = {"installed": False, "running": False, "containers": []}
        dockerd = Path("/usr/bin/docker") or Path("/usr/local/bin/docker") or Path("/usr/sbin/docker")
        if not dockerd.exists():
            dockerd = Path("/usr/bin/docker")
            if not dockerd.exists():
                return result
        result["installed"] = True
        try:
            r = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode == 0 and r.stdout.strip():
                result["running"] = True
                result["version"] = r.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        if result["running"]:
            try:
                r = subprocess.run(
                    ["docker", "ps", "--all", "--format", json.dumps({
                        "id": "{{.ID}}", "image": "{{.Image}}",
                        "names": "{{.Names}}", "status": "{{.Status}}",
                        "ports": "{{.Ports}}", "created": "{{.CreatedAt}}",
                    })],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if r.returncode == 0 and r.stdout.strip():
                    for line in r.stdout.splitlines():
                        try:
                            container = json.loads(line)
                            result["containers"].append(container)
                        except json.JSONDecodeError:
                            pass
            except (OSError, subprocess.SubprocessError):
                pass
        return result

    def _check_podman(self) -> dict:
        result: dict = {"installed": False, "running": False, "containers": []}
        podman_path = Path("/usr/bin/podman")
        if not podman_path.exists():
            return result
        result["installed"] = True
        try:
            r = subprocess.run(
                ["podman", "info", "--format", "{{.Version}}" if False else "",
                 "--format", "json"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode == 0 and r.stdout.strip():
                result["running"] = True
                try:
                    info = json.loads(r.stdout)
                    result["version"] = info.get("Version", {}).get("Version", "")
                except (json.JSONDecodeError, AttributeError):
                    pass
        except (OSError, subprocess.SubprocessError):
            pass
        if result["running"]:
            try:
                r = subprocess.run(
                    ["podman", "ps", "--all", "--format", json.dumps({
                        "id": "{{.ID}}", "image": "{{.Image}}",
                        "names": "{{.Names}}", "status": "{{.Status}}",
                    })],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if r.returncode == 0 and r.stdout.strip():
                    for line in r.stdout.splitlines():
                        try:
                            container = json.loads(line)
                            result["containers"].append(container)
                        except json.JSONDecodeError:
                            pass
            except (OSError, subprocess.SubprocessError):
                pass
        return result

    def _detect_runtimes(self) -> list[dict]:
        runtimes: list[dict] = []
        runtime_sockets = {
            "docker": "/var/run/docker.sock",
            "containerd": "/var/run/containerd/containerd.sock",
            "crio": "/var/run/crio/crio.sock",
            "podman": "/run/podman/podman.sock",
        }
        for name, sock_path in runtime_sockets.items():
            sock = Path(sock_path)
            runtimes.append({
                "name": name,
                "socket": sock_path,
                "socket_exists": sock.exists(),
            })
        return runtimes
