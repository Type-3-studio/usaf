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
        result: dict = {"installed": False, "running": False, "containers": [], "detailed": []}
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
            result["containers"] = self._list_docker_containers()
            result["detailed"] = self._inspect_docker_containers()
        return result

    def _list_docker_containers(self) -> list[dict]:
        containers: list[dict] = []
        try:
            r = subprocess.run(
                ["docker", "ps", "--all", "--format", json.dumps({
                    "id": "{{.ID}}", "image": "{{.Image}}",
                    "names": "{{.Names}}", "status": "{{.Status}}",
                    "ports": "{{.Ports}}", "created": "{{.CreatedAt}}",
                })],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if r.returncode == 0 and r.stdout.strip():
                for line in r.stdout.splitlines():
                    try:
                        containers.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        except (OSError, subprocess.SubprocessError):
            pass
        return containers

    def _inspect_docker_containers(self) -> list[dict]:
        detailed: list[dict] = []
        try:
            r = subprocess.run(
                ["docker", "ps", "--all", "-q"],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if r.returncode != 0 or not r.stdout.strip():
                return detailed
            ids = r.stdout.strip().splitlines()
            for cid in ids:
                try:
                    ir = subprocess.run(
                        ["docker", "inspect", cid],
                        capture_output=True, text=True, timeout=15, check=False,
                    )
                    if ir.returncode != 0 or not ir.stdout.strip():
                        continue
                    data = json.loads(ir.stdout)
                    if not data:
                        continue
                    info = data[0]
                    host_config = info.get("HostConfig", {}) or {}
                    config = info.get("Config", {}) or {}
                    detailed.append({
                        "id": cid,
                        "image": config.get("Image", ""),
                        "created": info.get("Created", ""),
                        "state": info.get("State", {}).get("Status", ""),
                        "privileged": host_config.get("Privileged", False),
                        "host_network": host_config.get("NetworkMode") == "host",
                        "host_pid": host_config.get("PidMode") == "host",
                        "host_ipc": host_config.get("IpcMode") == "host",
                        "user": config.get("User", ""),
                        "readonly_rootfs": host_config.get("ReadonlyRootfs", False),
                        "bind_mounts": self._get_bind_mounts(host_config),
                        "port_bindings": host_config.get("PortBindings", {}) or {},
                        "cap_add": host_config.get("CapAdd", []) or [],
                        "cap_drop": host_config.get("CapDrop", []) or [],
                        "security_opt": host_config.get("SecurityOpt", []) or [],
                        "image_name": config.get("Image", ""),
                    })
                except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
                    continue
        except (OSError, subprocess.SubprocessError):
            pass
        return detailed

    @staticmethod
    def _get_bind_mounts(host_config: dict) -> list[dict]:
        mounts: list[dict] = []
        for m in host_config.get("Binds", []) or []:
            parts = m.split(":", 2)
            mounts.append({
                "source": parts[0] if len(parts) > 0 else "",
                "destination": parts[1] if len(parts) > 1 else "",
                "mode": parts[2] if len(parts) > 2 else "",
            })
        for m in host_config.get("Mounts", []) or []:
            mounts.append({
                "source": m.get("Source", ""),
                "destination": m.get("Target", ""),
                "mode": "",
            })
        return mounts

    def _check_podman(self) -> dict:
        result: dict = {"installed": False, "running": False, "containers": [], "detailed": []}
        podman_path = Path("/usr/bin/podman")
        if not podman_path.exists():
            return result
        result["installed"] = True
        try:
            r = subprocess.run(
                ["podman", "info", "--format", "json"],
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
                    capture_output=True, text=True, timeout=15, check=False,
                )
                if r.returncode == 0 and r.stdout.strip():
                    for line in r.stdout.splitlines():
                        try:
                            result["containers"].append(json.loads(line))
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
