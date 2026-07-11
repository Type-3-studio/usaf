from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.collectors.container.runtime import ContainerCollector


class TestContainerCollector:
    def test_docker_not_installed(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p) != "/usr/bin/docker")
        collector = ContainerCollector()
        data = collector.collect()
        assert data["docker"]["installed"] is False
        assert data["docker"]["running"] is False
        assert data["docker"]["containers"] == []

    def test_docker_installed_and_running(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p) == "/usr/bin/docker")

        with patch("subprocess.run") as mock_run:
            docker_info = type("Result", (), {"returncode": 0, "stdout": "24.0.5\n"})
            docker_ps = type("Result", (), {"returncode": 0, "stdout": '{"id": "abc123", "image": "nginx:latest", "names": "web", "status": "Up 2 hours", "ports": "0.0.0.0:80->80/tcp", "created": "2026-01-01"}\n'})
            podman_info = type("Result", (), {"returncode": 0, "stdout": '{"Version": {"Version": "4.8.0"}}\n'})
            results = [docker_info(), docker_ps(), podman_info()]
            mock_run.side_effect = lambda *a, **kw: results.pop(0)

            collector = ContainerCollector()
            data = collector.collect()

        assert data["docker"]["installed"] is True
        assert data["docker"]["running"] is True
        assert data["docker"]["version"] == "24.0.5"
        assert len(data["docker"]["containers"]) == 1
        assert data["docker"]["containers"][0]["image"] == "nginx:latest"

    def test_docker_installed_but_not_running(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p) == "/usr/bin/docker")

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            mock_run.return_value.stdout = ""
            collector = ContainerCollector()
            data = collector.collect()

        assert data["docker"]["installed"] is True
        assert data["docker"]["running"] is False
        assert data["docker"]["containers"] == []

    def test_podman_not_installed(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p) != "/usr/bin/podman")
        collector = ContainerCollector()
        data = collector.collect()
        assert data["podman"]["installed"] is False

    def test_podman_installed(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: str(p) in ("/usr/bin/podman", "/usr/bin/docker"))

        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                class MockResult:
                    returncode = 0
                    stdout = ""
                if "podman info" in str(cmd) or "podman" in str(cmd) and "json" in str(cmd):
                    MockResult.stdout = '{"Version": {"Version": "4.8.0"}}\n'
                return MockResult()
            mock_run.side_effect = side_effect

            collector = ContainerCollector()
            data = collector.collect()

        assert data["podman"]["installed"] is True
        assert data["podman"]["running"] is True

    def test_runtime_socket_detection(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: "docker.sock" in str(p))
        collector = ContainerCollector()
        data = collector.collect()
        runtimes = {r["name"]: r["socket_exists"] for r in data["runtimes"]}
        assert runtimes.get("docker") is True
        assert runtimes.get("containerd") is False

    def test_handles_subprocess_error(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: True)
        with patch("subprocess.run", side_effect=OSError("not found")):
            collector = ContainerCollector()
            data = collector.collect()
        assert data["docker"]["installed"] is True
        assert data["docker"]["running"] is False
