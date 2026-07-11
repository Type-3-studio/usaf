from __future__ import annotations

from usaf.checks.containers.container_checks import (
    DockerTCPExposureCheck,
    HostMountsContainersCheck,
    HostNetworkContainersCheck,
    HostPIDContainersCheck,
    OldImagesCheck,
    PrivilegedContainersCheck,
    RootContainersCheck,
    UnsignedImagesCheck,
)


def _container_detail(overrides: dict | None = None) -> dict:
    base = {
        "id": "abc123def456",
        "image": "nginx:latest",
        "created": "2026-07-01T00:00:00Z",
        "state": "running",
        "privileged": False,
        "host_network": False,
        "host_pid": False,
        "host_ipc": False,
        "user": "1000",
        "readonly_rootfs": False,
        "bind_mounts": [],
        "port_bindings": {},
        "cap_add": [],
        "cap_drop": [],
        "security_opt": [],
        "image_name": "nginx:latest",
    }
    if overrides:
        base.update(overrides)
    return base


_COLLECTOR = {
    "docker": {
        "installed": True,
        "running": True,
        "version": "24.0.0",
        "containers": [{"id": "abc", "image": "nginx:latest", "names": "nginx", "status": "running"}],
        "detailed": [],
    },
    "podman": {"installed": False, "running": False, "containers": [], "detailed": []},
    "runtimes": [
        {"name": "docker", "socket": "/var/run/docker.sock", "socket_exists": True},
        {"name": "containerd", "socket": "/var/run/containerd/containerd.sock", "socket_exists": False},
    ],
}


class TestPrivilegedContainersCheck:
    def test_no_findings_when_no_containers(self):
        check = PrivilegedContainersCheck()
        result = check.evaluate(_COLLECTOR)
        assert result.passed

    def test_no_findings_when_not_privileged(self):
        check = PrivilegedContainersCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail()]}
        result = check.evaluate(collector)
        assert result.passed

    def test_finds_privileged_container(self):
        check = PrivilegedContainersCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail({"privileged": True})]}
        result = check.evaluate(collector)
        assert not result.passed
        assert len(result.findings) == 1

    def test_check_id(self):
        assert PrivilegedContainersCheck.id == "CTN-201"


class TestHostNetworkContainersCheck:
    def test_no_findings_when_no_containers(self):
        check = HostNetworkContainersCheck()
        result = check.evaluate(_COLLECTOR)
        assert result.passed

    def test_finds_host_network_container(self):
        check = HostNetworkContainersCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail({"host_network": True})]}
        result = check.evaluate(collector)
        assert not result.passed
        assert len(result.findings) == 1

    def test_check_id(self):
        assert HostNetworkContainersCheck.id == "CTN-202"


class TestHostPIDContainersCheck:
    def test_no_findings_when_no_containers(self):
        check = HostPIDContainersCheck()
        result = check.evaluate(_COLLECTOR)
        assert result.passed

    def test_finds_host_pid_container(self):
        check = HostPIDContainersCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail({"host_pid": True})]}
        result = check.evaluate(collector)
        assert not result.passed
        assert len(result.findings) == 1

    def test_check_id(self):
        assert HostPIDContainersCheck.id == "CTN-203"


class TestHostMountsContainersCheck:
    def test_no_findings_when_no_containers(self):
        check = HostMountsContainersCheck()
        result = check.evaluate(_COLLECTOR)
        assert result.passed

    def test_no_findings_with_safe_mounts(self):
        check = HostMountsContainersCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {
            **collector["docker"],
            "detailed": [_container_detail({"bind_mounts": [{"source": "/data/app", "destination": "/app", "mode": "rw"}]})],
        }
        result = check.evaluate(collector)
        assert result.passed

    def test_finds_sensitive_mount(self):
        check = HostMountsContainersCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {
            **collector["docker"],
            "detailed": [_container_detail({"bind_mounts": [{"source": "/etc/passwd", "destination": "/host/etc", "mode": "ro"}]})],
        }
        result = check.evaluate(collector)
        assert not result.passed
        assert len(result.findings) == 1

    def test_check_id(self):
        assert HostMountsContainersCheck.id == "CTN-204"


class TestRootContainersCheck:
    def test_no_findings_with_non_root_user(self):
        check = RootContainersCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail({"user": "1000"})]}
        result = check.evaluate(collector)
        assert result.passed

    def test_finds_root_container(self):
        check = RootContainersCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail({"user": ""})]}
        result = check.evaluate(collector)
        assert not result.passed
        assert len(result.findings) == 1

    def test_finds_explicit_root(self):
        check = RootContainersCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail({"user": "root"})]}
        result = check.evaluate(collector)
        assert not result.passed

    def test_check_id(self):
        assert RootContainersCheck.id == "CTN-301"


class TestOldImagesCheck:
    def test_no_findings_with_recent_image(self):
        check = OldImagesCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail({"created": "2026-07-11T00:00:00Z"})]}
        result = check.evaluate(collector)
        assert result.passed

    def test_finds_old_image(self):
        check = OldImagesCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail({"created": "2025-01-01T00:00:00Z"})]}
        result = check.evaluate(collector)
        assert not result.passed
        assert len(result.findings) == 1

    def test_no_findings_with_no_created_date(self):
        check = OldImagesCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": [_container_detail({"created": ""})]}
        result = check.evaluate(collector)
        assert result.passed

    def test_check_id(self):
        assert OldImagesCheck.id == "CTN-401"


class TestUnsignedImagesCheck:
    def test_no_findings_when_no_containers(self):
        check = UnsignedImagesCheck()
        collector = _COLLECTOR.copy()
        collector["docker"] = {**collector["docker"], "detailed": []}
        result = check.evaluate(collector)
        assert result.passed

    def test_detects_content_trust_disabled(self):
        import os
        old = os.environ.pop("DOCKER_CONTENT_TRUST", None)
        try:
            check = UnsignedImagesCheck()
            collector = _COLLECTOR.copy()
            collector["docker"] = {**collector["docker"], "detailed": [_container_detail()]}
            result = check.evaluate(collector)
            assert not result.passed
            assert len(result.findings) == 1
        finally:
            if old is not None:
                os.environ["DOCKER_CONTENT_TRUST"] = old

    def test_check_id(self):
        assert UnsignedImagesCheck.id == "CTN-402"


class TestDockerTCPExposureCheck:
    def test_no_findings_when_socket_exists(self):
        check = DockerTCPExposureCheck()
        result = check.evaluate({"containers": _COLLECTOR})
        assert result.passed

    def test_check_id(self):
        assert DockerTCPExposureCheck.id == "CTN-102"
