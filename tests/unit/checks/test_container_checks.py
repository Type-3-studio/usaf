from __future__ import annotations

from pathlib import Path

from usaf.checks.containers.docker_socket_check import DockerSocketCheck
from usaf.models.severity import Severity


class FakeSecureStat:
    st_mode = 0o100640
    st_uid = 0


class FakeInsecureStat:
    st_mode = 0o100777
    st_uid = 1000


class FakeGroupWriteStat:
    st_mode = 0o100662
    st_uid = 0


class TestDockerSocketCheck:
    def test_passes_when_no_socket(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = DockerSocketCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_socket_secure(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "stat", lambda _: FakeSecureStat())
        check = DockerSocketCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_world_accessible(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "stat", lambda _: FakeInsecureStat())
        check = DockerSocketCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "world-accessible" in f.title or "insecure" in f.title
        assert f.severity == Severity.HIGH

    def test_fails_when_not_root_owned(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "stat", lambda _: FakeInsecureStat())
        check = DockerSocketCheck()
        result = check.evaluate({})
        assert not result.passed
        assert "not owned by root" in result.findings[0].title

    def test_fails_when_group_writable(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "stat", lambda _: FakeGroupWriteStat())
        check = DockerSocketCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_handles_os_error_on_stat(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "stat", lambda _: (_ for _ in ()).throw(OSError))
        check = DockerSocketCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_mitre_mapping(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "stat", lambda _: FakeInsecureStat())
        check = DockerSocketCheck()
        result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0
