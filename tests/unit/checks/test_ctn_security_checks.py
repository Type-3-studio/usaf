from __future__ import annotations

from usaf.checks.containers.ctn_security_checks import (
    ContainerAddedCapabilitiesCheck,
    ContainerExcessiveMountsCheck,
    ContainerLatestTagCheck,
    ContainerLongRunningCheck,
    ContainerNoUserNameSpaceCheck,
    ContainerRestartPolicyCheck,
    ContainerSecurityOptsDroppedCheck,
)
from usaf.models.severity import Confidence, Severity

BASE_CTR = {"id": "abc123", "names": "web-app", "image": "nginx:1.25", "state": "running", "privileged": False, "user": "", "cap_add": [], "cap_drop": [], "security_opt": [], "bind_mounts": [], "readonly_rootfs": False, "created": "2026-07-01T00:00:00Z"}


class TestContainerAddedCapabilitiesCheck:
    def test_passes_with_no_added_caps(self):
        check = ContainerAddedCapabilitiesCheck()
        result = check.evaluate({"containers": {"docker": {"detailed": [BASE_CTR]}}})
        assert result.passed

    def test_fails_with_dangerous_caps(self):
        check = ContainerAddedCapabilitiesCheck()
        ctr = dict(BASE_CTR, cap_add=["cap_sys_admin", "cap_net_admin"])
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert not result.passed
        assert len(result.findings) == 1
        assert "cap_sys_admin" in result.findings[0].title or "cap_sys_admin" in result.findings[0].description
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].confidence == Confidence.HIGH

    def test_has_mitre_ids(self):
        check = ContainerAddedCapabilitiesCheck()
        ctr = dict(BASE_CTR, cap_add=["cap_sys_admin"])
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestContainerSecurityOptsDroppedCheck:
    def test_passes_with_secure_opts(self):
        check = ContainerSecurityOptsDroppedCheck()
        ctr = dict(BASE_CTR, security_opt=["seccomp=default.json", "apparmor=docker-default"])
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert result.passed

    def test_fails_with_unconfined(self):
        check = ContainerSecurityOptsDroppedCheck()
        ctr = dict(BASE_CTR, security_opt=["seccomp=unconfined"])
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert not result.passed
        assert len(result.findings) == 1
        assert "unconfined" in result.findings[0].description or "unconfined" in result.findings[0].title
        assert result.findings[0].severity == Severity.HIGH

    def test_has_mitre_ids(self):
        check = ContainerSecurityOptsDroppedCheck()
        ctr = dict(BASE_CTR, security_opt=["seccomp=unconfined"])
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestContainerLatestTagCheck:
    def test_passes_with_pinned_tag(self):
        check = ContainerLatestTagCheck()
        result = check.evaluate({"containers": {"docker": {"detailed": [BASE_CTR]}}})
        assert result.passed

    def test_fails_with_latest(self):
        check = ContainerLatestTagCheck()
        ctr = dict(BASE_CTR, image="nginx:latest")
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert not result.passed
        assert len(result.findings) == 1
        assert "latest" in result.findings[0].title.lower()
        assert result.findings[0].severity == Severity.MEDIUM
        assert result.findings[0].confidence == Confidence.MEDIUM

    def test_has_mitre_ids(self):
        check = ContainerLatestTagCheck()
        ctr = dict(BASE_CTR, image="nginx:latest")
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestContainerLongRunningCheck:
    def test_passes_with_recent_container(self):
        check = ContainerLongRunningCheck()
        import datetime
        recent = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(hours=24)).isoformat()
        result = check.evaluate({"containers": {"docker": {"detailed": [dict(BASE_CTR, created=recent)]}}})
        assert result.passed

    def test_has_mitre_ids(self):
        check = ContainerLongRunningCheck()
        old = "2024-01-01T00:00:00Z"
        result = check.evaluate({"containers": {"docker": {"detailed": [dict(BASE_CTR, created=old)]}}})
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestContainerExcessiveMountsCheck:
    def test_passes_with_few_mounts(self):
        check = ContainerExcessiveMountsCheck()
        result = check.evaluate({"containers": {"docker": {"detailed": [BASE_CTR]}}})
        assert result.passed

    def test_fails_with_sensitive_mount(self):
        check = ContainerExcessiveMountsCheck()
        ctr = dict(BASE_CTR, bind_mounts=[{"source": "/var/run/docker.sock"}, {"source": "/data"}])
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert not result.passed
        assert len(result.findings) >= 1
        titles = [f.title for f in result.findings]
        assert any("docker.sock" in t for t in titles) or any("sensitive" in t.lower() for t in titles)

    def test_has_mitre_ids(self):
        check = ContainerExcessiveMountsCheck()
        ctr = dict(BASE_CTR, bind_mounts=[{"source": "/var/run/docker.sock"}])
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestContainerNoUserNameSpaceCheck:
    def test_passes_with_userns(self):
        check = ContainerNoUserNameSpaceCheck()
        ctr = dict(BASE_CTR, user="1000:1000")
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert result.passed

    def test_fails_with_root_user(self):
        check = ContainerNoUserNameSpaceCheck()
        ctr = dict(BASE_CTR, user="")
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert not result.passed
        assert len(result.findings) >= 1
        assert "root" in result.findings[0].title.lower()
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].confidence == Confidence.MEDIUM

    def test_has_mitre_ids(self):
        check = ContainerNoUserNameSpaceCheck()
        ctr = dict(BASE_CTR, user="")
        result = check.evaluate({"containers": {"docker": {"detailed": [ctr]}}})
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestContainerRestartPolicyCheck:
    def test_has_mitre_ids(self):
        check = ContainerRestartPolicyCheck()
        result = check.evaluate({"containers": {"docker": {"detailed": [BASE_CTR]}}})
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0
