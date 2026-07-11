from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class DockerSocketCheck(AuditCheck):
    id = "CTN-001"
    name = "Docker Socket Permissions"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Checks that the Docker socket has appropriate ownership and permissions"
    depends = []
    tags = ["containers", "docker", "permissions"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []
        sock = Path("/var/run/docker.sock")
        if not sock.exists():
            return findings
        try:
            st = sock.stat()
        except OSError:
            return findings
        mode = st.st_mode & 0o7777
        owner = st.st_uid
        issues = []
        if owner != 0:
            issues.append("not owned by root")
        if mode & 0o007:
            issues.append("world-accessible")
        if mode & 0o022:
            issues.append("group-writable or world-writable")
        if not issues:
            return findings
        findings.append(
            self.finding(
                finding_id="001",
                title=f"Docker socket is insecure: {', '.join(issues)}",
                description=f"Docker socket {sock} has mode {oct(mode)}, owned by UID {owner}",
                rationale=(
                    "The Docker socket provides root-equivalent access to the Docker daemon. "
                    "Any user or group with access can create privileged containers, "
                    "mount host filesystems, and escalate to root. The socket should be owned by "
                    "root:docker with mode 660 or stricter."
                ),
                remediation=(
                    f"'chown root:docker {sock} && chmod 660 {sock}'. "
                    "Only trusted users should be in the 'docker' group. "
                    "Consider rootless Docker or Podman for production."
                ),
                evidence=FileEvidence(
                    path=str(sock),
                    permission=oct(mode),
                    owner=str(owner),
                    content=f"Mode {oct(mode)}, owner UID {owner}",
                ),
                detected_value=f"Mode {oct(mode)}, owner UID {owner}",
                expected_value="Mode 660, owner root:docker",
                affected_component=str(sock),
                reference="https://docs.docker.com/engine/security/",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                mitre_attack_ids=["T1610"],
                tags=["containers", "docker", "privilege-escalation"],
            )
        )
        return findings
