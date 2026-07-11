from __future__ import annotations

import datetime
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import NetworkEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class DockerTCPExposureCheck(AuditCheck):
    id = "CTN-102"
    name = "Docker Daemon TCP Exposure"
    category = CheckCategory.CONTAINERS
    severity = Severity.CRITICAL
    description = "Detects Docker daemon listening on TCP sockets (not just Unix socket)"
    depends = ["containers"]
    tags = ["containers", "docker", "network", "tcp"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        data = self._get_data(collectors, "containers")
        docker = data.get("docker", {})
        runtimes = data.get("runtimes", [])

        for rt in runtimes:
            if rt.get("name") in ("docker", "containerd") and rt.get("socket_exists"):
                return findings

        if docker.get("installed") and docker.get("running"):
            import subprocess
            try:
                r = subprocess.run(
                    ["docker", "info", "--format", "{{.HostRoot}}"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
            except (OSError, subprocess.SubprocessError):
                pass

            try:
                r = subprocess.run(
                    ["ss", "-tlnp"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                for line in r.stdout.splitlines():
                    if "docker" in line or "dockerd" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            addr = parts[3]
                            if addr.startswith("0.0.0.0:") or addr.startswith(":::"):
                                findings.append(
                                    self.finding(
                                        finding_id="001",
                                        title="Docker daemon exposed on TCP socket",
                                        description=f"Docker daemon is listening on {addr}. "
                                        "Docker should only listen on the Unix socket "
                                        "unless remote API access is explicitly required.",
                                        rationale="Exposing the Docker daemon on TCP allows "
                                        "remote attackers to interact with the Docker API. "
                                        "This can lead to container escape, host compromise, "
                                        "and cryptojacking if exposed to the network.",
                                        remediation="Edit /etc/docker/daemon.json and remove "
                                        "'hosts': ['tcp://0.0.0.0:2375'] or similar. "
                                        "Restart docker: systemctl restart docker. "
                                        "Use TLS certificates if remote API is required.",
                                        evidence=NetworkEvidence(
                                            protocol="tcp",
                                            local_address=addr.split(":")[0],
                                            local_port=int(addr.split(":")[1]),
                                            state="LISTEN",
                                            process_name="dockerd",
                                        ),
                                        detected_value=f"Listening on {addr}",
                                        expected_value="Unix socket only (/var/run/docker.sock)",
                                        affected_component="dockerd",
                                        confidence=Confidence.HIGH,
                                        false_positive_probability=0.05,
                                        mitre_attack_ids=["T1610", "T1190"],
                                        tags=["docker", "network", "remote-api"],
                                    )
                                )
            except (OSError, subprocess.SubprocessError):
                pass
        return findings


@register_check
class PrivilegedContainersCheck(AuditCheck):
    id = "CTN-201"
    name = "Privileged Containers"
    category = CheckCategory.CONTAINERS
    severity = Severity.CRITICAL
    description = "Detects containers running with elevated privileges (--privileged)"
    depends = ["containers"]
    tags = ["containers", "docker", "privileged", "privilege-escalation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        containers = self._get_containers(collectors)
        for c in containers:
            if c.get("privileged"):
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Privileged container: {c.get('image', '?')}",
                        description=f"Container '{c.get('image', '?')}' ({c.get('id', '?')[:12]}) "
                        "is running in privileged mode. Privileged containers have all "
                        "capabilities and can access all host devices.",
                        rationale="Privileged containers bypass all isolation mechanisms. "
                        "A compromised privileged container gives the attacker full root "
                        "access to the host system via container escape.",
                        remediation="Remove '--privileged' flag and use specific capabilities "
                        "instead. Example: --cap-add=NET_ADMIN --cap-add=SYS_TIME. "
                        f"Container: {c.get('id', '?')[:12]}",
                        evidence=RegistryEvidence(
                            key=f"container.{c.get('id', '?')[:12]}.privileged",
                            value="true",
                            expected="false",
                            source="docker inspect",
                        ),
                        detected_value="Privileged: true",
                        expected_value="Privileged: false",
                        affected_component=f"container/{c.get('id', '?')[:12]}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.02,
                        mitre_attack_ids=["T1610", "T1611", "T1548"],
                        tags=["containers", "privileged", "escape"],
                    )
                )
        return findings

    @staticmethod
    def _get_containers(data: dict) -> list[dict]:
        containers: list[dict] = []
        for runtime in ("docker", "podman"):
            for c in data.get(runtime, {}).get("detailed", []):
                containers.append(c)
        return containers


@register_check
class HostNetworkContainersCheck(AuditCheck):
    id = "CTN-202"
    name = "Containers Using Host Network"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Detects containers using the host network namespace (--network=host)"
    depends = ["containers"]
    tags = ["containers", "docker", "network", "isolation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        containers = PrivilegedContainersCheck._get_containers(collectors)
        for c in containers:
            if c.get("host_network"):
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Host network container: {c.get('image', '?')}",
                        description=f"Container '{c.get('image', '?')}' ({c.get('id', '?')[:12]}) "
                        "uses the host network namespace. It can access all host network "
                        "interfaces and ports.",
                        rationale="Host network containers bypass network isolation. If compromised, "
                        "attackers can sniff host network traffic, bind to privileged ports, "
                        "and access internal services.",
                        remediation="Remove '--network=host' and use port mapping instead: "
                        "-p <host_port>:<container_port>. "
                        f"Container: {c.get('id', '?')[:12]}",
                        evidence=RegistryEvidence(
                            key=f"container.{c.get('id', '?')[:12]}.network_mode",
                            value="host",
                            expected="default (bridge)",
                            source="docker inspect",
                        ),
                        detected_value="Host network: true",
                        expected_value="Host network: false",
                        affected_component=f"container/{c.get('id', '?')[:12]}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1610", "T1611"],
                        tags=["containers", "network", "host-network"],
                    )
                )
        return findings


@register_check
class HostPIDContainersCheck(AuditCheck):
    id = "CTN-203"
    name = "Containers Using Host PID Namespace"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Detects containers using the host PID namespace (--pid=host)"
    depends = ["containers"]
    tags = ["containers", "docker", "pid", "isolation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        containers = PrivilegedContainersCheck._get_containers(collectors)
        for c in containers:
            if c.get("host_pid"):
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Host PID namespace container: {c.get('image', '?')}",
                        description=f"Container '{c.get('image', '?')}' ({c.get('id', '?')[:12]}) "
                        "uses the host PID namespace. It can see all host processes.",
                        rationale="Host PID containers can see all host processes, including "
                        "those of other containers. This breaks isolation and allows "
                        "process discovery for targeted attacks.",
                        remediation="Remove '--pid=host'. Use --pid=container:<id> for "
                        "specific container sharing if needed. "
                        f"Container: {c.get('id', '?')[:12]}",
                        evidence=RegistryEvidence(
                            key=f"container.{c.get('id', '?')[:12]}.pid_mode",
                            value="host",
                            expected="default (isolated)",
                            source="docker inspect",
                        ),
                        detected_value="Host PID: true",
                        expected_value="Host PID: false (isolated)",
                        affected_component=f"container/{c.get('id', '?')[:12]}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1610", "T1611"],
                        tags=["containers", "pid", "host-pid", "isolation"],
                    )
                )
        return findings


@register_check
class HostMountsContainersCheck(AuditCheck):
    id = "CTN-204"
    name = "Containers Mounting Host Filesystem"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Detects containers with host filesystem mounts (bind mounts)"
    depends = ["containers"]
    tags = ["containers", "docker", "mounts", "isolation"]

    _SENSITIVE_HOST_PATHS = (
        "/etc/", "/var/run/docker.sock", "/proc/", "/sys/",
        "/dev/", "/boot/", "/root/", "/home/",
        "/var/log/", "/var/lib/", "/var/spool/",
    )

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        containers = PrivilegedContainersCheck._get_containers(collectors)
        for c in containers:
            mounts = c.get("bind_mounts", [])
            sensitive_mounts = [
                m for m in mounts
                if any(m.get("source", "").startswith(p) for p in self._SENSITIVE_HOST_PATHS)
            ]
            if sensitive_mounts:
                mount_desc = "; ".join(
                    f"{m['source']} -> {m['destination']}" for m in sensitive_mounts
                )
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Sensitive host mount in container: {c.get('image', '?')}",
                        description=f"Container '{c.get('image', '?')}' ({c.get('id', '?')[:12]}) "
                        f"mounts sensitive host paths: {mount_desc}",
                        rationale="Host filesystem mounts allow containers to read and write "
                        "the host filesystem. A compromised container can modify system files, "
                        "install persistence, and escalate to root on the host.",
                        remediation=f"Review the mount: {mount_desc}. Use named volumes instead "
                        f"of bind mounts for persistence. Avoid mounting the Docker socket. "
                        f"Container: {c.get('id', '?')[:12]}",
                        evidence=RegistryEvidence(
                            key=f"container.{c.get('id', '?')[:12]}.mounts",
                            value=mount_desc,
                            expected="No sensitive host mounts",
                            source="docker inspect",
                        ),
                        detected_value=f"Sensitive mounts: {len(sensitive_mounts)}",
                        expected_value="No sensitive host mounts",
                        affected_component=f"container/{c.get('id', '?')[:12]}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1610", "T1611"],
                        tags=["containers", "mounts", "host-filesystem"],
                    )
                )
        return findings


@register_check
class RootContainersCheck(AuditCheck):
    id = "CTN-301"
    name = "Containers Running as Root"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Detects containers running as root (no USER directive in Dockerfile)"
    depends = ["containers"]
    tags = ["containers", "docker", "root", "least-privilege"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        containers = PrivilegedContainersCheck._get_containers(collectors)
        for c in containers:
            user = c.get("user", "")
            if not user or user == "" or user == "0" or user == "root":
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Container running as root: {c.get('image', '?')}",
                        description=f"Container '{c.get('image', '?')}' ({c.get('id', '?')[:12]}) "
                        f"runs as root (user: {user or 'root'}). "
                        "Containers should run with a non-root user.",
                        rationale="Root inside a container has elevated capabilities and can "
                        "perform privileged operations. If the container is compromised, "
                        "root access makes container escape easier.",
                        remediation="Add a USER directive to the Dockerfile. "
                        "Example: RUN useradd -m appuser && USER appuser. "
                        f"Container: {c.get('id', '?')[:12]}. "
                        "Use --user flag in docker run as temporary fix.",
                        evidence=RegistryEvidence(
                            key=f"container.{c.get('id', '?')[:12]}.user",
                            value=user or "root",
                            expected="non-root user (1000+)",
                            source="docker inspect",
                        ),
                        detected_value=f"Running as: {user or 'root'}",
                        expected_value="Running as non-root user",
                        affected_component=f"container/{c.get('id', '?')[:12]}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.15,
                        mitre_attack_ids=["T1610", "T1548"],
                        tags=["containers", "root", "least-privilege"],
                    )
                )
        return findings


@register_check
class OldImagesCheck(AuditCheck):
    id = "CTN-401"
    name = "Container Images Older Than 30 Days"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Detects containers using images created more than 30 days ago"
    depends = ["containers"]
    tags = ["containers", "docker", "images", "vulnerabilities"]

    _MAX_AGE_DAYS = 30

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        containers = PrivilegedContainersCheck._get_containers(collectors)
        for c in containers:
            created_str = c.get("created", "")
            if not created_str:
                continue
            created_dt = self._parse_created(created_str)
            if created_dt is None:
                continue
            age = (datetime.datetime.now(datetime.timezone.utc) - created_dt).days
            if age > self._MAX_AGE_DAYS:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Old container image: {c.get('image', '?')}",
                        description=f"Container '{c.get('image', '?')}' ({c.get('id', '?')[:12]}) "
                        f"was created {age} days ago. Images older than {self._MAX_AGE_DAYS} "
                        "days may contain unpatched vulnerabilities.",
                        rationale="Old container images accumulate unpatched vulnerabilities. "
                        "Attackers exploit known CVEs in outdated base images for initial "
                        "access and container escape.",
                        remediation=f"Pull the latest image: docker pull {c.get('image', '?')} "
                        "and recreate the container. "
                        "Use automated image update pipelines and vulnerability scanning.",
                        evidence=RegistryEvidence(
                            key=f"container.{c.get('id', '?')[:12]}.age_days",
                            value=str(age),
                            expected=f"< {self._MAX_AGE_DAYS} days",
                            source="docker inspect",
                        ),
                        detected_value=f"Image age: {age} days",
                        expected_value=f"Image age < {self._MAX_AGE_DAYS} days",
                        affected_component=f"container/{c.get('id', '?')[:12]}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1190", "T1610"],
                        tags=["containers", "images", "vulnerabilities", "aging"],
                    )
                )
        return findings

    @staticmethod
    def _parse_created(created_str: str) -> datetime.datetime | None:
        for fmt in (
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S %z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
        ):
            try:
                dt = datetime.datetime.strptime(created_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt
            except ValueError:
                continue
        return None


@register_check
class DockerDaemonSecurityCheck(AuditCheck):
    id = "CTN-302"
    name = "Docker Daemon Security Configuration"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Checks Docker daemon config for missing security hardening options"
    depends = []
    tags = ["containers", "docker", "daemon", "hardening"]

    RECOMMENDED_CONFIG: dict[str, tuple[str, str, str]] = {
        "userns-remap": ("default", "User namespace remapping", "Prevents root inside containers from mapping to root on host"),
        "live-restore": ("true", "Live restore", "Keeps containers running when dockerd restarts"),
        "no-new-privileges": ("true", "No new privileges", "Prevents privilege escalation via setuid binaries"),
        "icc": ("false", "Inter-container communication", "Prevents all container-to-container traffic by default"),
        "log-driver": ("journald", "Log driver", "Ensures container logs go to journald for audit trail"),
        "userland-proxy": ("false", "Userland proxy", "Disables the userland proxy (uses hairpin NAT instead)"),
        "iptables": ("true", "iptables management", "Ensures Docker manages iptables rules"),
    }

    def _run_check(self, collectors: dict) -> list:
        findings: list = []
        config = self._read_daemon_config()
        if config is None:
            return findings

        for key, (expected, name, rationale) in self.RECOMMENDED_CONFIG.items():
            actual = config.get(key)
            actual_str = str(actual).lower() if actual is not None else "not set"

            if key == "userns-remap" and actual is not None:
                continue
            if actual_str == expected:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Docker daemon missing security option: {name}",
                    description=(
                        f"Docker daemon config '{key}' is set to '{actual_str}' "
                        f"(expected '{expected}'). {rationale}."
                    ),
                    rationale=(
                        f"{rationale}. Docker's default configuration prioritizes "
                        "ease-of-use over security. Each missing hardening option "
                        "increases the blast radius of a container compromise."
                    ),
                    remediation=(
                        f"Add '{key}: {expected}' to /etc/docker/daemon.json "
                        f"and restart: 'systemctl restart docker'"
                    ),
                    evidence=FileEvidence(
                        path="/etc/docker/daemon.json",
                        content=f"{key}: {actual_str} (expected: {expected})",
                    ),
                    detected_value=f"{key}: {actual_str}",
                    expected_value=f"{key}: {expected}",
                    affected_component="docker-daemon",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1610"],
                    cis_benchmarks=["CIS Docker 1.6: 1.1", "CIS Docker 1.6: 5.1"],
                    tags=["containers", "docker", "hardening"],
                )
            )

        if not config.get("log-opts"):
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Docker daemon missing log shipping configuration",
                    description="Docker daemon has no log-opts configured for log shipping and rotation.",
                    rationale="Without log rotation or shipping, container logs can fill up disk space "
                    "and forensic evidence may be lost. Centralized logging is critical for incident response.",
                    remediation="Add log shipping to daemon.json: "
                    '"log-driver": "journald" or "log-driver": "syslog". '
                    "Configure log rotation with max-size and max-file options.",
                    evidence=FileEvidence(
                        path="/etc/docker/daemon.json",
                        content="log-opts: not configured",
                    ),
                    detected_value="No log-opts configured",
                    expected_value="log-opts with max-size and/or log driver",
                    affected_component="docker-daemon",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1610"],
                    tags=["containers", "docker", "logging"],
                )
            )

        return findings

    @staticmethod
    def _read_daemon_config() -> dict | None:
        import json
        daemon_json = Path("/etc/docker/daemon.json")
        if not daemon_json.exists():
            return None
        try:
            return json.loads(daemon_json.read_text())
        except (json.JSONDecodeError, OSError):
            return {}


@register_check
class UnsignedImagesCheck(AuditCheck):
    id = "CTN-402"
    name = "Container Images Without Signing Verification"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Detects container images used without content trust (Docker Content Trust / Notary)"
    depends = ["containers"]
    tags = ["containers", "docker", "images", "supply-chain"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        containers = PrivilegedContainersCheck._get_containers(collectors)
        if not containers:
            return findings

        import os
        dct_enabled = os.environ.get("DOCKER_CONTENT_TRUST") == "1"

        image_count = len(set(c.get("image", "") for c in containers if c.get("image")))
        if image_count == 0:
            return findings

        if not dct_enabled:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Docker Content Trust not enabled",
                    description=f"Docker Content Trust is not enabled "
                    f"(DOCKER_CONTENT_TRUST != 1). {image_count} image(s) are used without "
                    "signature verification.",
                    rationale="Without content trust, Docker pulls and runs unsigned images. "
                    "Attackers can perform supply chain attacks by publishing malicious "
                    "images with the same tag.",
                    remediation="Export DOCKER_CONTENT_TRUST=1 in the Docker daemon "
                    "environment or systemd unit file. "
                    "This ensures images are signed before pull/run. "
                    "Use Docker Trusted Registry or Notary for image signing.",
                    evidence=RegistryEvidence(
                        key="DOCKER_CONTENT_TRUST",
                        value="0",
                        expected="1",
                        source="environment",
                    ),
                    detected_value="Content trust: disabled",
                    expected_value="Content trust: enabled",
                    affected_component="docker",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1554", "T1195", "T1195.001"],
                    tags=["containers", "supply-chain", "images", "signing"],
                )
            )
        return findings
