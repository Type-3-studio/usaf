from __future__ import annotations

import os
import stat
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

DANGEROUS_CAPABILITIES: set[str] = {
    "CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH",
    "CAP_SETUID", "CAP_SETGID", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO", "CAP_SYS_BOOT", "CAP_KILL", "CAP_LINUX_IMMUTABLE",
    "CAP_NET_ADMIN", "CAP_SYSLOG", "CAP_AUDIT_CONTROL",
}


def _get_containers(data: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    docker = data.get("docker", {})
    detailed: list[dict[str, Any]] = docker.get("detailed", [])
    result.extend(detailed)
    return result


@register_check
class DangerousCapabilitiesCheck(AuditCheck):
    id = "CTN-303"
    name = "Containers With Dangerous Capabilities"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Detects containers running with added dangerous Linux capabilities"
    depends = ["containers"]
    tags = ["containers", "capabilities", "privilege-escalation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        data = self._get_data(collectors, "containers")
        findings: list = []

        for c in _get_containers(data):
            cap_add: list[str] = c.get("cap_add", [])
            found = [cap for cap in cap_add if cap.upper() in DANGEROUS_CAPABILITIES]
            if not found:
                continue
            cid: str = c.get("id", "")[:12]
            image: str = c.get("image", "unknown")
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Dangerous capabilities added to container {image[:40]}",
                    description=(
                        f"Container {cid} ({image}) has added capabilities: "
                        f"{', '.join(found)}"
                    ),
                    rationale=(
                        "Linux capabilities like CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, "
                        "and CAP_SYS_PTRACE grant privileges equivalent to root. "
                        "A compromised container with these capabilities can "
                        "escape to the host."
                    ),
                    remediation=(
                        f"Remove dangerous capabilities from container {cid}: "
                        f"remove '--cap-add={found[0]}' from docker run. "
                        f"Use '--cap-drop=ALL' and add only needed caps."
                    ),
                    evidence=RegistryEvidence(
                        key=f"container.{cid}.cap_add",
                        value=", ".join(found),
                        expected="No dangerous capabilities added",
                        source=f"container {cid}",
                    ),
                    detected_value=f"Capabilities: {', '.join(found)} on {image}",
                    expected_value="No dangerous capabilities",
                    affected_component=f"container/{cid}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1548.003"],
                    tags=["containers", "capabilities", "privilege-escalation"],
                )
            )

        return findings


@register_check
class MissingSecurityOptsCheck(AuditCheck):
    id = "CTN-304"
    name = "Containers Without Security Options"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Detects containers missing security options like no-new-privileges"
    depends = ["containers"]
    tags = ["containers", "hardening", "security"]

    _recommended_opts: dict[str, str] = {
        "no-new-privileges": "Prevents privilege escalation via setuid binaries",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        data = self._get_data(collectors, "containers")
        findings: list = []

        for c in _get_containers(data):
            sec_opts: list[str] = [s.lower() for s in c.get("security_opt", [])]
            cid: str = c.get("id", "")[:12]
            image: str = c.get("image", "unknown")

            missing = [
                opt for opt in self._recommended_opts
                if opt not in sec_opts
            ]
            if not missing:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Container {image[:40]} missing security options",
                    description=(
                        f"Container {cid} ({image}) is missing recommended "
                        f"security options: {', '.join(missing)}"
                    ),
                    rationale=(
                        "Security options like no-new-privileges prevent "
                        "privilege escalation within the container. Without them, "
                        "a compromised container process can use setuid binaries "
                        "to gain additional privileges."
                    ),
                    remediation=(
                        f"Add --security-opt=no-new-privileges to container {cid}. "
                        "Also consider --security-opt=apparmor=PROFILE and "
                        "--security-opt=seccomp=default.json"
                    ),
                    evidence=RegistryEvidence(
                        key=f"container.{cid}.security_opt",
                        value=", ".join(sec_opts) if sec_opts else "none",
                        expected=f"Contains: {', '.join(self._recommended_opts.keys())}",
                        source=f"container {cid}",
                    ),
                    detected_value=f"Missing: {', '.join(missing)} on {image}",
                    expected_value="All recommended security options present",
                    affected_component=f"container/{cid}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.15,
                    mitre_attack_ids=["T1548.001"],
                    tags=["containers", "hardening"],
                )
            )

        return findings


@register_check
class ReadOnlyRootFSCheck(AuditCheck):
    id = "CTN-305"
    name = "Containers Without Read-Only Root Filesystem"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Detects containers running without a read-only root filesystem"
    depends = ["containers"]
    tags = ["containers", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        data = self._get_data(collectors, "containers")
        findings: list = []

        for c in _get_containers(data):
            if c.get("readonly_rootfs", False):
                continue
            cid: str = c.get("id", "")[:12]
            image: str = c.get("image", "unknown")
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Container {image[:40]} has writable root filesystem",
                    description=(
                        f"Container {cid} ({image}) is running without "
                        f"--read-only root filesystem"
                    ),
                    rationale=(
                        "A writable root filesystem allows a compromised container "
                        "to modify system binaries, install malware, and persist "
                        "changes. Using --read-only forces all writes to ephemeral "
                        "storage, reducing the attack surface."
                    ),
                    remediation=(
                        f"Add --read-only to container {cid}. "
                        "Use --tmpfs /tmp --tmpfs /var/run for writable directories."
                    ),
                    evidence=RegistryEvidence(
                        key=f"container.{cid}.readonly_rootfs",
                        value="false",
                        expected="true",
                        source=f"container {cid}",
                    ),
                    detected_value=f"Writable rootfs on {image}",
                    expected_value="Read-only root filesystem",
                    affected_component=f"container/{cid}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.15,
                    mitre_attack_ids=["T1204.002"],
                    tags=["containers", "hardening"],
                )
            )

        return findings


@register_check
class HostIPCCheck(AuditCheck):
    id = "CTN-306"
    name = "Containers Using Host IPC Namespace"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Detects containers using the host IPC namespace (--ipc=host)"
    depends = ["containers"]
    tags = ["containers", "ipc", "privilege-escalation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        data = self._get_data(collectors, "containers")
        findings: list = []

        for c in _get_containers(data):
            if not c.get("host_ipc", False):
                continue
            cid: str = c.get("id", "")[:12]
            image: str = c.get("image", "unknown")
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Container {image[:40]} uses host IPC namespace",
                    description=(
                        f"Container {cid} ({image}) runs with --ipc=host, "
                        f"sharing the host's IPC namespace"
                    ),
                    rationale=(
                        "Host IPC namespace allows the container to access "
                        "the host's inter-process communication resources, "
                        "including shared memory segments and semaphores. "
                        "This can be used for cross-container attacks and "
                        "host resource manipulation."
                    ),
                    remediation=(
                        f"Remove --ipc=host from container {cid}. "
                        "Use a shared IPC namespace only when required."
                    ),
                    evidence=RegistryEvidence(
                        key=f"container.{cid}.host_ipc",
                        value="true",
                        expected="false",
                        source=f"container {cid}",
                    ),
                    detected_value=f"host_ipc=true on {image}",
                    expected_value="host_ipc=false",
                    affected_component=f"container/{cid}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1611"],
                    tags=["containers", "ipc", "privilege-escalation"],
                )
            )

        return findings


@register_check
class ExposedContainerPortsCheck(AuditCheck):
    id = "CTN-307"
    name = "Containers With Exposed Port Bindings"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Detects containers exposing ports with host bindings"
    depends = ["containers"]
    tags = ["containers", "network", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        data = self._get_data(collectors, "containers")
        findings: list = []

        for c in _get_containers(data):
            port_bindings: dict[str, Any] = c.get("port_bindings", {})
            if not port_bindings:
                continue
            cid: str = c.get("id", "")[:12]
            image: str = c.get("image", "unknown")
            exposed: list[str] = []
            for container_port, host_config in port_bindings.items():
                if isinstance(host_config, list):
                    for binding in host_config:
                        host_ip = binding.get("HostIp", "0.0.0.0") if isinstance(binding, dict) else "0.0.0.0"
                        if host_ip in ("0.0.0.0", "::"):
                            exposed.append(f"{container_port} -> {host_ip}:{binding.get('HostPort', '?') if isinstance(binding, dict) else '?'}")

            if exposed:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Container {image[:40]} exposes ports to all interfaces",
                        description=(
                            f"Container {cid} ({image}) exposes ports "
                            f"on all interfaces: {', '.join(exposed[:5])}"
                        ),
                        rationale=(
                            "Container ports bound to 0.0.0.0 are accessible "
                            "from any network. For defense-in-depth, services "
                            "should bind to localhost unless remote access is "
                            "explicitly required."
                        ),
                        remediation=(
                            f"Bind ports to localhost: -p 127.0.0.1:{exposed[0].split('->')[0].strip()}"
                            " or remove the port mapping if not needed."
                        ),
                        evidence=RegistryEvidence(
                            key=f"container.{cid}.port_bindings",
                            value=", ".join(exposed[:5]),
                            expected="Ports bound to 127.0.0.1 or no bindings",
                            source=f"container {cid}",
                        ),
                        detected_value=f"Exposed ports: {', '.join(exposed[:5])}",
                        expected_value="Ports not exposed to all interfaces",
                        affected_component=f"container/{cid}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1046"],
                        tags=["containers", "network", "exposure"],
                    )
                )

        return findings


@register_check
class RuntimeSocketExposureCheck(AuditCheck):
    id = "CTN-501"
    name = "Container Runtime Socket Exposure"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Checks that container runtime sockets have restricted permissions"
    depends = ["containers"]
    tags = ["containers", "sockets", "privilege-escalation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        data = self._get_data(collectors, "containers")
        findings: list = []
        runtimes: list[dict[str, Any]] = data.get("runtimes", [])

        for rt in runtimes:
            socket_path: str = rt.get("socket", "")
            if not socket_path or not rt.get("socket_exists", False):
                continue
            try:
                st = os.stat(socket_path)
                mode = st.st_mode & 0o7777
                if mode & stat.S_IWOTH:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"{rt.get('name', 'unknown')} socket is world-writable",
                            description=(
                                f"Socket at {socket_path} has permissions "
                                f"{oct(mode)} (world-writable)"
                            ),
                            rationale=(
                                "Container runtime sockets grant full access to the "
                                "container runtime. A world-writable socket allows "
                                "any user to create, start, and exec into containers, "
                                "leading to privilege escalation."
                            ),
                            remediation=(
                                f"Fix permissions: 'chmod 660 {socket_path}'. "
                                f"Ensure the socket is owned by the docker group: "
                                f"'chown root:docker {socket_path}'."
                            ),
                            evidence=FileEvidence(
                                path=socket_path,
                                permission=oct(mode),
                            ),
                            detected_value=f"World-writable: {socket_path}",
                            expected_value="Socket not world-writable",
                            affected_component=socket_path,
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.0,
                            mitre_attack_ids=["T1611"],
                            tags=["containers", "sockets", "privilege-escalation"],
                        )
                    )
                if mode & stat.S_IRGRP == 0 and rt.get("name") == "docker":
                    findings.append(
                        self.finding(
                            finding_id="002",
                            title=f"{rt.get('name', 'unknown')} socket not group-readable",
                            description=(
                                f"Socket at {socket_path} has permissions "
                                f"{oct(mode)} which may prevent non-root access "
                                f"for authorized users"
                            ),
                            rationale=(
                                "The Docker socket should be readable by the docker "
                                "group to allow non-root users to run Docker commands. "
                                "Common permissions: 660 (root:docker)."
                            ),
                            remediation=(
                                f"Set group: 'chown root:docker {socket_path}'. "
                                f"Set permissions: 'chmod 660 {socket_path}'."
                            ),
                            evidence=FileEvidence(
                                path=socket_path,
                                permission=oct(mode),
                            ),
                            detected_value=f"Socker permissions: {oct(mode)}",
                            expected_value="660 (rw-rw----)",
                            affected_component=socket_path,
                            confidence=Confidence.LOW,
                            false_positive_probability=0.2,
                            tags=["containers", "sockets", "configuration"],
                        )
                    )
            except OSError:
                continue

        return findings


@register_check
class MultipleRuntimesCheck(AuditCheck):
    id = "CTN-502"
    name = "Multiple Container Runtimes Installed"
    category = CheckCategory.CONTAINERS
    severity = Severity.LOW
    description = "Detects multiple container runtimes installed when one may suffice"
    depends = ["containers"]
    tags = ["containers", "runtimes", "attack-surface"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        data = self._get_data(collectors, "containers")
        findings: list = []

        runtimes: list[dict[str, Any]] = data.get("runtimes", [])
        installed = [r for r in runtimes if r.get("socket_exists", False)]

        if len(installed) > 1:
            names = [r.get("name", "unknown") for r in installed]
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"{len(installed)} container runtimes installed",
                    description=(
                        f"Multiple container runtimes detected: "
                        f"{', '.join(names)}. "
                        "Each runtime increases attack surface."
                    ),
                    rationale=(
                        "Each container runtime socket is a potential privilege "
                        "escalation vector. Installing multiple runtimes when "
                        "only one is needed unnecessarily increases attack surface."
                    ),
                    remediation=(
                        "Remove unused container runtimes. "
                        "Keep only the runtime you actively use."
                    ),
                    evidence=RegistryEvidence(
                        key="runtimes.installed",
                        value=", ".join(names),
                        expected="Single container runtime",
                        source="container runtime sockets",
                    ),
                    detected_value=f"Installed: {', '.join(names)}",
                    expected_value="One container runtime",
                    affected_component="container runtimes",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.3,
                    tags=["containers", "runtimes", "attack-surface"],
                )
            )

        return findings


@register_check
class ContainerRestartLoopCheck(AuditCheck):
    id = "CTN-601"
    name = "Containers in Restart Loop"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Detects containers that are repeatedly restarting"
    depends = ["containers"]
    tags = ["containers", "stability", "monitoring"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        data = self._get_data(collectors, "containers")
        findings: list = []
        docker = data.get("docker", {})
        containers: list[dict[str, Any]] = docker.get("containers", [])

        for c in containers:
            status: str = c.get("status", "")
            status_lower = status.lower()
            if "restarting" in status_lower:
                cid: str = c.get("id", "")[:12]
                image: str = c.get("image", "unknown")
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Container {image[:40]} is restarting",
                        description=(
                            f"Container {cid} ({image}) has status "
                            f"'{status}' — currently restarting"
                        ),
                        rationale=(
                            "A container that is repeatedly restarting indicates "
                            "a crash loop or configuration issue. This may cause "
                            "service disruption and logs may fill up quickly."
                        ),
                        remediation=(
                            f"Check logs: 'docker logs {cid}'. "
                            f"Review configuration and fix the startup issue."
                        ),
                        evidence=RegistryEvidence(
                            key=f"container.{cid}.status",
                            value=status,
                            expected="running or exited (not restarting)",
                            source=f"container {cid}",
                        ),
                        detected_value=f"Status: {status}",
                        expected_value="running or exited normally",
                        affected_component=f"container/{cid}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.0,
                        tags=["containers", "stability", "monitoring"],
                    )
                )

        return findings
