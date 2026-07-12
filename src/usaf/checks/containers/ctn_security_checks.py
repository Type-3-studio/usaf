from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


DEFAULT_CONTAINER_CAPS: set[str] = {
    "cap_chown", "cap_dac_override", "cap_fowner", "cap_fsetid",
    "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap",
    "cap_net_bind_service", "cap_net_raw", "cap_sys_chroot",
    "cap_audit_write", "cap_setfcap",
}

DANGEROUS_ADDED_CAPS: set[str] = {
    "cap_sys_admin", "cap_sys_module", "cap_sys_ptrace",
    "cap_linux_immutable", "cap_mknod", "cap_sys_rawio",
    "cap_dac_read_search", "cap_sys_boot", "cap_net_admin",
}


@register_check
class ContainerAddedCapabilitiesCheck(AuditCheck):
    id = "CTN-701"
    name = "Containers with Added Capabilities"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Detects containers with dangerous added Linux capabilities"
    depends = ["containers"]
    tags = ["containers", "docker", "capabilities", "privilege-escalation"]
    max_findings = 50

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ctr_data = self._get_data(collectors, "containers")

        for runtime in ("docker", "podman"):
            for ctr in ctr_data.get(runtime, {}).get("detailed", []):
                cap_add = [c.lower().strip() for c in ctr.get("cap_add", []) if c]
                name = ctr.get("names", ctr.get("id", ""))[:20]

                dangerous = [c for c in cap_add if c in DANGEROUS_ADDED_CAPS]

                if not dangerous:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Container '{name}' has dangerous capabilities",
                        description=f"Container has added dangerous capabilities: {', '.join(dangerous)}.",
                        rationale="Dangerous capabilities like CAP_SYS_ADMIN or CAP_SYS_MODULE grant near-root privileges inside containers, breaking container isolation.",
                        remediation=f"Remove unnecessary capabilities from container '{name}'. Use '--cap-drop=ALL --cap-add=<needed>' to follow least privilege.",
                        evidence=RegistryEvidence(key=f"container.{runtime}.{name}.cap_add", value=", ".join(cap_add), expected="no dangerous caps", source=f"{runtime} inspect"),
                        detected_value=f"Added caps: {', '.join(dangerous)}",
                        expected_value="No dangerous capabilities added",
                        affected_component=f"container:{name}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1548.001"],
                        tags=["containers", "docker", "capabilities", "privilege-escalation"],
                    )
                )
        return findings


@register_check
class ContainerSecurityOptsDroppedCheck(AuditCheck):
    id = "CTN-702"
    name = "Containers with Security Options Dropped"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Detects containers running without seccomp or AppArmor profiles"
    depends = ["containers"]
    tags = ["containers", "docker", "seccomp", "apparmor", "hardening"]
    max_findings = 50

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ctr_data = self._get_data(collectors, "containers")

        for runtime in ("docker", "podman"):
            for ctr in ctr_data.get(runtime, {}).get("detailed", []):
                sec_opt = ctr.get("security_opt", [])
                name = ctr.get("names", ctr.get("id", ""))[:20]
                sec_lower = [s.lower() for s in sec_opt]

                issues: list[str] = []
                if any("seccomp=unconfined" in s for s in sec_lower):
                    issues.append("seccomp=unconfined")
                if any("apparmor=unconfined" in s for s in sec_lower):
                    issues.append("apparmor=unconfined")
                if any("no-new-privileges:false" in s for s in sec_lower):
                    issues.append("no-new-privileges disabled")

                if not issues:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Container '{name}' has security restrictions disabled",
                        description=f"Security options disabled: {', '.join(issues)}.",
                        rationale="Disabling seccomp, AppArmor, or no-new-privileges removes critical kernel-level protections. Compromise of this container can lead to host access.",
                        remediation=f"Remove unconfined settings from container '{name}'. Use '--security-opt seccomp=default.json --security-opt apparmor=docker-default'.",
                        evidence=RegistryEvidence(key=f"container.{runtime}.{name}.security_opt", value=", ".join(sec_opt), expected="seccomp/apparmor profiles enabled", source=f"{runtime} inspect"),
                        detected_value=f"Security issues: {', '.join(issues)}",
                        expected_value="Seccomp and AppArmor profiles enabled",
                        affected_component=f"container:{name}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1562"],
                        tags=["containers", "docker", "seccomp", "apparmor", "hardening"],
                    )
                )
        return findings


@register_check
class ContainerLatestTagCheck(AuditCheck):
    id = "CTN-703"
    name = "Containers Using Latest Tag"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Detects containers running images tagged :latest instead of a pinned version"
    depends = ["containers"]
    tags = ["containers", "docker", "images", "supply-chain"]
    max_findings = 50

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ctr_data = self._get_data(collectors, "containers")

        for runtime in ("docker", "podman"):
            for ctr in ctr_data.get(runtime, {}).get("detailed", []):
                image = ctr.get("image", "")
                name = ctr.get("names", ctr.get("id", ""))[:20]

                if not image or ":" not in image:
                    continue
                if not image.endswith(":latest"):
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Container '{name}' uses :latest tag",
                        description=f"Container '{name}' is running image '{image}' with the ':latest' tag.",
                        rationale="The :latest tag is mutable and may resolve to different versions over time. Updates can introduce breaking changes, security regressions, or unexpected behavior. Pinned versions provide deterministic deployments.",
                        remediation=f"Pin the image to a specific version tag for container '{name}': 'docker pull <image>:<version>'.",
                        evidence=RegistryEvidence(key=f"container.{runtime}.{name}.image", value=image, expected="pinned version (e.g., :1.2.3)", source=f"{runtime} ps"),
                        detected_value=f"Image: {image}",
                        expected_value="Pinned version tag",
                        affected_component=f"container:{name}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1525"],
                        tags=["containers", "docker", "images", "supply-chain"],
                    )
                )
        return findings


@register_check
class ContainerLongRunningCheck(AuditCheck):
    id = "CTN-704"
    name = "Long-Running Containers"
    category = CheckCategory.CONTAINERS
    severity = Severity.LOW
    description = "Detects containers that have been running for an extended period without restart"
    depends = ["containers"]
    tags = ["containers", "docker", "uptime", "maintenance"]

    MAX_UPTIME_HOURS = 720

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ctr_data = self._get_data(collectors, "containers")

        for runtime in ("docker", "podman"):
            for ctr in ctr_data.get(runtime, {}).get("detailed", []):
                created_raw = ctr.get("created", "")
                name = ctr.get("names", ctr.get("id", ""))[:20]

                if not created_raw:
                    continue

                try:
                    import datetime
                    created = datetime.datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
                    uptime = datetime.datetime.now(datetime.timezone.utc) - created
                    hours = uptime.total_seconds() / 3600
                except (ValueError, TypeError, AttributeError):
                    continue

                if hours < self.MAX_UPTIME_HOURS:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Container '{name}' running for {int(hours)} hours",
                        description=f"Container '{name}' has been running for {int(hours)} hours (created {created_raw[:19]}).",
                        rationale="Containers running for very long periods may have accumulated memory leaks, stale connections, or kernel vulnerabilities. Regular restarts ensure fresh security contexts.",
                        remediation=f"Restart container '{name}': 'docker restart {name}'. Consider setting restart policies and scheduled maintenance.",
                        evidence=RegistryEvidence(key=f"container.{runtime}.{name}.uptime_hours", value=f"{int(hours)}h", expected=f"<{self.MAX_UPTIME_HOURS}h", source=f"{runtime} inspect"),
                        detected_value=f"Uptime: {int(hours)} hours",
                        expected_value=f"Under {self.MAX_UPTIME_HOURS} hours",
                        affected_component=f"container:{name}",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.5,
                        mitre_attack_ids=["T1499"],
                        tags=["containers", "docker", "uptime", "maintenance"],
                    )
                )
        return findings


@register_check
class ContainerExcessiveMountsCheck(AuditCheck):
    id = "CTN-705"
    name = "Containers with Excessive Bind Mounts"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Detects containers with excessive host filesystem bind mounts"
    depends = ["containers"]
    tags = ["containers", "docker", "mounts", "isolation"]

    MAX_MOUNTS = 5

    SENSITIVE_MOUNTS: set[str] = {
        "/", "/etc", "/proc", "/sys", "/boot",
        "/var/run/docker.sock", "/run/docker.sock",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ctr_data = self._get_data(collectors, "containers")

        for runtime in ("docker", "podman"):
            for ctr in ctr_data.get(runtime, {}).get("detailed", []):
                mounts = ctr.get("bind_mounts", [])
                name = ctr.get("names", ctr.get("id", ""))[:20]

                mount_paths = [m.get("source", "") for m in mounts] if isinstance(mounts, list) else []

                sensitive = [p for p in mount_paths if p in self.SENSITIVE_MOUNTS or any(p.startswith(s) for s in self.SENSITIVE_MOUNTS)]

                if len(mount_paths) <= self.MAX_MOUNTS and not sensitive:
                    continue

                if sensitive:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Container '{name}' mounts sensitive host paths",
                            description=f"Container mounts sensitive host paths: {', '.join(sensitive[:5])}. This weakens isolation significantly.",
                            rationale="Mounting sensitive host paths like /proc, /sys, or the Docker socket breaks container isolation and can allow container escape.",
                            remediation=f"Remove sensitive mounts from container '{name}'. Use volume mounts instead of bind mounts where possible.",
                            evidence=RegistryEvidence(key=f"container.{runtime}.{name}.sensitive_mounts", value=", ".join(sensitive), expected="no sensitive mounts", source=f"{runtime} inspect"),
                            detected_value=f"Sensitive mounts: {', '.join(sensitive)}",
                            expected_value="No sensitive host mounts",
                            affected_component=f"container:{name}",
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.05,
                            mitre_attack_ids=["T1611"],
                            tags=["containers", "docker", "mounts", "isolation"],
                        )
                    )
                elif len(mount_paths) > self.MAX_MOUNTS:
                    findings.append(
                        self.finding(
                            finding_id="002",
                            title=f"Container '{name}' has {len(mount_paths)} bind mounts",
                            description=f"Container has {len(mount_paths)} bind mounts. Excessive mounts increase the attack surface.",
                            rationale="Each bind mount is a potential escape vector. Containers should have minimal host filesystem access.",
                            remediation=f"Reduce bind mounts on container '{name}'. Use named volumes for persistent data.",
                            evidence=RegistryEvidence(key=f"container.{runtime}.{name}.mount_count", value=str(len(mount_paths)), expected=f"<={self.MAX_MOUNTS}", source=f"{runtime} inspect"),
                            detected_value=f"{len(mount_paths)} bind mounts",
                            expected_value=f"{self.MAX_MOUNTS} or fewer",
                            affected_component=f"container:{name}",
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.3,
                            mitre_attack_ids=["T1611"],
                            tags=["containers", "docker", "mounts", "isolation"],
                        )
                    )
        return findings


@register_check
class ContainerNoUserNameSpaceCheck(AuditCheck):
    id = "CTN-706"
    name = "Containers Without User Namespace"
    category = CheckCategory.CONTAINERS
    severity = Severity.HIGH
    description = "Detects containers running without user namespace remapping"
    depends = ["containers"]
    tags = ["containers", "docker", "userns", "hardening"]
    max_findings = 50

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ctr_data = self._get_data(collectors, "containers")

        for runtime in ("docker", "podman"):
            for ctr in ctr_data.get(runtime, {}).get("detailed", []):
                user = ctr.get("user", "")
                name = ctr.get("names", ctr.get("id", ""))[:20]

                if user and user not in ("0", "root"):
                    continue

                findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Container '{name}' runs as root",
                            description=f"Container '{name}' runs as root user (user={user or 'default'}). User namespace remapping not enabled.",
                            rationale="Containers running as root inside the container have the same UID 0 as root on the host. Without user namespace remapping, a container escape grants immediate root access on the host.",
                            remediation=f"Run container '{name}' with '--user' flag or enable userns-remap in /etc/docker/daemon.json.",
                            evidence=RegistryEvidence(key=f"container.{runtime}.{name}.user", value=str(user) or "default (root)", expected="non-root user ID", source=f"{runtime} inspect"),
                            detected_value=f"Container runs as user: {user or 'root'}",
                            expected_value="Non-root user with userns-remap",
                            affected_component=f"container:{name}",
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.2,
                            mitre_attack_ids=["T1611"],
                            tags=["containers", "docker", "userns", "hardening"],
                        )
                    )
        return findings


@register_check
class ContainerRestartPolicyCheck(AuditCheck):
    id = "CTN-707"
    name = "Containers Without Restart Policy"
    category = CheckCategory.CONTAINERS
    severity = Severity.MEDIUM
    description = "Detects containers without a restart policy configured"
    depends = ["containers"]
    tags = ["containers", "docker", "availability", "resilience"]
    max_findings = 50

    RESTART_POLICIES: set[str] = {"always", "unless-stopped", "on-failure"}

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        ctr_data = self._get_data(collectors, "containers")

        for runtime in ("docker", "podman"):
            for ctr in ctr_data.get(runtime, {}).get("detailed", []):
                status = ctr.get("state", "")
                name = ctr.get("names", ctr.get("id", ""))[:20]

                if "running" not in status.lower():
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Container '{name}' has no restart info",
                        description=f"Container '{name}' is running but restart policy cannot be verified from available data. Ensure it has a restart policy.",
                        rationale="Containers without restart policies will not recover from crashes. In production, this leads to service downtime. Always and unless-stopped are recommended for critical services.",
                        remediation=f"Update container '{name}': 'docker update --restart=unless-stopped {name}'. For new containers, use '--restart=unless-stopped'.",
                        evidence=RegistryEvidence(key=f"container.{runtime}.{name}.restart_policy", value="unknown/not set", expected="unless-stopped or always", source=f"{runtime} inspect"),
                        detected_value="Restart policy not verified",
                        expected_value="Restart policy configured",
                        affected_component=f"container:{name}",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.4,
                        mitre_attack_ids=["T1499"],
                        tags=["containers", "docker", "availability", "resilience"],
                    )
                )
        return findings
