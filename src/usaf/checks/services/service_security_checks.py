from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

UNIT_SEARCH_DIRS: list[Path] = [
    Path("/etc/systemd/system"),
    Path("/lib/systemd/system"),
    Path("/run/systemd/system"),
]

SVC_SUFFIXES: tuple[str, ...] = (
    ".service", ".socket", ".timer", ".target",
    ".path", ".mount", ".device", ".slice",
)

SUSPICIOUS_PACKAGES: set[str] = {
    "cryptominer", "minerd", "xmrig", "rig", "monero",
    "backdoor", "shell", "revshell", "beacon",
    "keylog", "capture", "stealer",
}


def _strip_svc_suffix(name: str) -> str:
    for suffix in SVC_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _read_unit_file(unit_name: str) -> tuple[str | None, str | None]:
    for sd in UNIT_SEARCH_DIRS:
        unit_path = sd / unit_name
        if unit_path.exists():
            try:
                return str(unit_path), unit_path.read_text()
            except OSError:
                continue
    return None, None


def _parse_execstart(content: str) -> str | None:
    in_service = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            in_service = section in ("service", "socket", "timer")
            continue
        if not in_service:
            continue
        key = stripped.split("=", 1)[0].strip()
        if key != "ExecStart":
            continue
        value = stripped.split("=", 1)[1].strip() if "=" in stripped else ""
        if not value:
            continue
        if value.startswith("@"):
            parts = value.split(None, 1)
            if len(parts) > 1:
                value = parts[1]
            else:
                continue
        for prefix in ("-", "!", "+", "@"):
            if value.startswith(prefix):
                value = value[1:].strip()
        binary = value.split(None, 1)[0] if value else None
        if binary:
            return binary
    return None


def _check_hardening_directive(content: str, directive: str) -> bool:
    in_service = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            in_service = section == "service"
            continue
        if not in_service:
            continue
        if stripped.startswith("#"):
            continue
        key = stripped.split("=", 1)[0].strip()
        if key == directive:
            return True
    return False


@register_check
class ServicesMissingHardeningCheck(AuditCheck):
    id = "SVC-103"
    name = "Services Missing Security Hardening"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Detects active services missing key security hardening directives"
    depends = ["systemd"]
    tags = ["services", "hardening", "systemd"]

    _hardening_directives: list[str] = [
        "NoNewPrivileges",
        "PrivateTmp",
        "PrivateDevices",
        "ProtectSystem",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sys_data = self._get_data(collectors, "systemd")
        findings: list = []
        seen: set[str] = set()

        for svc in sys_data.get("services", []):
            unit_name: str = svc.get("name", "")
            active: str = svc.get("active", "")
            if active != "active":
                continue
            short = _strip_svc_suffix(unit_name)
            if short in seen:
                continue
            seen.add(short)

            path, content = _read_unit_file(unit_name)
            if not content:
                continue

            missing = [
                d for d in self._hardening_directives
                if not _check_hardening_directive(content, d)
            ]
            if not missing:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Service '{short}' missing hardening: {', '.join(missing)}",
                    description=(
                        f"Service '{unit_name}' is missing systemd hardening directives: "
                        f"{', '.join(missing)}"
                    ),
                    rationale=(
                        "Systemd security directives (NoNewPrivileges, PrivateTmp, "
                        "ProtectSystem) reduce the impact of a compromised service. "
                        "Without them, a service has full access to the filesystem, "
                        "can create new privileges, and share temporary files."
                    ),
                    remediation=(
                        f"Add hardening directives to '{unit_name}': "
                        f"'systemctl edit {unit_name}' and add:\n"
                        "[Service]\nNoNewPrivileges=yes\nPrivateTmp=yes\n"
                        "ProtectSystem=strict"
                    ),
                    evidence=FileEvidence(
                        path=path or f"/etc/systemd/system/{unit_name}",
                        content=f"Missing: {', '.join(missing)}",
                    ),
                    detected_value=f"Missing hardening: {', '.join(missing)}",
                    expected_value="All hardening directives present",
                    affected_component=unit_name,
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1543.002"],
                    tags=["services", "hardening"],
                )
            )

        return findings


@register_check
class ServiceMissingBinaryCheck(AuditCheck):
    id = "SVC-203"
    name = "Services With Non-Existent ExecStart Binary"
    category = CheckCategory.SERVICES
    severity = Severity.HIGH
    description = "Detects active services whose ExecStart binary does not exist on disk"
    depends = ["systemd"]
    tags = ["services", "integrity", "systemd"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sys_data = self._get_data(collectors, "systemd")
        findings: list = []
        seen: set[str] = set()

        for svc in sys_data.get("services", []):
            unit_name: str = svc.get("name", "")
            short = _strip_svc_suffix(unit_name)
            if short in seen:
                continue
            seen.add(short)

            _path, content = _read_unit_file(unit_name)
            if not content:
                continue
            binary = _parse_execstart(content)
            if not binary:
                continue
            if binary.startswith("/") and not os.path.exists(binary):
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Service '{short}' refers to missing binary: {binary}",
                        description=(
                            f"Service '{unit_name}' has ExecStart set to '{binary}' "
                            f"which does not exist on disk"
                        ),
                        rationale=(
                            "A service whose ExecStart binary is missing will fail to start. "
                            "This may indicate an incomplete software installation, a "
                            "service that was uninstalled but not disabled, or tampering."
                        ),
                        remediation=(
                            f"Reinstall the package providing '{binary}', or disable "
                            f"the service: 'systemctl disable {unit_name}'"
                        ),
                        evidence=RegistryEvidence(
                            key=f"ExecStart for {unit_name}",
                            value=binary,
                            expected="existing binary path",
                            source=unit_name,
                        ),
                        detected_value=binary,
                        expected_value="path to existing binary",
                        affected_component=binary,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1543.002"],
                        tags=["services", "integrity"],
                    )
                )
            elif not binary.startswith("/"):
                findings.append(
                    self.finding(
                        finding_id="002",
                        title=f"Service '{short}' uses relative ExecStart path: {binary}",
                        description=(
                            f"Service '{unit_name}' uses a non-absolute ExecStart path "
                            f"'{binary}', which relies on PATH resolution"
                        ),
                        rationale=(
                            "Non-absolute ExecStart paths depend on PATH environment "
                            "variable resolution. An attacker who modifies PATH can "
                            "substitute a malicious binary."
                        ),
                        remediation=(
                            f"Use an absolute path in ExecStart for '{unit_name}'. "
                            f"Find the binary with 'which {binary}' and update the unit file."
                        ),
                        evidence=RegistryEvidence(
                            key=f"ExecStart for {unit_name}",
                            value=binary,
                            expected="absolute path (starting with /)",
                            source=unit_name,
                        ),
                        detected_value=binary,
                        expected_value="absolute path",
                        affected_component=unit_name,
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1574.001"],
                        tags=["services", "path-hijacking"],
                    )
                )

        return findings


@register_check
class OrphanedTimerUnitsCheck(AuditCheck):
    id = "SVC-303"
    name = "Timer Units With Missing Target Services"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Detects systemd timer units whose corresponding service unit is missing"
    depends = ["systemd"]
    tags = ["services", "timers", "systemd"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sys_data = self._get_data(collectors, "systemd")
        findings: list = []
        active_services: set[str] = set()

        for svc in sys_data.get("services", []):
            name: str = svc.get("name", "")
            active_services.add(_strip_svc_suffix(name))

        for timer in sys_data.get("timers", []):
            timer_name: str = timer.get("name", "")
            timer_short = _strip_svc_suffix(timer_name)
            expected_svc = f"{timer_short}.service"

            if expected_svc not in list(sys_data.get("services", [])):
                _path, content = _read_unit_file(timer_name)
                if content:
                    target = self._find_timer_target(content)
                    if target is None:
                        target = f"{timer_short}.service"
                    if target and _strip_svc_suffix(target) not in active_services:
                        findings.append(
                            self.finding(
                                finding_id="001",
                                title=f"Timer '{timer_short}' has no target service",
                                description=(
                                    f"Timer unit '{timer_name}' references service "
                                    f"'{target}' which is not loaded"
                                ),
                                rationale=(
                                    "A timer unit whose target service is missing "
                                    "indicates an incomplete installation or removal. "
                                    "The timer will fail when triggered."
                                ),
                                remediation=(
                                    f"Install the missing service, or disable the timer: "
                                    f"'systemctl disable {timer_name}'"
                                ),
                                evidence=RegistryEvidence(
                                    key="timer",
                                    value=timer_name,
                                    expected=f"service {target} active",
                                    source=timer_name,
                                ),
                                detected_value=f"Timer {timer_name} -> missing {target}",
                                expected_value=f"Service {target} active",
                                affected_component=timer_name,
                                confidence=Confidence.MEDIUM,
                                false_positive_probability=0.1,
                                tags=["services", "timers"],
                            )
                        )

        return findings

    @staticmethod
    def _find_timer_target(content: str) -> str | None:
        in_timer = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].strip().lower()
                in_timer = section == "timer"
                continue
            if not in_timer:
                continue
            if stripped.startswith("Unit="):
                return stripped.split("=", 1)[1].strip()
        return None


@register_check
class ServiceWorldWritableBinaryCheck(AuditCheck):
    id = "SVC-501"
    name = "Services With World-Writable ExecStart Binary"
    category = CheckCategory.SERVICES
    severity = Severity.CRITICAL
    description = "Detects services whose ExecStart binary is world-writable"
    depends = ["systemd"]
    tags = ["services", "privilege-escalation", "systemd"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sys_data = self._get_data(collectors, "systemd")
        findings: list = []
        seen: set[str] = set()

        for svc in sys_data.get("services", []):
            unit_name: str = svc.get("name", "")
            short = _strip_svc_suffix(unit_name)
            if short in seen:
                continue
            seen.add(short)

            _path, content = _read_unit_file(unit_name)
            if not content:
                continue
            binary = _parse_execstart(content)
            if not binary or not binary.startswith("/"):
                continue
            try:
                st = os.stat(binary)
                if st.st_mode & stat.S_IWOTH:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Service '{short}' uses world-writable binary: {binary}",
                            description=(
                                f"Service '{unit_name}' ExecStart binary '{binary}' "
                                f"is world-writable (mode {oct(st.st_mode & 0o7777)})"
                            ),
                            rationale=(
                                "A world-writable service binary allows any user to "
                                "replace the executable. When systemd starts the service "
                                "(often as root), the malicious code runs with the "
                                "service's privileges. This is a direct privilege "
                                "escalation path."
                            ),
                            remediation=(
                                f"Fix permissions: 'chmod o-w {binary}'. "
                                f"Verify integrity of the binary."
                            ),
                            evidence=FileEvidence(
                                path=binary,
                                permission=oct(st.st_mode & 0o7777),
                                size=st.st_size,
                            ),
                            detected_value=f"World-writable: {binary}",
                            expected_value="Not world-writable",
                            affected_component=binary,
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.0,
                            mitre_attack_ids=["T1543.002", "T1574.002"],
                            tags=["services", "privilege-escalation"],
                        )
                    )
            except OSError:
                continue

        return findings


@register_check
class SuspiciousServiceNamesCheck(AuditCheck):
    id = "SVC-502"
    name = "Suspicious Service Descriptions"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Detects services with descriptions suggesting malicious activity"
    depends = ["systemd"]
    tags = ["services", "persistence", "systemd"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sys_data = self._get_data(collectors, "systemd")
        findings: list = []

        for svc in sys_data.get("services", []):
            name: str = svc.get("name", "")
            desc: str = svc.get("description", "").lower()
            load: str = svc.get("load", "")

            if load != "loaded":
                continue

            for keyword in SUSPICIOUS_PACKAGES:
                if keyword in desc:
                    short = _strip_svc_suffix(name)
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Suspicious service description: {short}",
                            description=(
                                f"Service '{name}' has description containing "
                                f"suspicious keyword '{keyword}': '{desc}'"
                            ),
                            rationale=(
                                "Service descriptions containing keywords associated "
                                "with cryptominers, backdoors, or credential stealers "
                                "may indicate a compromised system. Legitimate services "
                                "rarely use these terms in their descriptions."
                            ),
                            remediation=(
                                f"Investigate '{name}': 'systemctl cat {name}' "
                                f"and 'systemctl status {name}'. If malicious: "
                                f"'systemctl disable --now {name}' and remove the unit file."
                            ),
                            evidence=RegistryEvidence(
                                key=f"{name}/description",
                                value=desc,
                                expected=f"No keyword '{keyword}' in description",
                                source="systemd",
                            ),
                            detected_value=f"Description contains '{keyword}'",
                            expected_value="No suspicious keywords",
                            affected_component=name,
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.2,
                            mitre_attack_ids=["T1543.002", "T1505"],
                            tags=["services", "persistence"],
                        )
                    )

        return findings


@register_check
class StoppedEnabledServicesCheck(AuditCheck):
    id = "SVC-503"
    name = "Enabled But Stopped Services"
    category = CheckCategory.SERVICES
    severity = Severity.LOW
    description = "Detects enabled services that are not currently running"
    depends = ["systemd"]
    tags = ["services", "monitoring", "systemd"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sys_data = self._get_data(collectors, "systemd")
        findings: list = []

        for svc in sys_data.get("services", []):
            name: str = svc.get("name", "")
            load: str = svc.get("load", "")
            active: str = svc.get("active", "")
            sub: str = svc.get("sub", "")

            if load != "loaded":
                continue
            if active == "active":
                continue
            if sub in ("dead", "exited"):
                short = _strip_svc_suffix(name)
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Enabled service not running: {short}",
                        description=(
                            f"Service '{name}' is loaded but {active}/{sub}. "
                            f"It is enabled but not currently running."
                        ),
                        rationale=(
                            "Services that are enabled but not running may indicate "
                            "a failed startup, a service that crashed without being "
                            "restarted, or a misconfiguration. Enabled services "
                            "should typically be running on boot."
                        ),
                        remediation=(
                            f"Check status: 'systemctl status {name}'. "
                            f"Start: 'systemctl start {name}'. "
                            f"If not needed: 'systemctl disable {name}'."
                        ),
                        evidence=RegistryEvidence(
                            key=f"{name}/active",
                            value=f"{active}/{sub}",
                            expected="active/running",
                            source="systemd",
                        ),
                        detected_value=f"{name}: {active}/{sub}",
                        expected_value="active/running",
                        affected_component=name,
                        confidence=Confidence.LOW,
                        false_positive_probability=0.3,
                        tags=["services", "monitoring"],
                    )
                )

        return findings


@register_check
class MaskedActiveServicesCheck(AuditCheck):
    id = "SVC-504"
    name = "Masked Services Still Present"
    category = CheckCategory.SERVICES
    severity = Severity.LOW
    description = "Detects services that are masked but still have unit files present"
    depends = ["systemd"]
    tags = ["services", "persistence", "systemd"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        sys_data = self._get_data(collectors, "systemd")
        findings: list = []

        for svc in sys_data.get("services", []):
            name: str = svc.get("name", "")
            load: str = svc.get("load", "")
            active: str = svc.get("active", "")

            if load != "masked":
                continue
            if active not in ("active", "inactive"):
                continue

            unit_path = _find_unit_file_path(name)
            if unit_path:
                short = _strip_svc_suffix(name)
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Masked service still has unit file: {short}",
                        description=(
                            f"Service '{name}' is masked (load={load}) but unit "
                            f"file still exists at {unit_path}"
                        ),
                        rationale=(
                            "A masked service should have its unit file symlinked "
                            "to /dev/null. If the unit file still exists, the "
                            "masking may not be effective, or the mask was "
                            "improperly applied."
                        ),
                        remediation=(
                            f"Verify mask: 'systemctl status {name}'. "
                            f"Re-mask: 'systemctl mask {name}'."
                        ),
                        evidence=FileEvidence(
                            path=unit_path,
                            content=f"Service {name} is masked but unit file exists",
                        ),
                        detected_value=f"Masked: {name}, unit: {unit_path}",
                        expected_value="Masked services point to /dev/null",
                        affected_component=name,
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1562.001"],
                        tags=["services", "persistence"],
                    )
                )

        return findings


def _find_unit_file_path(unit_name: str) -> str | None:
    for sd in UNIT_SEARCH_DIRS:
        unit_path = sd / unit_name
        if unit_path.exists():
            return str(unit_path)
    return None
