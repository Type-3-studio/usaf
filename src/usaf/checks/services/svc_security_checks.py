from __future__ import annotations

from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


def _strip_svc_suffix(name: str) -> str:
    for suffix in (".service", ".timer", ".socket", ".target", ".path", ".mount", ".scope", ".slice"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _get_unit_path(unit_name: str) -> str | None:
    for base in ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system"):
        p = Path(base) / unit_name
        if p.exists():
            return str(p)
        if not unit_name.endswith(".d"):
            p = Path(base) / (unit_name + ".d" if unit_name.endswith("/") else unit_name)
    return None


@register_check
class ServiceLoadFailuresCheck(AuditCheck):
    id = "SVC-601"
    name = "Service Load Failures"
    category = CheckCategory.SERVICES
    severity = Severity.HIGH
    description = "Detects systemd units that failed to load or have errors"
    depends = ["systemd"]
    tags = ["services", "systemd", "failures", "monitoring"]

    FAILED_LOAD_STATES: set[str] = {"error", "not-found", "bad-setting", "masked"}

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")

        for unit_type, _label in [("services", "service"), ("timers", "timer"), ("sockets", "socket")]:
            for unit in sys_data.get(unit_type, []):
                name = unit.get("name", "")
                load = unit.get("load", "")
                active = unit.get("active", "")
                sub = unit.get("sub", "")

                if load not in self.FAILED_LOAD_STATES:
                    continue

                short = _strip_svc_suffix(name)

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Unit load failure: {short}",
                        description=(
                            f"Unit '{name}' is in load state '{load}' (active={active}/{sub}). "
                            f"The unit configuration has errors or the file is missing."
                        ),
                        rationale=(
                            "Systemd units in error or not-found load state indicate "
                            "configuration errors, missing dependencies, or incomplete "
                            "installations. These units will not function and may cause "
                            "dependent services to fail."
                        ),
                        remediation=(
                            f"Check unit status: 'systemctl status {name}'. "
                            f"Verify configuration: 'systemctl cat {name}'. "
                            f"Review logs: 'journalctl -u {name}'."
                        ),
                        evidence=RegistryEvidence(
                            key=f"{name}/load",
                            value=load,
                            expected="loaded",
                            source="systemd",
                        ),
                        detected_value=f"{name}: load={load}",
                        expected_value="loaded",
                        affected_component=name,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1543"],
                        tags=["services", "systemd", "failures", "monitoring"],
                    )
                )
        return findings


@register_check
class SocketUnitsNotRunningCheck(AuditCheck):
    id = "SVC-602"
    name = "Socket Units Not Running"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Detects socket units that are not in active/listening state"
    depends = ["systemd"]
    tags = ["services", "sockets", "systemd", "monitoring"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")

        for sock in sys_data.get("sockets", []):
            name = sock.get("name", "")
            load = sock.get("load", "")
            active = sock.get("active", "")
            sub = sock.get("sub", "")

            if load != "loaded":
                continue
            if active == "active":
                continue

            short = _strip_svc_suffix(name)

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Socket not running: {short}",
                    description=(
                        f"Socket unit '{name}' is loaded but in state "
                        f"{active}/{sub}. Socket-activated services will not "
                        f"start on connection."
                    ),
                    rationale=(
                        "Socket units that are not listening prevent their associated "
                        "services from being socket-activated. This can cause service "
                        "failures and disrupt system functionality. Non-listening sockets "
                        "may indicate configuration errors or crashes."
                    ),
                    remediation=(
                        f"Check socket: 'systemctl status {name}'. "
                        f"Start: 'systemctl start {name}'. "
                        f"Enable: 'systemctl enable {name}'."
                    ),
                    evidence=RegistryEvidence(
                        key=f"{name}/active",
                        value=f"{active}/{sub}",
                        expected="active/listening",
                        source="systemd",
                    ),
                    detected_value=f"{name}: {active}/{sub}",
                    expected_value="active/listening",
                    affected_component=name,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1543"],
                    tags=["services", "sockets", "systemd", "monitoring"],
                )
            )
        return findings


@register_check
class TimerServiceMismatchCheck(AuditCheck):
    id = "SVC-603"
    name = "Timer-Service Mismatch"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Detects timer units whose associated service may be misconfigured or mismatched"
    depends = ["systemd"]
    tags = ["services", "timers", "systemd", "monitoring"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")

        service_names: set[str] = set()
        for svc in sys_data.get("services", []):
            name = svc.get("name", "")
            load = svc.get("load", "")
            if load == "loaded":
                service_names.add(name)

        for timer in sys_data.get("timers", []):
            name = timer.get("name", "")
            load = timer.get("load", "")

            if load != "loaded":
                continue

            timer_short = _strip_svc_suffix(name)
            expected_service = f"{timer_short}.service"

            if expected_service in service_names:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Timer without matching service: {timer_short}",
                    description=(
                        f"Timer '{name}' is loaded but the expected target service "
                        f"'{expected_service}' is not loaded. The timer will fail "
                        f"when triggered."
                    ),
                    rationale=(
                        "Timer units activate a corresponding service when they fire. "
                        "If the target service is not loaded or doesn't exist, the timer "
                        "activation fails silently. This may indicate incomplete "
                        "installation, misconfiguration, or a removed service."
                    ),
                    remediation=(
                        f"Verify timer: 'systemctl cat {name}'. "
                        f"Check for the expected service unit: "
                        f"'systemctl status {expected_service}'. "
                        f"Install missing service or fix timer reference."
                    ),
                    evidence=RegistryEvidence(
                        key=f"{name}/expected_service",
                        value="not loaded",
                        expected=expected_service,
                        source="systemd",
                    ),
                    detected_value=f"Timer {name} targets missing {expected_service}",
                    expected_value=f"{expected_service} should be loaded",
                    affected_component=name,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1543"],
                    tags=["services", "timers", "systemd", "monitoring"],
                )
            )
        return findings


@register_check
class UnitFileOwnershipCheck(AuditCheck):
    id = "SVC-604"
    name = "Systemd Unit File Ownership"
    category = CheckCategory.SERVICES
    severity = Severity.HIGH
    description = "Checks that systemd unit files are owned by root"
    depends = ["systemd"]
    tags = ["services", "systemd", "permissions", "hardening"]
    max_findings = 50

    UNIT_DIRS: list[str] = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        seen: set[str] = set()

        unit_names: set[str] = set()
        for unit_type in ("services", "timers", "sockets"):
            for unit in sys_data.get(unit_type, []):
                name = unit.get("name", "")
                if name:
                    unit_names.add(name)

        for unit_name in sorted(unit_names):
            for base_dir in self.UNIT_DIRS:
                unit_path = Path(base_dir) / unit_name
                if not unit_path.exists():
                    continue
                sp = str(unit_path)
                if sp in seen:
                    continue
                seen.add(sp)

                try:
                    st = unit_path.stat()
                except OSError:
                    continue

                if st.st_uid == 0:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Unit file not owned by root: {unit_name}",
                        description=(
                            f"Unit file '{sp}' is owned by uid {st.st_uid} instead "
                            f"of root (0). Systemd unit files must be owned by root."
                        ),
                        rationale=(
                            "Unit files not owned by root allow the owning user to modify "
                            "service definitions, including ExecStart, Environment, and "
                            "other directives. This enables trivial privilege escalation — "
                            "the owner can change a service to execute arbitrary code as root."
                        ),
                        remediation=(
                            f"Fix ownership: 'chown root:root {sp}'."
                        ),
                        evidence=FileEvidence(
                            path=sp,
                            permission=oct(st.st_mode)[2:] if hasattr(st, 'st_mode') else "",
                            owner=str(st.st_uid),
                            group=str(st.st_gid),
                            size=st.st_size,
                            content=f"Owned by uid {st.st_uid}, expected root",
                        ),
                        detected_value=f"Owner uid {st.st_uid}",
                        expected_value="Owner uid 0 (root)",
                        affected_component=sp,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1222", "T1543"],
                        tags=["services", "systemd", "permissions", "hardening"],
                    )
                )
        return findings


@register_check
class UnitFileWorldWritableCheck(AuditCheck):
    id = "SVC-605"
    name = "World-Writable Systemd Unit Files"
    category = CheckCategory.SERVICES
    severity = Severity.CRITICAL
    description = "Detects systemd unit files with world-writable permissions"
    depends = ["systemd"]
    tags = ["services", "systemd", "permissions", "privilege-escalation"]
    max_findings = 50

    UNIT_DIRS: list[str] = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")
        seen: set[str] = set()

        unit_names: set[str] = set()
        for unit_type in ("services", "timers", "sockets"):
            for unit in sys_data.get(unit_type, []):
                name = unit.get("name", "")
                if name:
                    unit_names.add(name)

        for unit_name in sorted(unit_names):
            for base_dir in self.UNIT_DIRS:
                unit_path = Path(base_dir) / unit_name
                if not unit_path.exists():
                    continue
                sp = str(unit_path)
                if sp in seen:
                    continue
                seen.add(sp)

                try:
                    st = unit_path.stat()
                except OSError:
                    continue

                if not (st.st_mode & 0o002):
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"World-writable unit file: {unit_name}",
                        description=(
                            f"Unit file '{sp}' is world-writable (mode "
                            f"{oct(st.st_mode & 0o7777)[2:]}). Any user can modify "
                            f"this service definition."
                        ),
                        rationale=(
                            "World-writable systemd unit files allow any user on the "
                            "system to modify service definitions. An attacker can "
                            "change ExecStart to run arbitrary commands as root on "
                            "the next service start, making this a critical privilege "
                            "escalation and persistence vector."
                        ),
                        remediation=(
                            f"Restrict permissions: 'chmod 644 {sp}'. "
                            f"Review unit contents: 'systemctl cat {unit_name}'."
                        ),
                        evidence=FileEvidence(
                            path=sp,
                            permission=oct(st.st_mode & 0o7777)[2:],
                            owner=str(st.st_uid),
                            size=st.st_size,
                            content="World-writable unit file",
                        ),
                        detected_value=f"World-writable ({oct(st.st_mode & 0o7777)[2:]})",
                        expected_value="Not world-writable (e.g., 644)",
                        affected_component=sp,
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.02,
                        mitre_attack_ids=["T1222", "T1543", "T1053"],
                        tags=["services", "systemd", "permissions", "privilege-escalation"],
                    )
                )
        return findings


@register_check
class StaticServicesNotRunningCheck(AuditCheck):
    id = "SVC-606"
    name = "Static Services Not Running"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Detects static systemd services that are not running (static=always on)"
    depends = ["systemd"]
    tags = ["services", "systemd", "monitoring", "availability"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")

        for svc in sys_data.get("services", []):
            name = svc.get("name", "")
            load = svc.get("load", "")
            active = svc.get("active", "")
            sub = svc.get("sub", "")

            if load != "loaded":
                continue
            if active != "inactive":
                continue
            if sub not in ("dead",):
                continue

            short = _strip_svc_suffix(name)

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Static service not running: {short}",
                    description=(
                        f"Static service '{name}' is {active}/{sub}. Static services "
                        f"are enabled implicitly and should always run."
                    ),
                    rationale=(
                        "Static services are enabled by default (no enable/disable). "
                        "They are expected to be running on every boot. A static service "
                        "in dead/inactive state may indicate a failed startup, missing "
                        "dependencies, or a service that crashed without recovery."
                    ),
                    remediation=(
                        f"Check status: 'systemctl status {name}'. "
                        f"Start manually: 'systemctl start {name}'. "
                        f"Review logs: 'journalctl -u {name} --since yesterday'."
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
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1543"],
                    tags=["services", "systemd", "monitoring", "availability"],
                )
            )
        return findings


@register_check
class DuplicateUnitFilesCheck(AuditCheck):
    id = "SVC-607"
    name = "Duplicate Unit Files"
    category = CheckCategory.SERVICES
    severity = Severity.MEDIUM
    description = "Detects systemd unit files that exist in multiple locations"
    depends = ["systemd"]
    tags = ["services", "systemd", "integrity", "monitoring"]

    UNIT_DIRS: list[str] = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")

        unit_names: set[str] = set()
        for unit_type in ("services", "timers", "sockets"):
            for unit in sys_data.get(unit_type, []):
                name = unit.get("name", "")
                if name:
                    unit_names.add(name)

        for unit_name in sorted(unit_names):
            paths: list[str] = []
            for base_dir in self.UNIT_DIRS:
                p = Path(base_dir) / unit_name
                if p.exists():
                    paths.append(str(p))

            if len(paths) < 2:
                continue

            has_etc = any(p.startswith("/etc/") for p in paths)
            has_run = any(p.startswith("/run/") for p in paths)

            priority = "/etc takes priority over /run" if has_etc and has_run else ""

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Duplicate unit file: {unit_name}",
                    description=(
                        f"Unit '{unit_name}' exists in multiple locations: "
                        f"{', '.join(paths)}. {priority}"
                    ),
                    rationale=(
                        "Duplicate unit files in /etc, /run, and /usr/lib can cause "
                        "confusion about which configuration is active. An attacker "
                        "may place a modified unit in /etc to shadow the original "
                        "in /usr/lib, creating a persistent backdoor."
                    ),
                    remediation=(
                        f"Review all copies: {', '.join(paths)}. "
                        f"Remove obsolete duplicates. "
                        f"Verify current config: 'systemctl cat {unit_name}'."
                    ),
                    evidence=RegistryEvidence(
                        key=f"{unit_name}/paths",
                        value=", ".join(paths),
                        expected="Single copy preferred",
                        source="systemd",
                    ),
                    detected_value=f"Duplicate in {len(paths)} locations",
                    expected_value="Single unit file location",
                    affected_component=unit_name,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.15,
                    mitre_attack_ids=["T1543", "T1222"],
                    tags=["services", "systemd", "integrity", "monitoring"],
                )
            )
        return findings


@register_check
class ActiveTimersWithoutCalendarCheck(AuditCheck):
    id = "SVC-608"
    name = "Active Timers Without Calendar Schedule"
    category = CheckCategory.SERVICES
    severity = Severity.LOW
    description = "Detects active timer units that may have unusual triggering mechanisms"
    depends = ["systemd"]
    tags = ["services", "timers", "systemd", "monitoring"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        sys_data = self._get_data(collectors, "systemd")

        for timer in sys_data.get("timers", []):
            name = timer.get("name", "")
            load = timer.get("load", "")
            active = timer.get("active", "")

            if load != "loaded":
                continue
            if active == "inactive":
                continue

            short = _strip_svc_suffix(name)
            unit_path = _get_unit_path(name)
            if unit_path is None:
                continue

            has_calendar = False
            has_monotonic = False
            try:
                text = Path(unit_path).read_text()
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if "=" not in stripped:
                        continue
                    key, _val = stripped.split("=", 1)
                    k = key.strip().lower()
                    if k == "oncalendar":
                        has_calendar = True
                    elif k in ("onbootsec", "onunitactive", "onunitinactive"):
                        has_monotonic = True
            except OSError:
                continue

            if has_calendar:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Timer without calendar: {short}",
                    description=(
                        f"Timer '{name}' is active but has no OnCalendar= directive "
                        + (" (uses monotonic triggers: OnBootSec/OnUnitActive)." if has_monotonic else ".")
                    ),
                    rationale=(
                        "Timer units without OnCalendar= use monotonic triggers "
                        "(OnBootSec, OnUnitActiveSec). These timers reset on every "
                        "boot or service activation, making their execution schedule "
                        "unpredictable. For security monitoring and compliance, "
                        "calendar-based schedules are preferred."
                    ),
                    remediation=(
                        f"Review timer: 'systemctl cat {name}'. "
                        f"Consider adding OnCalendar= for predictable scheduling."
                    ),
                    evidence=RegistryEvidence(
                        key=f"{name}/trigger",
                        value="monotonic only" if has_monotonic else "no calendar or monotonic found",
                        expected="OnCalendar= set",
                        source=unit_path,
                    ),
                    detected_value=f"Timer {name} uses monotonic triggers",
                    expected_value="OnCalendar= with explicit schedule",
                    affected_component=name,
                    confidence=Confidence.LOW,
                    false_positive_probability=0.6,
                    mitre_attack_ids=["T1053"],
                    tags=["services", "timers", "systemd", "monitoring"],
                )
            )
        return findings
