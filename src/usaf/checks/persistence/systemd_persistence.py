import os
import re

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

KNOWN_SYSTEMD_TIMERS = {
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "dpkg-db-backup.timer",
    "e2scrub_all.timer",
    "fstrim.timer",
    "logrotate.timer",
    "man-db.timer",
    "motd-news.timer",
    "networkd-dispatcher.timer",
    "phc2sys.timer",
    "pollinate.timer",
    "plymouth-read-write.timer",
    "snapd.snap-repair.timer",
    "sysstat-collect.timer",
    "sysstat-summary.timer",
    "systemd-tmpfiles-clean.timer",
    "ua-timer.timer",
    "update-notifier-download.timer",
    "update-notifier-motd.timer",
}

SUSPICIOUS_TIMER_NAME_PATTERNS = [
    r"backdoor",
    r"reverse",
    r"beacon",
    r"implant",
    r"miner",
    r"crypto",
    r"meterp",
    r"proxy",
]

KNOWN_DROPIN_BINARIES = {
    "ssh",
    "sshd",
    "cron",
    "systemd",
    "dbus",
    "NetworkManager",
    "systemd-logind",
    "systemd-resolved",
    "systemd-journald",
    "systemd-networkd",
    "systemd-timesyncd",
    "systemd-udevd",
    "polkitd",
    "accounts-daemon",
    "avahi-daemon",
    "cups",
    "cups-browsed",
    "whoopsie",
    "snapd",
    "udisksd",
    "upowerd",
    "colord",
    "geoclue",
}

KNOWN_PATH_UNITS = {
    "systemd-networkd-wait-online.service",
    "systemd-resolved.service",
}


@register_check
class SuspiciousSystemdTimersCheck(AuditCheck):
    id = "PER-202"
    name = "Suspicious Systemd Timer Names"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects systemd timers with suspicious or unknown names"
    depends = ["systemd"]
    tags = ["persistence", "systemd", "timers", "scheduled-tasks"]

    def _run_check(self, collectors: dict) -> list:
        systemd_data = self._get_data(collectors, "systemd")
        findings: list = []

        timers = systemd_data.get("timers", [])
        if not timers:
            return findings

        suspicious_timers: list[dict] = []
        unknown_timers: list[dict] = []

        for timer in timers:
            name: str = timer.get("name", "")
            if not name:
                continue
            base = name.replace(".timer", "")
            is_suspicious = any(re.search(p, base, re.IGNORECASE) for p in SUSPICIOUS_TIMER_NAME_PATTERNS)
            if is_suspicious:
                suspicious_timers.append(timer)
            elif name not in KNOWN_SYSTEMD_TIMERS and timer.get("active") == "active":
                unknown_timers.append(timer)

        for timer in suspicious_timers:
            name = timer.get("name", "")
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Suspicious timer name: {name}",
                    description=(
                        f"Systemd timer '{name}' has a name matching "
                        f"suspicious patterns and may be malicious."
                    ),
                    rationale=(
                        "Attackers often name persistence timers with innocuous-sounding "
                        "names, but sometimes use tool-generated names matching common "
                        "backdoor/beacon terminology. Systemd timers are a robust "
                        "persistence mechanism that survive reboots."
                    ),
                    remediation=(
                        f"Investigate: 'systemctl cat {name}'\n"
                        f"Check if legitimate: 'dpkg -S /etc/systemd/system/{name}'\n"
                        f"Disable if unauthorized: 'systemctl disable --now {name}'"
                    ),
                    evidence=FileEvidence(
                        path=f"/etc/systemd/system/{name}",
                        content=f"Timer: {name}, active: {timer.get('active')}",
                        owner="",
                        group="",
                    ),
                    detected_value=name,
                    expected_value="Timer should be a known system timer",
                    affected_component=name,
                    confidence=Confidence.LOW,
                    false_positive_probability=0.6,
                    mitre_attack_ids=["T1053.006"],
                    tags=["persistence", "systemd", "timer"],
                )
            )

        for timer in unknown_timers[:5]:
            name = timer.get("name", "")
            findings.append(
                self.finding(
                    finding_id="002",
                    title=f"Unknown active timer: {name}",
                    description=(
                        f"Systemd timer '{name}' is active but not in the "
                        f"known-safe timer list."
                    ),
                    rationale=(
                        "Unknown systemd timers that are actively running should be "
                        "investigated. Attackers deploy timers as a stealthy persistence "
                        "mechanism that can execute arbitrary commands on a schedule."
                    ),
                    remediation=(
                        f"Investigate: 'systemctl cat {name}'\n"
                        f"Check timer status: 'systemctl status {name}'\n"
                        f"Review timer events: 'journalctl -u {name}'"
                    ),
                    evidence=FileEvidence(
                        path=f"/etc/systemd/system/{name}",
                        content=f"Unknown timer: {name}",
                        owner="",
                        group="",
                    ),
                    detected_value=name,
                    expected_value="All active timers should be known system timers",
                    affected_component=name,
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1053.006"],
                    tags=["persistence", "systemd", "timer"],
                )
            )

        return findings


@register_check
class SystemdServiceDropinsCheck(AuditCheck):
    id = "PER-203"
    name = "Systemd Service Drop-Ins"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects systemd service drop-in files that may alter service behavior"
    depends = ["systemd"]
    tags = ["persistence", "systemd", "dropins"]

    def _run_check(self, collectors: dict) -> list:
        systemd_data = self._get_data(collectors, "systemd")
        findings: list = []

        services = systemd_data.get("services", [])
        services_by_name = {}
        for svc in services:
            name: str = svc.get("name", "")
            if name:
                services_by_name[name] = svc

        dropin_dirs = [
            "/etc/systemd/system",
            "/run/systemd/system",
        ]

        suspicious_dropins: list[dict] = []
        for dropin_dir in dropin_dirs:
            if not os.path.isdir(dropin_dir):
                continue
            try:
                entries = os.listdir(dropin_dir)
            except (OSError, PermissionError):
                continue
            for entry in entries:
                if not entry.endswith(".d"):
                    continue
                dropin_path = os.path.join(dropin_dir, entry)
                if not os.path.isdir(dropin_path):
                    continue
                try:
                    conf_files = os.listdir(dropin_path)
                except (OSError, PermissionError):
                    continue
                for conf in conf_files:
                    if conf.endswith(".conf") and conf != "override.conf":
                        conf_path = os.path.join(dropin_path, conf)
                        try:
                            with open(conf_path) as f:
                                content = f.read()
                        except (OSError, PermissionError):
                            content = ""
                        service_name = entry.replace(".d", "")
                        service_name = service_name.replace(".service", "") + ".service"
                        svc = services_by_name.get(service_name, {})
                        is_active = svc.get("active") == "active"
                        if "ExecStart=" in content or "ExecStartPre=" in content or "ExecStartPost=" in content:
                            suspicious_dropins.append({
                                "service": service_name,
                                "dropin_dir": entry,
                                "conf_file": conf,
                                "path": conf_path,
                                "content": content,
                                "is_active": is_active,
                                "has_exec_start": True,
                            })

        for sd in suspicious_dropins:
            findings.append(
                self.finding(
                    finding_id="001" if sd["is_active"] else "002",
                    title=(
                        f"Drop-in modifies ExecStart for {sd['service']}"
                        if sd["is_active"]
                        else f"Inactive drop-in config: {sd['service']}"
                    ),
                    description=(
                        f"Drop-in file {sd['path']} adds/modifies ExecStart "
                        f"for service {sd['service']}. "
                        f"This can alter service behavior to execute arbitrary commands. "
                        f"Service is {'active' if sd['is_active'] else 'inactive'}."
                    ),
                    rationale=(
                        "Systemd drop-in files allow modifying service behavior without "
                        "changing the original unit file. Attackers use drop-ins to "
                        "inject malicious ExecStart commands that run alongside or "
                        "instead of legitimate services. This is a stealthy persistence "
                        "mechanism that blends into normal systemd operations."
                    ),
                    remediation=(
                        f"Inspect: 'systemctl cat {sd['service']}'\n"
                        f"Review drop-in: 'cat {sd['path']}'\n"
                        f"Remove if unauthorized: 'rm -r {os.path.dirname(sd['path'])}'"
                    ),
                    evidence=FileEvidence(
                        path=sd["path"],
                        content=sd["content"][:500],
                        owner="",
                        group="",
                    ),
                    detected_value=sd["path"],
                    expected_value="No custom drop-ins modifying ExecStart for known services",
                    affected_component=sd["service"],
                    confidence=Confidence.MEDIUM if sd["is_active"] else Confidence.LOW,
                    false_positive_probability=0.3 if sd["is_active"] else 0.6,
                    mitre_attack_ids=["T1543.002"],
                    tags=["persistence", "systemd", "dropin"],
                )
            )

        return findings


@register_check
class SystemdPathUnitsCheck(AuditCheck):
    id = "PER-204"
    name = "Systemd Path Units"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects systemd path units that trigger on file system changes"
    depends = ["systemd"]
    tags = ["persistence", "systemd", "path-units"]

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        path_units_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/system",
        ]

        path_units: list[dict] = []
        for pud in path_units_dirs:
            if not os.path.isdir(pud):
                continue
            try:
                entries = os.listdir(pud)
            except (OSError, PermissionError):
                continue
            for entry in entries:
                if entry.endswith(".path") and entry not in KNOWN_PATH_UNITS:
                    path_path = os.path.join(pud, entry)
                    if not os.path.isfile(path_path):
                        continue
                    try:
                        with open(path_path) as f:
                            content = f.read()
                    except (OSError, PermissionError):
                        content = ""
                    if "PathModified=" in content or "PathChanged=" in content or "PathExists=" in content:
                        path_units.append({
                            "name": entry,
                            "path": path_path,
                            "content": content,
                        })

        for pu in path_units:
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Systemd path unit: {pu['name']}",
                    description=(
                        f"Systemd path unit '{pu['name']}' monitors filesystem "
                        f"changes and triggers service activation. "
                        f"Path: {pu['path']}"
                    ),
                    rationale=(
                        "Systemd path units activate services when filesystem changes "
                        "occur (file modified, created, or exists). Attackers use path "
                        "units to trigger malicious actions when specific files change, "
                        "creating event-driven persistence that is harder to detect "
                        "than timer-based scheduling."
                    ),
                    remediation=(
                        f"Review path unit: 'systemctl cat {pu['name']}'\n"
                        f"Check associated service: 'systemctl status {pu['name'].replace('.path', '.service')}'\n"
                        f"Disable if unauthorized: 'systemctl disable --now {pu['name']}'"
                    ),
                    evidence=FileEvidence(
                        path=pu["path"],
                        content=pu["content"][:500],
                        owner="",
                        group="",
                    ),
                    detected_value=pu["name"],
                    expected_value="No unexpected systemd path units",
                    affected_component=pu["name"],
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1543.002"],
                    tags=["persistence", "systemd", "path-unit"],
                )
            )

        return findings
