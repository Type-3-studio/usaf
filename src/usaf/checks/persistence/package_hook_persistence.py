import os
import re

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

APT_HOOK_DIRS = [
    "/etc/apt/apt.conf.d",
    "/usr/lib/apt/apt.conf.d",
]

KNOWN_APT_HOOKS: dict[str, str] = {
    "00aptitude": "Aptitude hook",
    "00CDMountPoint": "CD mount point",
    "00trustcdrom": "Trust CD-ROM",
    "01autoremove": "Auto-remove kernels",
    "01-vendor-ubuntu": "Ubuntu vendor config",
    "10autoremove": "Auto-remove",
    "10periodic": "Periodic updates",
    "15update-stamp": "Update stamp",
    "20apt-esm-hook.conf": "ESM hook",
    "20archive": "Archive config",
    "20listchanges": "List changes",
    "20packagekit": "PackageKit hook",
    "20snapd.conf": "Snapd hook",
    "50appstream": "AppStream data",
    "50command-not-found": "Command not found",
    "50unattended-upgrades": "Unattended upgrades",
    "70debconf": "Debconf config",
    "99needrestart": "Need restart detection",
    "99update-notifier": "Update notifier",
}

DPKG_HOOK_DIRS = [
    "/etc/dpkg/dpkg.cfg.d",
    "/usr/lib/dpkg/hooks",
]

KNOWN_DPKG_HOOKS: dict[str, str] = {
    "pkg-info-hook": "Package info hook",
    "dpkg-reconfigure": "Reconfiguration hook",
    "install-info": "Info database update",
    "apt-configure": "APT configure hook",
}

SUSPICIOUS_HOOK_PATTERNS_RE = re.compile(
    r"(wget |curl |bash -c|python|perl -e|mkfifo|/dev/tcp/|base64 -d|chmod \+x|nc |ncat|socat|openssl)",
    re.IGNORECASE,
)


@register_check
class AptHookPersistenceCheck(AuditCheck):
    id = "PER-701"
    name = "APT Hook Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects APT hooks that may execute arbitrary commands during package operations"
    depends = ["apt"]
    tags = ["persistence", "apt", "hooks", "package"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        for hook_dir in APT_HOOK_DIRS:
            if not os.path.isdir(hook_dir):
                continue
            try:
                entries = sorted(os.listdir(hook_dir))
            except (OSError, PermissionError):
                continue

            for entry in entries:
                if entry in KNOWN_APT_HOOKS:
                    continue
                if not (entry.endswith(".conf") or "." not in entry):
                    continue

                fp = os.path.join(hook_dir, entry)
                if not os.path.isfile(fp):
                    continue
                try:
                    with open(fp) as f:
                        content = f.read()
                except (OSError, PermissionError):
                    content = ""

                has_dpkg_pre_invoke = "DPkg::Pre-Invoke" in content
                has_dpkg_post_invoke = "DPkg::Post-Invoke" in content
                has_apt_update = "APT::Update::Pre-Invoke" in content or "APT::Update::Post-Invoke" in content
                suspicious_matches = SUSPICIOUS_HOOK_PATTERNS_RE.findall(content)

                if has_dpkg_pre_invoke or has_dpkg_post_invoke or has_apt_update or suspicious_matches:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Unknown APT hook: {entry}",
                            description=(
                                f"Unknown APT hook configuration '{entry}' in {hook_dir}. "
                                f"Contains: {'DPkg pre/post invoke' if has_dpkg_pre_invoke or has_dpkg_post_invoke else ''} "
                                f"{'APT update hooks' if has_apt_update else ''} "
                                f"{f'Suspicious patterns: {suspicious_matches}' if suspicious_matches else ''}"
                            ),
                            rationale=(
                                "APT hooks execute during package operations (install, "
                                "update, remove). Attackers use APT hooks for stealthy "
                                "persistence — the hook runs whenever the admin uses apt, "
                                "including automated updates. DPkg::Pre-Invoke and "
                                "Post-Invoke execute arbitrary commands as root during "
                                "package installations."
                            ),
                            remediation=(
                                f"Investigate: 'cat {fp}'\n"
                                f"Remove if unauthorized: 'rm {fp}'\n"
                                f"Check for malicious apt hook patterns in other configs"
                            ),
                            evidence=FileEvidence(
                                path=fp,
                                content=content[:500],
                                owner="",
                                group="",
                            ),
                            detected_value=entry,
                            expected_value="Only known APT hooks should exist",
                            affected_component=entry,
                            confidence=Confidence.HIGH if suspicious_matches else Confidence.MEDIUM,
                            false_positive_probability=0.2 if suspicious_matches else 0.4,
                            mitre_attack_ids=["T1546.015"],
                            tags=["persistence", "apt", "hook", "package"],
                        )
                    )

        return findings


@register_check
class DpkgHookPersistenceCheck(AuditCheck):
    id = "PER-702"
    name = "Dpkg Hook Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects dpkg hooks that may execute arbitrary commands during package operations"
    depends = []
    tags = ["persistence", "dpkg", "hooks", "package"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        for hook_dir in DPKG_HOOK_DIRS:
            if not os.path.isdir(hook_dir):
                continue
            try:
                entries = sorted(os.listdir(hook_dir))
            except (OSError, PermissionError):
                continue

            for entry in entries:
                if entry in KNOWN_DPKG_HOOKS:
                    continue

                fp = os.path.join(hook_dir, entry)
                if not os.path.isfile(fp):
                    continue

                is_executable = os.access(fp, os.X_OK)
                try:
                    with open(fp) as f:
                        content = f.read()
                except (OSError, PermissionError):
                    content = ""

                suspicious_matches = SUSPICIOUS_HOOK_PATTERNS_RE.findall(content)

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Unknown dpkg hook: {entry}",
                        description=(
                            f"Unknown dpkg hook '{entry}' in {hook_dir}. "
                            f"Executable: {is_executable}. "
                            f"{f'Suspicious patterns: {suspicious_matches}' if suspicious_matches else ''}"
                        ),
                        rationale=(
                            "Dpkg hooks execute during package install/remove operations. "
                            "Attackers use dpkg hooks to maintain persistence by "
                            "re-installing their backdoors whenever a legitimate "
                            "package is updated. The hook runs as root and can "
                            "execute arbitrary commands."
                        ),
                        remediation=(
                            f"Investigate: 'cat {fp}'\n"
                            f"Remove if unauthorized: 'rm {fp}'\n"
                            f"Check if part of a legitimate package: 'dpkg -S {fp}'"
                        ),
                        evidence=FileEvidence(
                            path=fp,
                            content=content[:500],
                            owner="",
                            group="",
                        ),
                        detected_value=entry,
                        expected_value="Only known dpkg hooks should exist",
                        affected_component=entry,
                        confidence=Confidence.HIGH if suspicious_matches else Confidence.MEDIUM,
                        false_positive_probability=0.2 if suspicious_matches else 0.4,
                        mitre_attack_ids=["T1546.015"],
                        tags=["persistence", "dpkg", "hook", "package"],
                    )
                )

        return findings
