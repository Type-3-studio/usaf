from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

PERSISTENCE_DIRS: dict[str, str] = {
    "/etc/modprobe.d": "kernel module configuration",
    "/etc/sysctl.d": "kernel sysctl configuration",
    "/etc/security/limits.d": "resource limit configuration",
    "/etc/environment": "system-wide environment variables",
    "/etc/systemd/system-generators": "systemd generators",
    "/etc/dbus-1/system.d": "D-Bus system service config",
    "/etc/polkit-1/rules.d": "polkit authorization rules",
    "/etc/tmpfiles.d": "systemd tmpfile configuration",
    "/etc/sysusers.d": "systemd sysuser configuration",
    "/etc/binfmt.d": "binary format handlers",
    "/etc/modules-load.d": "kernel module auto-load",
    "/etc/initramfs-tools": "initramfs hooks",
    "/etc/udev/rules.d": "udev device rules (user)",
    "/etc/ld.so.conf.d": "library search path config",
}

KNOWN_SYSTEM_FILES: dict[str, set[str]] = {
    "/etc/modprobe.d": {"blacklist.conf"},
    "/etc/sysctl.d": {"99-sysctl.conf", "10-network-security.conf"},
    "/etc/security/limits.d": set(),
    "/etc/environment": set(),
    "/etc/systemd/system-generators": set(),
    "/etc/dbus-1/system.d": set(),
    "/etc/polkit-1/rules.d": set(),
    "/etc/tmpfiles.d": set(),
    "/etc/sysusers.d": set(),
    "/etc/binfmt.d": set(),
    "/etc/modules-load.d": set(),
    "/etc/initramfs-tools": set(),
    "/etc/udev/rules.d": set(),
    "/etc/ld.so.conf.d": set(),
}


@register_check
class PersistenceDirectoryAuditCheck(AuditCheck):
    id = "PER-901"
    name = "Persistence Directory Audit"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects unexpected files in system persistence directories"
    depends = []
    tags = ["persistence", "directories", "systemd", "kexec"]
    max_findings = 200

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for dirpath, purpose in PERSISTENCE_DIRS.items():
            d = Path(dirpath)
            if not d.is_dir():
                continue

            known = KNOWN_SYSTEM_FILES.get(dirpath, set())

            try:
                for entry in sorted(d.iterdir()):
                    name = entry.name
                    if name in known:
                        continue
                    if name.endswith(".dpkg-old") or name.endswith(".dpkg-dist"):
                        continue
                    if name.endswith(".bak") or name.endswith(".backup"):
                        continue

                    try:
                        st = entry.stat()
                    except OSError:
                        continue

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"File in persistence dir: {dirpath}/{name}",
                            description=f"'{dirpath}/{name}' is present in {purpose} directory. This may be intentional or malicious.",
                            rationale="Persistence directories control system behavior at various levels. Unexpected files here can indicate attacker persistence, backdoors, or configuration drift.",
                            remediation=f"Review '{dirpath}/{name}': 'cat {dirpath}/{name}'. If authorized, document in usaf.yaml. If not, remove and investigate.",
                            evidence=FileEvidence(
                                path=f"{dirpath}/{name}",
                                permission=oct(stat.S_IMODE(st.st_mode)),
                                owner=str(st.st_uid),
                                size=st.st_size,
                                content=f"Located in {purpose} directory",
                            ),
                            detected_value=f"Unexpected file: {dirpath}/{name}",
                            expected_value="Only known system files",
                            affected_component=f"{dirpath}/{name}",
                            confidence=Confidence.MEDIUM,
                            false_positive_probability=0.3,
                            mitre_attack_ids=["T1037", "T1053"],
                            tags=["persistence", "directories", "audit"],
                        )
                    )
            except PermissionError:
                continue

        return findings


@register_check
class WorldWritablePersistenceCheck(AuditCheck):
    id = "PER-902"
    name = "World-Writable Persistence Files"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects world-writable files in persistence directories"
    depends = []
    tags = ["persistence", "permissions", "privilege-escalation"]
    max_findings = 100

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for dirpath in PERSISTENCE_DIRS:
            d = Path(dirpath)
            if not d.is_dir():
                continue

            try:
                for entry in d.iterdir():
                    if not entry.is_file():
                        continue
                    try:
                        st = entry.stat()
                        if not (st.st_mode & stat.S_IWOTH):
                            continue
                    except OSError:
                        continue

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"World-writable persistence: {entry}",
                            description=f"'{entry}' is world-writable (mode {oct(stat.S_IMODE(st.st_mode))[2:]}). Any user can modify this persistent system configuration.",
                            rationale="World-writable files in persistence directories allow any user to inject persistent behavior. This is a high-risk privilege escalation and persistence vector.",
                            remediation=f"Restrict permissions: 'chmod 644 {entry}'.",
                            evidence=FileEvidence(
                                path=str(entry),
                                permission=oct(stat.S_IMODE(st.st_mode)),
                                owner=str(st.st_uid),
                                size=st.st_size,
                                content="World-writable persistence file",
                            ),
                            detected_value=f"World-writable: {entry}",
                            expected_value="Not world-writable",
                            affected_component=str(entry),
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.05,
                            mitre_attack_ids=["T1222", "T1037"],
                            tags=["persistence", "permissions", "privilege-escalation"],
                        )
                    )
            except PermissionError:
                continue

        return findings


@register_check
class SystemdGeneratorCheck(AuditCheck):
    id = "PER-903"
    name = "Systemd Generators"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects systemd generator scripts that can persist code"
    depends = []
    tags = ["persistence", "systemd", "generators"]

    GENERATOR_DIRS: list[str] = [
        "/etc/systemd/system-generators",
        "/run/systemd/system-generators",
        "/usr/lib/systemd/system-generators",
    ]

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for gen_dir in self.GENERATOR_DIRS:
            d = Path(gen_dir)
            if not d.is_dir():
                continue

            try:
                for entry in d.iterdir():
                    if not entry.is_file() and not entry.is_symlink():
                        continue
                    if entry.name.endswith(".dpkg-dist") or entry.name.endswith(".dpkg-old"):
                        continue

                    try:
                        st = entry.stat()
                    except OSError:
                        continue

                    if st.st_uid != 0:
                        findings.append(
                            self.finding(
                                finding_id="001",
                                title=f"Systemd generator not owned by root: {entry.name}",
                                description=f"Generator '{entry}' is owned by uid {st.st_uid} instead of root.",
                                rationale="Systemd generators execute during boot and can create arbitrary unit files. Non-root ownership allows privilege escalation.",
                                remediation=f"Fix ownership: 'chown root:root {entry}'.",
                                evidence=FileEvidence(path=str(entry), owner=str(st.st_uid), permission=oct(stat.S_IMODE(st.st_mode))),
                                detected_value=f"Owner uid {st.st_uid}",
                                expected_value="root ownership",
                                affected_component=str(entry),
                                confidence=Confidence.HIGH,
                                false_positive_probability=0.05,
                                mitre_attack_ids=["T1543"],
                                tags=["persistence", "systemd", "generators"],
                            )
                        )
            except PermissionError:
                continue

        return findings


@register_check
class DbusActivatedServicesCheck(AuditCheck):
    id = "PER-904"
    name = "D-Bus Activated Services"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects unexpected D-Bus service activation files"
    depends = []
    tags = ["persistence", "dbus", "services", "activation"]
    max_findings = 100

    DBUS_DIRS: list[str] = [
        "/etc/dbus-1/system.d",
        "/etc/dbus-1/services",
        "/usr/share/dbus-1/system-services",
        "/usr/share/dbus-1/services",
    ]

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for dbus_dir in self.DBUS_DIRS:
            d = Path(dbus_dir)
            if not d.is_dir():
                continue

            try:
                for entry in d.iterdir():
                    if not entry.name.endswith(".conf") and not entry.name.endswith(".service"):
                        continue

                    try:
                        st = entry.stat()
                    except OSError:
                        continue

                    if st.st_uid == 0 and not (st.st_mode & stat.S_IWOTH):
                        continue

                    issues: list[str] = []
                    if st.st_uid != 0:
                        issues.append(f"owner uid {st.st_uid}")
                    if st.st_mode & stat.S_IWOTH:
                        issues.append("world-writable")

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Insecure D-Bus config: {entry.name}",
                            description=f"D-Bus configuration '{entry}' has issues: {'; '.join(issues)}.",
                            rationale="D-Bus service files define how system services are activated. Insecure permissions or ownership can allow unauthorized service activation.",
                            remediation=f"Fix: 'chown root:root {entry} && chmod 644 {entry}'.",
                            evidence=FileEvidence(path=str(entry), owner=str(st.st_uid), permission=oct(stat.S_IMODE(st.st_mode))),
                            detected_value="; ".join(issues),
                            expected_value="root-owned, not world-writable",
                            affected_component=str(entry),
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.1,
                            mitre_attack_ids=["T1543"],
                            tags=["persistence", "dbus", "services", "activation"],
                        )
                    )
            except PermissionError:
                continue

        return findings


@register_check
class PolkitRulePersistenceCheck(AuditCheck):
    id = "PER-905"
    name = "Polkit Rule Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects unexpected polkit authorization rule files"
    depends = []
    tags = ["persistence", "polkit", "privilege-escalation"]

    POLKIT_DIRS: list[str] = [
        "/etc/polkit-1/rules.d",
        "/usr/share/polkit-1/rules.d",
    ]

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for polkit_dir in self.POLKIT_DIRS:
            d = Path(polkit_dir)
            if not d.is_dir():
                continue

            try:
                for entry in d.iterdir():
                    if not entry.name.endswith(".rules"):
                        continue
                    if entry.name in ("00-ubuntu-admin.rules",):
                        continue

                    try:
                        st = entry.stat()
                    except OSError:
                        continue

                    if st.st_uid == 0 and not (st.st_mode & stat.S_IWOTH):
                        continue

                    issues: list[str] = []
                    if st.st_uid != 0:
                        issues.append(f"owner uid {st.st_uid}")
                    if st.st_mode & stat.S_IWOTH:
                        issues.append("world-writable")

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Polkit rule file: {entry.name}",
                            description=f"Polkit rule '{entry.name}' issues: {'; '.join(issues) if issues else 'present but not from standard package'}.",
                            rationale="Polkit rules define authorization policies. Unexpected or world-writable rules can grant unauthorized privilege escalation.",
                            remediation=f"Review rule: 'cat {entry}'. If unauthorized, remove: 'rm {entry}'.",
                            evidence=FileEvidence(path=str(entry), owner=str(st.st_uid), permission=oct(stat.S_IMODE(st.st_mode))),
                            detected_value="; ".join(issues) if issues else "non-standard polkit rule",
                            expected_value="Only standard polkit rules",
                            affected_component=str(entry),
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.15,
                            mitre_attack_ids=["T1543"],
                            tags=["persistence", "polkit", "privilege-escalation"],
                        )
                    )
            except PermissionError:
                continue

        return findings


@register_check
class TmpfilesDPersistenceCheck(AuditCheck):
    id = "PER-906"
    name = "Systemd Tmpfiles Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects unexpected tmpfiles.d configuration"
    depends = []
    tags = ["persistence", "systemd", "tmpfiles"]

    TMPFILES_DIRS: list[str] = [
        "/etc/tmpfiles.d",
        "/run/tmpfiles.d",
        "/usr/lib/tmpfiles.d",
    ]

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for tdir in self.TMPFILES_DIRS:
            d = Path(tdir)
            if not d.is_dir():
                continue

            try:
                for entry in d.iterdir():
                    if not entry.name.endswith(".conf"):
                        continue

                    try:
                        st = entry.stat()
                    except OSError:
                        continue

                    if entry.name.startswith("systemd-") or entry.name.startswith("home-"):
                        continue
                    if st.st_uid == 0:
                        continue

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Non-root tmpfiles conf: {entry.name}",
                            description=f"tmpfiles.d entry '{entry.name}' is owned by uid {st.st_uid} instead of root.",
                            rationale="tmpfiles.d configurations create, delete, and manage files at boot. Non-root ownership allows arbitrary file creation with privileges.",
                            remediation=f"Fix ownership: 'chown root:root {entry}'.",
                            evidence=FileEvidence(path=str(entry), owner=str(st.st_uid), permission=oct(stat.S_IMODE(st.st_mode))),
                            detected_value=f"Owner uid {st.st_uid}",
                            expected_value="root owner",
                            affected_component=str(entry),
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.1,
                            mitre_attack_ids=["T1053"],
                            tags=["persistence", "systemd", "tmpfiles"],
                        )
                    )
            except PermissionError:
                continue

        return findings


@register_check
class ModuleLoadPersistenceCheck(AuditCheck):
    id = "PER-907"
    name = "Kernel Module Load Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects kernel module auto-load configuration in modules-load.d"
    depends = []
    tags = ["persistence", "kernel", "modules", "load"]

    MODULES_LOAD_DIRS: list[str] = [
        "/etc/modules-load.d",
        "/run/modules-load.d",
        "/usr/lib/modules-load.d",
    ]

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for mdir in self.MODULES_LOAD_DIRS:
            d = Path(mdir)
            if not d.is_dir():
                continue

            try:
                for entry in d.iterdir():
                    if not entry.name.endswith(".conf"):
                        continue
                    if entry.name in ("modules.conf",):
                        continue

                    try:
                        text = entry.read_text()
                    except OSError:
                        continue

                    modules = [l.strip() for l in text.splitlines()
                               if l.strip() and not l.strip().startswith("#")]

                    for modline in modules:
                        if modline.startswith("blacklist"):
                            continue

                        findings.append(
                            self.finding(
                                finding_id="001",
                                title=f"Auto-loaded module: {modline}",
                                description=f"Kernel module '{modline}' is configured for automatic loading in '{entry}'.",
                                rationale="Kernel modules auto-loaded at boot can be used for rootkits, keystroke loggers, and hardware backdoors.",
                                remediation=f"Review module '{modline}'. If unnecessary, remove from '{entry}' or blacklist: 'echo blacklist {modline} > /etc/modprobe.d/blacklist.conf'.",
                                evidence=RegistryEvidence(key=f"modules-load.{entry.name}.module", value=modline, expected="only required modules", source=str(entry)),
                                detected_value=f"Module: {modline}",
                                expected_value="Only required kernel modules",
                                affected_component=f"Module: {modline}",
                                confidence=Confidence.LOW,
                                false_positive_probability=0.5,
                                mitre_attack_ids=["T1547"],
                                tags=["persistence", "kernel", "modules", "load"],
                            )
                        )
            except PermissionError:
                continue

        return findings


@register_check
class ShellInitPersistenceExtCheck(AuditCheck):
    id = "PER-908"
    name = "Extended Shell Init Files"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects unexpected files in shell initialization directories"
    depends = ["users"]
    tags = ["persistence", "shell", "init", "bash"]
    max_findings = 100

    SHELL_INIT_FILES: list[str] = [
        ".bashrc", ".bash_profile", ".bash_login", ".profile",
        ".zshrc", ".zprofile", ".zlogin", ".kshrc",
        ".env", ".alias", ".aliases", ".exports",
        ".path", ".config/fish/config.fish",
        ".local/share/fish/generated_completions",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")

        for entry in users_data.get("users", []):
            username = entry.get("username", "")
            uid = entry.get("uid", 0)
            home = entry.get("home", "")

            if not home or home == "/nonexistent" or uid < 1000:
                continue

            for init_file in self.SHELL_INIT_FILES:
                fpath = Path(home) / init_file
                if not fpath.is_file():
                    continue

                try:
                    st = fpath.stat()
                except OSError:
                    continue

                if st.st_uid == uid or st.st_uid == 0:
                    continue

                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Wrong owner on init file: {fpath}",
                        description=f"'{fpath}' is owned by uid {st.st_uid} instead of {uid}. Shell init files should be owned by the user.",
                        rationale="Shell init files execute commands on login. Wrong ownership allows code injection into the user's session.",
                        remediation=f"Fix: 'chown {username}:{username} {fpath}'.",
                        evidence=FileEvidence(path=str(fpath), owner=str(st.st_uid), permission=oct(stat.S_IMODE(st.st_mode))),
                        detected_value=f"Owner uid {st.st_uid}",
                        expected_value=f"Owner uid {uid}",
                        affected_component=str(fpath),
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.05,
                        mitre_attack_ids=["T1546"],
                        tags=["persistence", "shell", "init", "bash"],
                    )
                )
        return findings


@register_check
class InitramfsHookCheck(AuditCheck):
    id = "PER-909"
    name = "Initramfs Hook Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects unexpected initramfs hook scripts"
    depends = []
    tags = ["persistence", "initramfs", "hooks", "boot"]

    HOOK_DIRS: list[str] = [
        "/etc/initramfs-tools/hooks",
        "/etc/initramfs-tools/scripts/init-top",
        "/etc/initramfs-tools/scripts/init-bottom",
        "/etc/initramfs-tools/scripts/local-top",
        "/etc/initramfs-tools/scripts/local-bottom",
        "/etc/initramfs-tools/scripts/nfs-top",
        "/etc/initramfs-tools/scripts/nfs-bottom",
    ]

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for hook_dir in self.HOOK_DIRS:
            d = Path(hook_dir)
            if not d.is_dir():
                continue

            try:
                for entry in d.iterdir():
                    if entry.name.startswith("."):
                        continue
                    if entry.name in ("README",):
                        continue

                    try:
                        st = entry.stat()
                    except OSError:
                        continue

                    if st.st_uid == 0:
                        continue

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Non-root initramfs hook: {entry.name}",
                            description=f"Initramfs hook '{entry}' is owned by uid {st.st_uid} instead of root.",
                            rationale="Initramfs hooks execute during boot, before the root filesystem is mounted. Non-root ownership allows code execution at the most privileged boot stage.",
                            remediation=f"Fix ownership: 'chown root:root {entry}'.",
                            evidence=FileEvidence(path=str(entry), owner=str(st.st_uid), permission=oct(stat.S_IMODE(st.st_mode))),
                            detected_value=f"Owner uid {st.st_uid}",
                            expected_value="root owner",
                            affected_component=str(entry),
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.05,
                            mitre_attack_ids=["T1542"],
                            tags=["persistence", "initramfs", "hooks", "boot"],
                        )
                    )
            except PermissionError:
                continue

        return findings


@register_check
class LdConfigPersistenceCheck(AuditCheck):
    id = "PER-910"
    name = "Library Path Configuration"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects unexpected library path configuration files"
    depends = []
    tags = ["persistence", "library", "ldconfig", "ld.so"]

    LDSO_DIRS: list[str] = [
        "/etc/ld.so.conf.d",
        "/etc/ld.so.conf",
    ]

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for ldir in self.LDSO_DIRS:
            p = Path(ldir)
            if not p.exists():
                continue

            if p.is_dir():
                try:
                    for entry in p.iterdir():
                        if not entry.name.endswith(".conf"):
                            continue
                        if entry.name in ("libc.conf", "x86_64-linux-gnu.conf", "i386-linux-gnu.conf"):
                            continue

                        try:
                            st = entry.stat()
                        except OSError:
                            continue

                        if st.st_uid != 0:
                            findings.append(
                                self.finding(
                                    finding_id="001",
                                    title=f"Library config not root: {entry.name}",
                                    description=f"'{entry}' is owned by uid {st.st_uid} instead of root.",
                                    rationale="ld.so.conf.d files add directories to the runtime library search path. Non-root ownership allows DLL hijacking and code injection.",
                                    remediation=f"Fix: 'chown root:root {entry}'.",
                                    evidence=FileEvidence(path=str(entry), owner=str(st.st_uid)),
                                    detected_value=f"Owner uid {st.st_uid}",
                                    expected_value="root owner",
                                    affected_component=str(entry),
                                    confidence=Confidence.HIGH,
                                    false_positive_probability=0.05,
                                    mitre_attack_ids=["T1574"],
                                    tags=["persistence", "library", "ldconfig", "ld.so"],
                                )
                            )
                except PermissionError:
                    continue

        return findings


@register_check
class SysctlPersistenceCheck(AuditCheck):
    id = "PER-911"
    name = "Sysctl Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects unexpected sysctl configuration files"
    depends = []
    tags = ["persistence", "sysctl", "kernel", "configuration"]
    max_findings = 50

    SYSCTL_DIRS: list[str] = [
        "/etc/sysctl.d",
        "/run/sysctl.d",
        "/usr/lib/sysctl.d",
    ]

    def _run_check(self, _: dict[str, Any]) -> list:
        findings: list = []

        for sdir in self.SYSCTL_DIRS:
            d = Path(sdir)
            if not d.is_dir():
                continue

            try:
                for entry in d.iterdir():
                    if not entry.name.endswith(".conf"):
                        continue
                    if entry.name in ("99-sysctl.conf", "10-network-security.conf",
                                       "10-ptrace.conf", "10-magic-sysrq.conf",
                                       "10-link-restrictions.conf", "10-zeropage.conf",
                                       "10-unknown-bpf.conf", "10-unknown.conf",
                                       "10-console-messages.conf", "10-kernel-hardening.conf"):
                        continue

                    try:
                        st = entry.stat()
                    except OSError:
                        continue

                    if st.st_uid == 0:
                        continue

                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Non-root sysctl conf: {entry.name}",
                            description=f"'{entry}' is owned by uid {st.st_uid} instead of root.",
                            rationale="sysctl configuration files set kernel parameters at boot. Non-root ownership allows kernel parameter manipulation for privilege escalation.",
                            remediation=f"Fix: 'chown root:root {entry}'.",
                            evidence=FileEvidence(path=str(entry), owner=str(st.st_uid)),
                            detected_value=f"Owner uid {st.st_uid}",
                            expected_value="root owner",
                            affected_component=str(entry),
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.05,
                            mitre_attack_ids=["T1562"],
                            tags=["persistence", "sysctl", "kernel", "configuration"],
                        )
                    )
            except PermissionError:
                continue

        return findings


@register_check
class UserTimerPersistenceCheck(AuditCheck):
    id = "PER-912"
    name = "User Timer Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects suspicious systemd user timer units"
    depends = ["users"]
    tags = ["persistence", "systemd", "timers", "user"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")

        for entry in users_data.get("users", []):
            username = entry.get("username", "")
            uid = entry.get("uid", 0)
            home = entry.get("home", "")

            if not home or home == "/nonexistent" or uid < 1000:
                continue

            user_units = Path(home) / ".config/systemd/user"
            if not user_units.is_dir():
                continue

            timers = list(user_units.glob("*.timer"))
            for timer in timers:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"User timer: {timer.name} ({username})",
                        description=f"User '{username}' has a systemd user timer '{timer.name}'. User timers execute with user privileges and may indicate persistence.",
                        rationale="Systemd user timers execute at user login or on schedule. While legitimate, they can be used for user-level persistence that survives across sessions.",
                        remediation=f"Review timer: 'systemctl --user cat {timer.name}'. If unauthorized: 'systemctl --user disable {timer.name}' and 'rm {timer}'.",
                        evidence=FileEvidence(path=str(timer)),
                        detected_value=f"User timer: {timer.name}",
                        expected_value="No user timers unless expected",
                        affected_component=str(timer),
                        confidence=Confidence.LOW,
                        false_positive_probability=0.5,
                        mitre_attack_ids=["T1053"],
                        tags=["persistence", "systemd", "timers", "user"],
                    )
                )

        return findings
