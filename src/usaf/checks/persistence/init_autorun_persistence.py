import os
from datetime import datetime

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

RC_LOCAL = "/etc/rc.local"
INIT_D_DIR = "/etc/init.d"
SYSTEMD_USER_UNITS_DIRS = [
    "/etc/systemd/user",
    "/run/systemd/user",
]

KNOWN_INIT_D_SCRIPTS = {
    "alsa-utils",
    "anacron",
    "apparmor",
    "apport",
    "avahi-daemon",
    "bluetooth",
    "console-setup",
    "cron",
    "cups",
    "cups-browsed",
    "dbus",
    "dns-clean",
    "grub-common",
    "halt",
    "hwclock",
    "irqbalance",
    "kerneloops",
    "keyboard-setup",
    "killprocs",
    "kmod",
    "lvm2",
    "lvm2-lvmpolld",
    "mdadm",
    "mdadm-waitidle",
    "network-manager",
    "networking",
    "ondemand",
    "open-iscsi",
    "open-vm-tools",
    "plymouth",
    "plymouth-log",
    "pppd-dns",
    "procps",
    "quota",
    "rc",
    "rcS",
    "reboot",
    "resolvconf",
    "rsync",
    "rsyslog",
    "samba-ad-dc",
    "screen-cleanup",
    "sendsigs",
    "smbd",
    "ssh",
    "sudo",
    "sysklogd",
    "timidity",
    "ufw",
    "umountfs",
    "umountnfs",
    "umountroot",
    "unattended-upgrades",
    "urandom",
    "whoopsie",
}

KNOWN_SYSTEMD_USER_UNITS = {
    "dbus.service",
    "dirmngr.service",
    "dirmngr.socket",
    "gpg-agent.service",
    "gpg-agent.socket",
    "gpg-agent-extra.socket",
    "gpg-agent-browser.socket",
    "gpg-agent-ssh.socket",
    "pipewire.service",
    "pipewire.socket",
    "pipewire-pulse.service",
    "pipewire-pulse.socket",
    "pulseaudio.service",
    "pulseaudio.socket",
    "wireplumber.service",
    "xdg-document-portal.service",
    "xdg-permission-store.service",
    "xdg-desktop-portal.service",
}

KNOWN_XDG_AUTOSTART_APPS = {
    "gnome-settings-daemon.desktop",
    "gnome-software-service.desktop",
    "gnome-terminal.desktop",
    "gnome-shell-overrides-migration.desktop",
    "ibus-desktop-setup.desktop",
    "ibus-setup.desktop",
    "im-launch.desktop",
    "indicator-application.desktop",
    "indicator-messages.desktop",
    "indicator-session.desktop",
    "indicator-sound.desktop",
    "org.gnome.SettingsDaemon.Housekeeping.desktop",
    "org.gnome.SettingsDaemon.A11ySettings.desktop",
    "org.gnome.SettingsDaemon.Clipboard.desktop",
    "org.gnome.SettingsDaemon.Color.desktop",
    "org.gnome.SettingsDaemon.Datetime.desktop",
    "org.gnome.SettingsDaemon.DiskUtilityNotify.desktop",
    "org.gnome.SettingsDaemon.Keyboard.desktop",
    "org.gnome.SettingsDaemon.MediaKeys.desktop",
    "org.gnome.SettingsDaemon.Power.desktop",
    "org.gnome.SettingsDaemon.PrintNotifications.desktop",
    "org.gnome.SettingsDaemon.Rfkill.desktop",
    "org.gnome.SettingsDaemon.ScreensaverProxy.desktop",
    "org.gnome.SettingsDaemon.Sharing.desktop",
    "org.gnome.SettingsDaemon.Smartcard.desktop",
    "org.gnome.SettingsDaemon.Sound.desktop",
    "org.gnome.SettingsDaemon.UsbProtection.desktop",
    "org.gnome.SettingsDaemon.Wacom.desktop",
    "org.gnome.SettingsDaemon.XSettings.desktop",
    "org.gnome.Shell.desktop",
    "org.gnome.Shell.Notifications.desktop",
    "org.gnome.Shell.PortalHelper.desktop",
    "snapd.user-session.service",
    "update-notifier.desktop",
    "user-dirs-update-gtk.desktop",
    "vboxclient.desktop",
    "xfce4-power-manager.desktop",
    "xfce4-session.desktop",
    "xfce4-settings-helper.desktop",
    "xfdesktop.desktop",
    "xfsettingsd.desktop",
    "xfwm4.desktop",
    "xss-lock.desktop",
    "onboard-autostart.desktop",
    "orca-autostart.desktop",
    "spice-vdagent.desktop",
    "pulseaudio.desktop",
    "nm-applet.desktop",
    "blueman.desktop",
}

SUSPICIOUS_INIT_PATTERNS = [
    "wget ",
    "curl ",
    "nc ",
    "ncat",
    "bash -c",
    "python",
    "perl -e",
    "mkfifo",
    "/dev/tcp/",
    "base64 -d",
    "chmod +x",
    "nohup",
    "setsid",
    "socat",
    "openssl",
]


@register_check
class RcLocalScriptCheck(AuditCheck):
    id = "PER-801"
    name = "rc.local Script Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects suspicious content in /etc/rc.local"
    depends = []
    tags = ["persistence", "rc-local", "init", "boot"]

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        if not os.path.exists(RC_LOCAL):
            return findings

        try:
            with open(RC_LOCAL) as f:
                content = f.read()
            st = os.stat(RC_LOCAL)
        except (OSError, PermissionError):
            return findings

        is_executable = os.access(RC_LOCAL, os.X_OK)
        suspicious_matches = [p for p in SUSPICIOUS_INIT_PATTERNS if p in content]
        lines = content.strip().split("\n")
        non_comment_lines = [entry for entry in lines if entry.strip() and not entry.strip().startswith("#")]
        has_exit_0 = "exit 0" in content

        if not has_exit_0 or len(non_comment_lines) > 2 or suspicious_matches:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="rc.local contains unusual content",
                    description=(
                        f"/etc/rc.local has {len(non_comment_lines)} executable lines, "
                        f"executable={is_executable}, exit 0 present={has_exit_0}. "
                        f"{f'Suspicious patterns: {suspicious_matches}' if suspicious_matches else ''}"
                    ),
                    rationale=(
                        "/etc/rc.local executes on every boot as root before login. "
                        "It is a classic persistence vector — attackers append "
                        "malicious commands to rc.local to execute payloads at "
                        "system startup. The file should only contain system-relevant "
                        "commands and should always have 'exit 0'."
                    ),
                    remediation=(
                        f"Review: 'cat {RC_LOCAL}'\n"
                        f"Remove unauthorized lines\n"
                        f"Ensure it ends with 'exit 0'\n"
                        f"Disable the rc-local service if not needed"
                    ),
                    evidence=FileEvidence(
                        path=RC_LOCAL,
                        content=content[:500],
                        owner="",
                        group="",
                        size=st.st_size,
                        modified=datetime.fromtimestamp(st.st_mtime),
                    ),
                    detected_value=f"{len(non_comment_lines)} executable lines, no exit 0" if not has_exit_0 else "Has content",
                    expected_value="Empty or minimal rc.local with exit 0",
                    affected_component=RC_LOCAL,
                    confidence=Confidence.HIGH if suspicious_matches else Confidence.MEDIUM,
                    false_positive_probability=0.1 if suspicious_matches else 0.3,
                    mitre_attack_ids=["T1037.004"],
                    tags=["persistence", "rc-local", "boot", "init"],
                )
            )

        return findings


@register_check
class InitScriptPersistenceCheck(AuditCheck):
    id = "PER-802"
    name = "Init.d Script Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects unknown init.d scripts that may indicate persistence"
    depends = []
    tags = ["persistence", "init-d", "init", "boot"]

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        if not os.path.isdir(INIT_D_DIR):
            return findings

        try:
            entries = sorted(os.listdir(INIT_D_DIR))
        except (OSError, PermissionError):
            return findings

        for entry in entries:
            if entry in KNOWN_INIT_D_SCRIPTS:
                continue
            if entry.startswith(".") or entry.startswith("README"):
                continue

            fp = os.path.join(INIT_D_DIR, entry)
            if not os.path.isfile(fp):
                continue
            if not os.access(fp, os.X_OK):
                continue

            try:
                with open(fp) as f:
                    first_lines = "".join(f.readlines()[:30])
                st = os.stat(fp)
            except (OSError, PermissionError):
                continue

            suspicious_matches = [p for p in SUSPICIOUS_INIT_PATTERNS if p in first_lines]

            findings.append(
                self.finding(
                    finding_id="001" if suspicious_matches else "002",
                    title=(
                        f"Suspicious init.d script: {entry}"
                        if suspicious_matches
                        else f"Unknown init.d script: {entry}"
                    ),
                    description=(
                        f"Unknown init.d script '{entry}' in {INIT_D_DIR}. "
                        f"{f'Contains suspicious patterns: {suspicious_matches}' if suspicious_matches else ''}"
                    ),
                    rationale=(
                        "Init.d scripts execute during system boot. Attackers place "
                        "malicious scripts here for boot-level persistence. Unlike "
                        "systemd services, init.d scripts are less monitored and can "
                        "persist even if systemd is not the init system."
                    ),
                    remediation=(
                        f"Investigate: 'cat {fp}'\n"
                        f"Check package ownership: 'dpkg -S {fp}'\n"
                        f"Remove if unauthorized: 'rm {fp} && update-rc.d {entry} remove'"
                    ),
                    evidence=FileEvidence(
                        path=fp,
                        content=first_lines,
                        owner="",
                        group="",
                        size=st.st_size,
                        modified=datetime.fromtimestamp(st.st_mtime),
                    ),
                    detected_value=entry,
                    expected_value="Only known init.d scripts should exist",
                    affected_component=entry,
                    confidence=Confidence.HIGH if suspicious_matches else Confidence.LOW,
                    false_positive_probability=0.2 if suspicious_matches else 0.6,
                    mitre_attack_ids=["T1037.004"],
                    tags=["persistence", "init-d", "boot", "init"],
                )
            )

        return findings


@register_check
class LoginLogoutHooksCheck(AuditCheck):
    id = "PER-803"
    name = "Login/Logout Hook Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects login/logout hooks that execute on user session events"
    depends = ["users"]
    tags = ["persistence", "login", "logout", "hooks"]

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        login_hook_files = [
            "/etc/profile",
            "/etc/bash.bashrc",
            "/etc/zsh/zshrc",
            "/etc/zshrc",
        ]

        for fp in login_hook_files:
            if not os.path.exists(fp):
                continue
            try:
                with open(fp) as f:
                    content = f.read()
            except (OSError, PermissionError):
                continue

            for suspicious in ["trap ", "EXIT", "SIGINT", "SIGTERM"]:
                if suspicious in content:
                    lines_containing = [
                        entry.strip() for entry in content.split("\n")
                        if suspicious.lower() in entry.lower()
                    ]
                    if lines_containing:
                        findings.append(
                            self.finding(
                                finding_id="001",
                                title=f"Signal trap in {os.path.basename(fp)}",
                                description=(
                                    f"File {fp} contains trap/signal handler. "
                                    f"Relevant lines: {'; '.join(lines_containing[:3])}"
                                ),
                                rationale=(
                                    "Login/logout hooks using trap or signal handlers "
                                    "can execute arbitrary code when bash exits. "
                                    "Attackers use 'trap ... EXIT' or 'trap ... 0' "
                                    "to execute malicious commands when the admin "
                                    "logs out of a session."
                                ),
                                remediation=(
                                    f"Inspect: 'cat {fp}'\n"
                                    f"Remove malicious trap handlers\n"
                                    f"Check for additional login hooks"
                                ),
                                evidence=FileEvidence(
                                    path=fp,
                                    content="\n".join(lines_containing[:5]),
                                    owner="",
                                    group="",
                                ),
                                detected_value=f"trap/signal handler in {fp}",
                                expected_value="No trap handlers in shell init files",
                                affected_component=fp,
                                confidence=Confidence.LOW,
                                false_positive_probability=0.6,
                                mitre_attack_ids=["T1546.004"],
                                tags=["persistence", "login", "logout", "hook"],
                            )
                        )
                    break

        return findings


@register_check
class SystemdUserUnitsCheck(AuditCheck):
    id = "PER-804"
    name = "Systemd User Unit Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects systemd user units for user-level persistence"
    depends = ["users"]
    tags = ["persistence", "systemd", "user-units"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        user_data = self._get_optional_data(collectors, "users") or {}
        users = user_data.get("users", [])

        for user_entry in users:
            home = user_entry.get("home", "")
            username = user_entry.get("username", "")
            if not home or home == "/nonexistent":
                continue

            user_systemd_units = [
                os.path.join(home, ".config", "systemd", "user"),
                os.path.join(home, ".local", "share", "systemd", "user"),
            ]

            for unit_dir in user_systemd_units:
                if not os.path.isdir(unit_dir):
                    continue
                try:
                    unit_files = [
                        f for f in os.listdir(unit_dir)
                        if f.endswith(".service") or f.endswith(".timer") or f.endswith(".path")
                    ]
                except (OSError, PermissionError):
                    continue

                for uf in unit_files:
                    if uf in KNOWN_SYSTEMD_USER_UNITS:
                        continue
                    fp = os.path.join(unit_dir, uf)
                    try:
                        with open(fp) as f:
                            content = f.read()
                        st = os.stat(fp)
                    except (OSError, PermissionError):
                        continue

                    suspicious_matches = [p for p in SUSPICIOUS_INIT_PATTERNS if p in content]

                    findings.append(
                        self.finding(
                            finding_id="001" if suspicious_matches else "002",
                            title=(
                                f"Suspicious user unit: {uf} for {username}"
                                if suspicious_matches
                                else f"Unknown user unit: {uf} for {username}"
                            ),
                            description=(
                                f"User '{username}' has systemd user unit '{uf}' "
                                f"in {unit_dir}. "
                                f"{f'Suspicious patterns: {suspicious_matches}' if suspicious_matches else ''}"
                            ),
                            rationale=(
                                "Systemd user units run with the user's privileges and "
                                "start on user login. Attackers use user-level systemd "
                                "units for per-user persistence that survives reboots. "
                                "User units are harder to detect than system-wide units "
                                "since they don't appear in systemctl list-units."
                            ),
                            remediation=(
                                f"Investigate: 'systemctl --user cat {uf}'\n"
                                f"Check as user: 'sudo -u {username} systemctl --user status {uf}'\n"
                                f"Remove: 'rm {fp}'"
                            ),
                            evidence=FileEvidence(
                                path=fp,
                                content=content[:500],
                                owner=username,
                                group="",
                                size=st.st_size,
                                modified=datetime.fromtimestamp(st.st_mtime),
                            ),
                            detected_value=uf,
                            expected_value="No unexpected systemd user units",
                            affected_component=uf,
                            confidence=Confidence.HIGH if suspicious_matches else Confidence.LOW,
                            false_positive_probability=0.2 if suspicious_matches else 0.5,
                            mitre_attack_ids=["T1543.002"],
                            tags=["persistence", "systemd", "user-unit"],
                        )
                    )

        return findings


@register_check
class XdgAutostartCheck(AuditCheck):
    id = "PER-805"
    name = "XDG Autostart Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects XDG autostart entries for GUI session persistence"
    depends = ["users"]
    tags = ["persistence", "xdg", "autostart", "gui"]

    def _run_check(self, _collectors: dict) -> list:
        findings: list = []

        xdg_autostart_dirs = [
            "/etc/xdg/autostart",
        ]

        for ad in xdg_autostart_dirs:
            if not os.path.isdir(ad):
                continue
            try:
                entries = sorted(os.listdir(ad))
            except (OSError, PermissionError):
                continue

            for entry in entries:
                if entry in KNOWN_XDG_AUTOSTART_APPS:
                    continue
                if not entry.endswith(".desktop"):
                    continue

                fp = os.path.join(ad, entry)
                if not os.path.isfile(fp):
                    continue
                try:
                    with open(fp) as f:
                        content = f.read()
                except (OSError, PermissionError):
                    content = ""

                suspicious_matches = [p for p in SUSPICIOUS_INIT_PATTERNS if p in content]
                has_exec = "Exec=" in content
                has_hidden = "Hidden=true" in content

                findings.append(
                    self.finding(
                        finding_id="001" if suspicious_matches else "002",
                        title=(
                            f"Suspicious autostart entry: {entry}"
                            if suspicious_matches
                            else f"Unknown autostart entry: {entry}"
                        ),
                        description=(
                            f"XDG autostart entry '{entry}' in {ad}. "
                            f"Exec={has_exec}, Hidden={has_hidden}, "
                            f"{f'Suspicious patterns: {suspicious_matches}' if suspicious_matches else ''}"
                        ),
                        rationale=(
                            "XDG autostart entries launch applications when a user "
                            "logs into a graphical desktop session. Attackers place "
                            "malicious .desktop files in autostart directories to "
                            "maintain GUI-level persistence. This is effective on "
                            "desktop Ubuntu installations and bypasses non-GUI "
                            "security checks."
                        ),
                        remediation=(
                            f"Investigate: 'cat {fp}'\n"
                            f"Remove if unauthorized: 'rm {fp}'\n"
                            f"Check user-level autostart: ~/.config/autostart/"
                        ),
                        evidence=FileEvidence(
                            path=fp,
                            content=content[:500],
                            owner="",
                            group="",
                        ),
                        detected_value=entry,
                        expected_value="Only known autostart entries should exist",
                        affected_component=entry,
                        confidence=Confidence.HIGH if suspicious_matches else Confidence.LOW,
                        false_positive_probability=0.2 if suspicious_matches else 0.6,
                        mitre_attack_ids=["T1547.001"],
                        tags=["persistence", "xdg", "autostart", "gui"],
                    )
                )

        return findings
