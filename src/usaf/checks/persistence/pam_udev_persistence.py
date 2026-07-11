import os
from datetime import datetime

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


KNOWN_PAM_MODULES = {
    "pam_unix.so": "Unix authentication",
    "pam_unix2.so": "Unix authentication (alt)",
    "pam_pwquality.so": "Password quality",
    "pam_cracklib.so": "Password strength",
    "pam_tally2.so": "Login attempt counting",
    "pam_faillock.so": "Account locking",
    "pam_limits.so": "Resource limits",
    "pam_env.so": "Environment variables",
    "pam_motd.so": "MOTD display",
    "pam_mail.so": "Mail notification",
    "pam_lastlog.so": "Last login display",
    "pam_securetty.so": "Secure TTY restrictions",
    "pam_nologin.so": "Disable non-root logins",
    "pam_selinux.so": "SELinux integration",
    "pam_apparmor.so": "AppArmor integration",
    "pam_systemd.so": "Systemd session",
    "pam_systemd_home.so": "Systemd home",
    "pam_keyinit.so": "Keyring initialization",
    "pam_group.so": "Group membership",
    "pam_time.so": "Time-based access",
    "pam_loginuid.so": "Login UID tracking",
    "pam_wheel.so": "Wheel group restrictions",
    "pam_listfile.so": "File-based access control",
    "pam_rootok.so": "Root authorization",
    "pam_timestamp.so": "Timestamp-based auth caching",
    "pam_gnome_keyring.so": "GNOME keyring unlock",
    "pam_kwallet5.so": "KDE wallet unlock",
    "pam_winbind.so": "Winbind integration",
    "pam_ldap.so": "LDAP authentication",
    "pam_krb5.so": "Kerberos authentication",
    "pam_sss.so": "SSSD authentication",
    "pam_u2f.so": "U2F hardware token",
    "pam_duo.so": "Duo MFA",
    "pam_google_authenticator.so": "Google Authenticator MFA",
    "pam_yubico.so": "Yubikey MFA",
    "pam_ssh_agent_auth.so": "SSH agent auth",
    "pam_cap.so": "Linux capabilities",
    "pam_namespace.so": "Namespace setup",
    "pam_issue.so": "Display /etc/issue",
    "pam_access.so": "Login access control",
    "pam_exec.so": "Execute external command",
    "pam_echo.so": "Display messages",
}

SUSPICIOUS_PAM_MODULE_PATTERNS = [
    "pam_backdoor",
    "pam_rootkit",
    "pam_hook",
    "pam_inject",
    "pam_shellz",
    "pam_filter",
]

CRITICAL_PAM_FILES = [
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-account",
    "/etc/pam.d/common-session",
    "/etc/pam.d/common-password",
    "/etc/pam.d/sshd",
    "/etc/pam.d/login",
    "/etc/pam.d/su",
    "/etc/pam.d/sudo",
]


@register_check
class UnexpectedPamModulesCheck(AuditCheck):
    id = "PER-501"
    name = "Unexpected PAM Modules"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects unexpected or suspicious PAM modules"
    depends = ["pam"]
    tags = ["persistence", "pam", "authentication"]

    def _run_check(self, collectors: dict) -> list:
        pam_data = self._get_data(collectors, "pam")
        findings: list = []

        modules = pam_data.get("modules", [])
        if not modules:
            return findings

        unknown_modules: list[dict] = []
        for mod in modules:
            name = mod.get("name", "")
            path = mod.get("path", "")
            if name and name not in KNOWN_PAM_MODULES:
                if not any(kp in name for kp in KNOWN_PAM_MODULES):
                    unknown_modules.append(mod)

        for mod in unknown_modules:
            name = mod.get("name", "")
            path = mod.get("path", "") or f"<unknown path for {name}>"
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Unknown PAM module: {name}",
                    description=(
                        f"PAM module '{name}' at '{path}' is not in the "
                        f"known PAM modules list."
                    ),
                    rationale=(
                        "Unknown PAM modules are a critical persistence vector. "
                        "Attackers can create malicious PAM modules that capture "
                        "passwords, bypass authentication, or execute arbitrary "
                        "code as any user. The PAM backdoor is a well-known "
                        "attack pattern (e.g., pam_unix-backdoor, pam_python)."
                    ),
                    remediation=(
                        f"Inspect: 'file {path}' and 'strings {path}'\n"
                        f"Check package ownership: 'dpkg -S {path}'\n"
                        f"Remove the module and check which PAM configs reference it\n"
                        f"Immediately rotate all user passwords"
                    ),
                    evidence=FileEvidence(
                        path=path,
                        content=f"Unknown PAM module: {name}",
                        owner="",
                        group="",
                    ),
                    detected_value=name,
                    expected_value="All PAM modules should be known system modules",
                    affected_component=path,
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1556.003"],
                    tags=["persistence", "pam", "authentication", "backdoor"],
                )
            )

        config_files = pam_data.get("config_files", [])
        for cf in config_files:
            content = str(cf.get("content", ""))
            for suspicious_mod in SUSPICIOUS_PAM_MODULE_PATTERNS:
                if suspicious_mod in content.lower():
                    findings.append(
                        self.finding(
                            finding_id="002",
                            title=f"Suspicious PAM module reference in config",
                            description=(
                                f"Config file {cf.get('file', '')} references "
                                f"suspicious PAM module '{suspicious_mod}'"
                            ),
                            rationale=(
                                "PAM config files referencing modules with backdoor-like "
                                "names should be treated as indicators of compromise."
                            ),
                            remediation=(
                                f"Remove the suspicious PAM line from {cf.get('file', '')}\n"
                                f"Check for the module file and delete it\n"
                                f"Immediately rotate all passwords\n"
                                f"Audit system for additional backdoors"
                            ),
                            evidence=RegistryEvidence(
                                key=f"pam_module:{suspicious_mod}",
                                value="present",
                                expected="not present",
                                source=cf.get("file", ""),
                            ),
                            detected_value=suspicious_mod,
                            expected_value="Not present",
                            affected_component=cf.get("file", ""),
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                            mitre_attack_ids=["T1556.003"],
                            tags=["persistence", "pam", "backdoor"],
                        )
                    )

        return findings


@register_check
class PamModuleModificationsCheck(AuditCheck):
    id = "PER-502"
    name = "PAM Module Modifications"
    category = CheckCategory.PERSISTENCE
    severity = Severity.HIGH
    description = "Detects modifications to critical PAM configuration files"
    depends = ["pam"]
    tags = ["persistence", "pam", "authentication"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        for pam_file in CRITICAL_PAM_FILES:
            if not os.path.exists(pam_file):
                continue
            try:
                st = os.stat(pam_file)
            except (OSError, PermissionError):
                continue

            try:
                with open(pam_file) as f:
                    first_lines = "".join(f.readlines()[:50])
            except (OSError, PermissionError):
                first_lines = ""

            modifications_detected = False
            details: list[str] = []

            pam_auth = os.path.join(os.path.dirname(pam_file), os.path.basename(pam_file))
            base_path = pam_file.replace("/etc/pam.d/", "")
            if base_path in ("common-auth", "common-account", "common-session", "common-password"):
                known_defaults = self._get_known_pam_defaults(base_path)
                if known_defaults:
                    for line in first_lines.split("\n"):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            base_module = line.split()[-1] if line.split() else ""
                            if base_module and base_module not in known_defaults and "pam_" in line:
                                modifications_detected = True
                                details.append(f"Unexpected module: {base_module}")

            if modifications_detected:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"PAM configuration modified: {os.path.basename(pam_file)}",
                        description=(
                            f"PAM file {pam_file} contains unexpected module "
                            f"references: {'; '.join(details)}"
                        ),
                        rationale=(
                            "Modifications to critical PAM files can indicate "
                            "authentication backdoors. Attackers add PAM modules "
                            "that accept a master password or bypass authentication "
                            "entirely."
                        ),
                        remediation=(
                            f"Review: 'cat {pam_file}'\n"
                            f"Restore from package: 'dpkg --verify pam' or reinstall\n"
                            f"Rotate all user passwords immediately"
                        ),
                        evidence=FileEvidence(
                            path=pam_file,
                            content=first_lines[:500],
                            owner="",
                            group="",
                            modified=datetime.fromtimestamp(st.st_mtime),
                        ),
                        detected_value=f"Modified modules: {'; '.join(details)}",
                        expected_value="Only standard PAM modules should be present",
                        affected_component=pam_file,
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1556.003"],
                        tags=["persistence", "pam", "authentication"],
                    )
                )

        return findings

    def _get_known_pam_defaults(self, base_name: str) -> set[str]:
        defaults = {
            "common-auth": {
                "pam_unix.so",
                "pam_unix2.so",
                "pam_sss.so",
                "pam_ldap.so",
                "pam_krb5.so",
                "pam_winbind.so",
                "pam_u2f.so",
                "pam_duo.so",
                "pam_google_authenticator.so",
                "pam_yubico.so",
                "pam_permit.so",
                "pam_deny.so",
            },
            "common-account": {
                "pam_unix.so",
                "pam_sss.so",
                "pam_ldap.so",
                "pam_krb5.so",
                "pam_winbind.so",
            },
            "common-session": {
                "pam_unix.so",
                "pam_sss.so",
                "pam_systemd.so",
                "pam_systemd_home.so",
                "pam_keyinit.so",
                "pam_limits.so",
                "pam_motd.so",
                "pam_mail.so",
                "pam_lastlog.so",
                "pam_env.so",
            },
            "common-password": {
                "pam_unix.so",
                "pam_pwquality.so",
                "pam_cracklib.so",
                "pam_sss.so",
            },
        }
        return defaults.get(base_name, set())


@register_check
class UdevRulesPersistenceCheck(AuditCheck):
    id = "PER-503"
    name = "Udev Rules Persistence"
    category = CheckCategory.PERSISTENCE
    severity = Severity.MEDIUM
    description = "Detects udev rules that may be used for device-triggered persistence"
    depends = []
    tags = ["persistence", "udev", "device", "trigger"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []

        udev_dirs = [
            "/etc/udev/rules.d",
            "/run/udev/rules.d",
            "/usr/lib/udev/rules.d",
        ]

        for udev_dir in udev_dirs:
            if not os.path.isdir(udev_dir):
                continue
            try:
                entries = sorted(os.listdir(udev_dir))
            except (OSError, PermissionError):
                continue

            for entry in entries:
                if not entry.endswith(".rules"):
                    continue
                fp = os.path.join(udev_dir, entry)
                if not os.path.isfile(fp):
                    continue

                if udev_dir.startswith("/usr/lib/"):
                    continue

                try:
                    with open(fp) as f:
                        content = f.read()
                except (OSError, PermissionError):
                    continue

                has_run = "RUN+" in content
                has_program = "PROGRAM=" in content or "IMPORT{program}" in content
                has_exec = "RUN+=" in content

                if has_run or has_program:
                    suspicious = any(
                        p in content.lower()
                        for p in ["/tmp/", "/dev/shm/", "base64", "chmod +x", "wget ", "curl "]
                    )
                    findings.append(
                        self.finding(
                            finding_id="001" if suspicious else "002",
                            title=(
                                f"Suspicious udev rule: {entry}"
                                if suspicious
                                else f"Udev rule with RUN/PROGRAM: {entry}"
                            ),
                            description=(
                                f"Udev rule '{entry}' contains "
                                f"{'RUN+' if has_run else 'PROGRAM='} directive."
                                f"File: {fp}. "
                                f"Suspicious patterns found: {suspicious}"
                            ),
                            rationale=(
                                "Udev rules can trigger script execution when devices "
                                "are plugged in. Attackers use udev rules to execute "
                                "malicious code when a USB device is connected, "
                                "creating hardware-triggered persistence that bypasses "
                                "normal security controls. Udev rules with RUN+= "
                                "execute arbitrary commands as root."
                            ),
                            remediation=(
                                f"Review: 'cat {fp}'\n"
                                f"Remove if unauthorized: 'rm {fp}'\n"
                                f"Reload udev rules: 'udevadm control --reload-rules'"
                            ),
                            evidence=FileEvidence(
                                path=fp,
                                content=content[:500],
                                owner="",
                                group="",
                            ),
                            detected_value=entry,
                            expected_value="No udev rules with RUN+/PROGRAM= directives",
                            affected_component=entry,
                            confidence=Confidence.HIGH if suspicious else Confidence.LOW,
                            false_positive_probability=0.2 if suspicious else 0.5,
                            mitre_attack_ids=["T1546.011"],
                            tags=["persistence", "udev", "device-trigger"],
                        )
                    )

        return findings
