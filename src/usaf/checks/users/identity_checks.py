from __future__ import annotations

import datetime
from collections import Counter

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence, UserEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

VALID_SHELLS = frozenset({
    "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash",
    "/bin/fish", "/bin/tcsh", "/bin/ksh",
})

KNOWN_ADMIN_USERS = frozenset({
    "root", "daemon", "bin", "sys", "sync", "games", "man",
    "lp", "mail", "news", "uucp", "proxy", "www-data", "backup",
    "list", "irc", "gnats", "nobody", "systemd-network",
    "systemd-resolve", "systemd-timesync", "messagebus", "syslog",
    "_apt", "tss", "uuidd", "tcpdump", "avahi-autoipd", "usbmux",
    "dnsmasq", "whoopsie", "avahi", "lightdm", "colord",
    "speech-dispatcher", "hplip", "kernoops", "pulse", "rtkit",
    "saned", "nm-openvpn", "fwupd-refresh", "geoclue", "gdm",
    "sshd", "pollinate", "render", "lxd",
})

SUDO_SAFE_PATTERNS = [
    "root",
    "%admin",
    "%sudo",
    "%wheel",
    "#includedir",
    "Defaults",
    "Cmnd_Alias",
    "User_Alias",
    "Runas_Alias",
    "Host_Alias",
]


@register_check
class DuplicateUIDCheck(AuditCheck):
    """Check for duplicate UIDs across user accounts."""

    id = "USR-103"
    name = "Duplicate UIDs"
    category = CheckCategory.USERS
    severity = Severity.HIGH
    description = "Checks that no two user accounts share the same UID"
    depends = ["users"]
    tags = ["users", "authentication", "integrity"]

    def _run_check(self, collectors: dict) -> list:
        users_data = self._get_data(collectors, "users")
        findings = []

        users = users_data.get("users", [])
        uid_counts = Counter(u.get("uid") for u in users if u.get("uid") is not None)
        duplicate_uids = {uid: count for uid, count in uid_counts.items() if count > 1}

        for uid, count in duplicate_uids.items():
            conflicting = [u for u in users if u.get("uid") == uid]
            usernames = [u["username"] for u in conflicting]
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Duplicate UID {uid} shared by {count} users",
                    description=(
                        f"UID {uid} is assigned to {count} users: {', '.join(usernames)}. "
                        "Each UID should uniquely identify one user account."
                    ),
                    rationale=(
                        "Duplicate UIDs cause the kernel to treat multiple usernames as the "
                        "same user for permission checking. Files owned by the UID are accessible "
                        "to all accounts sharing that UID. This breaks audit trails and can "
                        "enable privilege escalation or access to unauthorized resources."
                    ),
                    remediation=(
                        "Assign each user a unique UID. For conflicting non-root users: "
                        "'usermod -u <new_uid> <username> && find / -user <old_uid> -exec chown "
                        "<new_uid> {} +'. Verify changes with 'id <username>'."
                    ),
                    evidence=UserEvidence(
                        username=conflicting[0]["username"],
                        uid=uid,
                        gid=conflicting[0].get("gid", 0),
                        home=conflicting[0].get("home") or None,
                        shell=conflicting[0].get("shell") or None,
                    ),
                    detected_value=f"UID {uid} shared by: {', '.join(usernames)}",
                    expected_value="Each UID assigned to exactly one user",
                    affected_component=f"UID: {uid}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1078.002", "T1136"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 6.2.5"],
                    tags=["integrity", "account"],
                )
            )

        return findings


@register_check
class DisabledAccountsWithShellCheck(AuditCheck):
    """Check for disabled/locked accounts that still have valid login shells."""

    id = "USR-104"
    name = "Disabled Accounts With Valid Shells"
    category = CheckCategory.USERS
    severity = Severity.MEDIUM
    description = "Checks that locked accounts do not have valid login shells"
    depends = ["users"]
    tags = ["users", "authentication", "hardening"]

    def _run_check(self, collectors: dict) -> list:
        users_data = self._get_data(collectors, "users")
        findings = []

        passwd_map = {u["username"]: u for u in users_data.get("users", []) if u.get("username")}

        for shadow_entry in users_data.get("shadow", []):
            username = shadow_entry.get("username", "")
            locked = shadow_entry.get("locked")

            if locked is not True:
                continue

            user_info = passwd_map.get(username, {})
            shell = user_info.get("shell", "")

            if shell in VALID_SHELLS:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Disabled account '{username}' has valid shell: {shell}",
                        description=(
                            f"Account '{username}' is locked (password disabled) but has a valid "
                            f"login shell '{shell}'. This can allow access via SSH keys, "
                            "sudo, or other auth methods."
                        ),
                        rationale=(
                            "A locked password prevents password-based login, but does not prevent "
                            "authentication via SSH keys, Kerberos, or other PAM mechanisms. "
                            "Accounts that should be disabled should have their shell set to "
                            "/sbin/nologin or /usr/sbin/nologin to prevent all interactive access."
                        ),
                        remediation=(
                            f"Lock the account fully: 'usermod -s /sbin/nologin {username}' or "
                            f"'usermod -s /usr/sbin/nologin {username}'. "
                            f"If the account is no longer needed: 'userdel {username}'."
                        ),
                        evidence=UserEvidence(
                            username=username,
                            uid=user_info.get("uid", 0),
                            gid=user_info.get("gid", 0),
                            home=user_info.get("home") or None,
                            shell=shell or None,
                            is_locked=True,
                        ),
                        detected_value=f"Shell: {shell}",
                        expected_value="/sbin/nologin or /bin/false",
                        affected_component=f"User: {username}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.2,
                        mitre_attack_ids=["T1078.002"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 6.2.10"],
                        tags=["disabled-account", "hardening"],
                    )
                )

        return findings


@register_check
class ExpiredPasswordCheck(AuditCheck):
    """Check for users with expired or soon-to-expire passwords."""

    id = "USR-105"
    name = "Expired or Non-Expiring Passwords"
    category = CheckCategory.USERS
    severity = Severity.MEDIUM
    description = "Checks for user accounts with expired passwords or no password expiration"
    depends = ["users"]
    tags = ["users", "authentication", "passwords"]

    def _run_check(self, collectors: dict) -> list:
        users_data = self._get_data(collectors, "users")
        findings = []

        now = datetime.date.today()
        epoch = datetime.date(1970, 1, 1)
        days_since_epoch = (now - epoch).days

        for shadow_entry in users_data.get("shadow", []):
            username = shadow_entry.get("username", "")
            password_hash = shadow_entry.get("password_hash", "")
            last_changed = shadow_entry.get("last_changed")
            max_days = shadow_entry.get("max_days")
            if password_hash in ("!", "!?", "*", "!!"):
                continue

            if max_days is not None and max_days > 0 and last_changed is not None:
                expiry_day = last_changed + max_days
                days_until_expiry = expiry_day - days_since_epoch

                if days_until_expiry < 0:
                    findings.append(
                        self.finding(
                            finding_id="001",
                            title=f"Password expired for user '{username}'",
                            description=(
                                f"Password for '{username}' expired "
                                f"{abs(days_until_expiry)} day(s) ago "
                                f"(last changed: day {last_changed}, max age: {max_days} days)."
                            ),
                            rationale=(
                                "Expired passwords should be proactively reset. Accounts with expired "
                                "passwords may be forced to change on next login, but in some "
                                "configurations they can still authenticate using old methods. "
                                "Monitoring password expiration helps identify neglected accounts."
                            ),
                            remediation=(
                                f"Set a new password: 'passwd {username}'. "
                                f"Check aging info: 'chage -l {username}'. "
                                f"To set a new expiration: 'chage -M 90 {username}'."
                            ),
                            evidence=UserEvidence(
                                username=username,
                                uid=0,
                                gid=0,
                                is_locked=False,
                            ),
                            detected_value=f"Password expired {abs(days_until_expiry)} days ago",
                            expected_value="Password within validity period",
                            affected_component=f"User: {username}",
                            confidence=Confidence.HIGH,
                            false_positive_probability=0.0,
                            mitre_attack_ids=["T1078"],
                            cis_benchmarks=["CIS Ubuntu 20.04: 6.2.6"],
                            tags=["password-expiry", "accounts"],
                        )
                    )
                elif days_until_expiry <= 7:
                    findings.append(
                        self.finding(
                            finding_id="002",
                            title=f"Password expiring soon for user '{username}'",
                            description=(
                        f"Password for '{username}' will expire in "
                        f"{days_until_expiry} day(s) "
                        f"(last changed: day {last_changed}, max age: {max_days} days)."
                            ),
                            rationale=(
                                "Passwords expiring within 7 days should be proactively rotated "
                                "to prevent authentication disruption and ensure security posture."
                            ),
                            remediation=(
                                f"User should change password before expiration: 'passwd {username}'."
                            ),
                            evidence=UserEvidence(
                                username=username,
                                uid=0,
                                gid=0,
                                is_locked=False,
                            ),
                            detected_value=f"Expires in {days_until_expiry} days",
                            expected_value="More than 7 days until expiration",
                            affected_component=f"User: {username}",
                            confidence=Confidence.LOW,
                            false_positive_probability=0.1,
                            mitre_attack_ids=["T1078"],
                            cis_benchmarks=["CIS Ubuntu 20.04: 6.2.6"],
                            tags=["password-expiry", "accounts"],
                        )
                    )

            if max_days is None or max_days in (0, -1):
                if username in KNOWN_ADMIN_USERS:
                    continue
                if password_hash in ("!", "!?", "*", "!!", "", None, "NP"):
                    continue

                findings.append(
                    self.finding(
                        finding_id="003",
                        title=f"Password never expires for user '{username}'",
                        description=(
                            f"Account '{username}' has no password expiration "
                            f"(max_days: {max_days}). "
                            "Passwords that never expire increase risk of credential compromise."
                        ),
                        rationale=(
                            "Without password aging, compromised credentials remain valid indefinitely. "
                            "Attackers who obtain a password through phishing, data breach, or "
                            "credential stuffing maintain access until the password is manually changed. "
                            "Password expiration ensures regular credential rotation."
                        ),
                        remediation=(
                            f"Set max password age: 'chage -M 90 {username}'. "
                            f"Verify: 'chage -l {username}'."
                        ),
                        evidence=RegistryEvidence(
                            key=f"/etc/shadow:{username}",
                            value=f"max_days={max_days}",
                            expected="max_days=90 (or similar finite value)",
                            source="/etc/shadow",
                        ),
                        detected_value=f"max_days={max_days} (password never expires)",
                        expected_value="Finite max_days (typically 90)",
                        affected_component=f"User: {username}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.1,
                        mitre_attack_ids=["T1078"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 6.2.6"],
                        tags=["password-expiry", "aging"],
                    )
                )

        return findings


@register_check
class PasswordReuseCheck(AuditCheck):
    """Check for password reuse restrictions in PAM configuration."""

    id = "USR-202"
    name = "Password Reuse Policy"
    category = CheckCategory.USERS
    severity = Severity.MEDIUM
    description = "Checks that password history is enforced to prevent password reuse"
    depends = ["pam"]
    tags = ["users", "authentication", "passwords"]

    def _run_check(self, collectors: dict) -> list:
        pam_data = self._get_data(collectors, "pam")
        findings = []

        pam_auth_lines = pam_data.get("pam_auth_lines", [])
        remember_found = False
        remember_count = 0

        for line in pam_auth_lines:
            if "remember=" in line:
                remember_found = True
                for part in line.split():
                    if part.startswith("remember="):
                        try:
                            remember_count = int(part.split("=")[1])
                        except (ValueError, IndexError):
                            remember_count = 0

        if not remember_found:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Password history policy not configured",
                    description=(
                        "No password reuse restriction (remember=) found in PAM "
                        "password configuration. Users can reuse previous passwords."
                    ),
                    rationale=(
                        "Without password history enforcement, users can cycle through "
                        "the same passwords, negating the benefit of password expiration. "
                        "Attackers who obtain a current password can predict or wait for "
                        "reuse. NIST SP 800-63 and CIS benchmarks recommend password "
                        "history of at least 5 previous passwords."
                    ),
                    remediation=(
                        "Add to /etc/pam.d/common-password: "
                        "'password requisite pam_pwhistory.so remember=5' "
                        "or add 'remember=5' to the existing pam_unix.so line. "
                        "Then restart: 'systemctl restart sshd' (if applicable)."
                    ),
                    evidence=RegistryEvidence(
                        key="/etc/pam.d/common-password",
                        value="remember= not found",
                        expected="remember=5 (or higher)",
                        source="/etc/pam.d/common-password",
                    ),
                    detected_value="No password reuse restriction",
                    expected_value="remember=5 or higher configured",
                    affected_component="PAM password policy",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    cis_benchmarks=["CIS Ubuntu 20.04: 6.3.1"],
                    tags=["passwords", "reuse", "policy"],
                )
            )
        elif remember_count < 5:
            findings.append(
                self.finding(
                    finding_id="002",
                    title=f"Weak password history (remember={remember_count})",
                    description=(
                        f"Password history is set to {remember_count} previous passwords. "
                        "CIS recommends remembering at least 5 previous passwords."
                    ),
                    rationale=(
                        "A low password history count allows users to cycle through "
                        "passwords quickly and return to a previously used one. "
                        "A history of at least 5 passwords is recommended."
                    ),
                    remediation=(
                        "Update /etc/pam.d/common-password to set "
                        "'remember=5' on the password requisite line."
                    ),
                    evidence=RegistryEvidence(
                        key="/etc/pam.d/common-password",
                        value=f"remember={remember_count}",
                        expected="remember=5",
                        source="/etc/pam.d/common-password",
                    ),
                    detected_value=f"remember={remember_count}",
                    expected_value="remember=5 or higher",
                    affected_component="PAM password policy",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    cis_benchmarks=["CIS Ubuntu 20.04: 6.3.1"],
                    tags=["passwords", "reuse", "policy"],
                )
            )

        return findings


@register_check
class MFAStatusCheck(AuditCheck):
    """Check if multi-factor authentication is configured."""

    id = "USR-301"
    name = "Multi-Factor Authentication Status"
    category = CheckCategory.USERS
    severity = Severity.HIGH
    description = "Checks if MFA is configured via PAM modules (pam_u2f, pam_duo, etc.)"
    depends = ["pam"]
    tags = ["users", "authentication", "mfa"]

    MFA_MODULES = frozenset({
        "pam_u2f.so", "pam_duo.so", "pam_google_authenticator.so",
        "pam_yubico.so", "pam_otpw.so", "pam_oath.so",
        "pam_totp.so", "pam_hotp.so",
    })

    def _run_check(self, collectors: dict) -> list:
        pam_data = self._get_data(collectors, "pam")
        findings = []

        modules = pam_data.get("modules", [])
        installed_mfa_modules = [m for m in modules if m.get("name") in self.MFA_MODULES]
        installed_names = {m["name"] for m in installed_mfa_modules}

        pam_auth_lines = " ".join(pam_data.get("pam_auth_lines", []))
        mfa_in_use = any(name in pam_auth_lines for name in self.MFA_MODULES)

        if not installed_mfa_modules:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="No MFA modules installed",
                    description=(
                        "No multi-factor authentication PAM modules are installed. "
                        "MFA is not available on this system."
                    ),
                    rationale=(
                        "Multi-factor authentication significantly reduces the risk of "
                        "credential compromise. Without MFA, a stolen or guessed password "
                        "is sufficient for full authentication. MFA is particularly critical "
                        "for systems with remote SSH access, administrative accounts, "
                        "and internet-exposed services. See NIST SP 800-63B and CIS benchmarks."
                    ),
                    remediation=(
                        "Install an MFA module. Options include:\n"
                        "1. 'apt install libpam-u2f' (U2F hardware tokens)\n"
                        "2. 'apt install libpam-google-authenticator' (TOTP)\n"
                        "3. Duo Security: install pam_duo from https://duo.com\n"
                        "4. 'apt install libpam-yubico' (YubiKey)\n"
                        "Then configure in /etc/pam.d/common-auth."
                    ),
                    evidence=RegistryEvidence(
                        key="PAM modules",
                        value="No MFA modules installed",
                        expected="At least one MFA module installed and configured",
                        source="/lib/*/security/",
                    ),
                    detected_value="No MFA modules installed",
                    expected_value="MFA module installed and configured",
                    affected_component="PAM authentication",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1078"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 6.3.2"],
                    tags=["mfa", "authentication", "hardening"],
                )
            )
        elif not mfa_in_use:
            names = ", ".join(sorted(installed_names))
            findings.append(
                self.finding(
                    finding_id="002",
                    title=f"MFA modules installed but not enabled: {names}",
                    description=(
                        f"MFA module(s) installed ({names}) but not referenced in "
                        "PAM auth configuration. MFA is not actively enforced."
                    ),
                    rationale=(
                        "Installing an MFA module without configuring it in PAM provides "
                        "no security benefit. The module must be added to the PAM auth stack "
                        "to require second-factor authentication for login."
                    ),
                    remediation=(
                        "Configure MFA by adding the module to /etc/pam.d/common-auth. "
                        "See the module's documentation for exact configuration."
                    ),
                    evidence=RegistryEvidence(
                        key="PAM auth configuration",
                        value=f"Installed: {names}, configured: no",
                        expected="PAM module is referenced in common-auth",
                        source="/etc/pam.d/common-auth",
                    ),
                    detected_value="Installed but not configured",
                    expected_value="MFA enabled in PAM auth config",
                    affected_component="PAM authentication",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1078"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 6.3.2"],
                    tags=["mfa", "authentication"],
                )
            )

        return findings


@register_check
class UnauthorizedSudoMembersCheck(AuditCheck):
    """Check for potentially unauthorized sudo access."""

    id = "USR-401"
    name = "Unauthorized Sudo Members"
    category = CheckCategory.USERS
    severity = Severity.HIGH
    description = "Identifies sudoers entries granting privileges to unexpected users or groups"
    depends = ["sudo"]
    tags = ["users", "privilege", "sudo"]

    def _is_safe_entry(self, content: str) -> bool:
        stripped = content.strip()
        return any(
            stripped.startswith(pattern) for pattern in SUDO_SAFE_PATTERNS
        ) or stripped.startswith("#") or stripped.startswith("Defaults")

    def _run_check(self, collectors: dict) -> list:
        sudo_data = self._get_data(collectors, "sudo")
        findings = []

        entries = sudo_data.get("sudoers_entries", [])

        for entry in entries:
            content = entry.get("content", "")
            if not content:
                continue
            if self._is_safe_entry(content):
                continue

            parts = content.split("=", 1)
            if len(parts) < 2:
                continue

            user_spec = parts[0].strip()
            privilege = parts[1].strip()

            if "(ALL)" in privilege and "NOPASSWD" in privilege:
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Password-less sudo access: {user_spec}",
                        description=(
                            f"Entry in {entry.get('file', 'sudoers')}: '{content}'. "
                            f"User/group '{user_spec}' can run commands as ALL "
                            "without password authentication."
                        ),
                        rationale=(
                            "NOPASSWD sudo entries allow any command to be executed as root "
                            "without re-authentication. If an attacker compromises a user with "
                            "NOPASSWD sudo access, they immediately gain root privileges "
                            "without needing the user's password. This bypasses a key "
                            "security control and audit trail."
                        ),
                        remediation=(
                            f"Review the entry in {entry.get('file', '/etc/sudoers')}. "
                            "Remove NOPASSWD unless explicitly required for automation. "
                            "Use 'visudo' to edit safely. "
                            "If password-less is required, restrict to specific commands."
                        ),
                        evidence=RegistryEvidence(
                            key=entry.get("file", "sudoers"),
                            value=content,
                            expected="Restricted sudo with password requirement",
                            source=entry.get("file", "sudoers"),
                        ),
                        detected_value=f"NOPASSWD ALL for {user_spec}",
                        expected_value="Password required for sudo",
                        affected_component=f"sudo entry: {user_spec}",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1548.003", "T1059"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 5.4"],
                        tags=["sudo", "privilege", "authorization"],
                    )
                )
            elif "(ALL)" in privilege:
                findings.append(
                    self.finding(
                        finding_id="002",
                        title=f"Unrestricted sudo access: {user_spec}",
                        description=(
                            f"Entry in {entry.get('file', 'sudoers')}: '{content}'. "
                            f"User/group '{user_spec}' can run commands as ALL users."
                        ),
                        rationale=(
                            "Sudo access to ALL commands provides full root privileges. "
                            "While this may be appropriate for administrators, each such "
                            "entry should be documented and justified. Unrestricted sudo "
                            "access increases the blast radius of any compromised account."
                        ),
                        remediation=(
                            f"Review the entry in {entry.get('file', '/etc/sudoers')}. "
                            "Restrict to specific commands needed by the user/group. "
                            "Use 'visudo' to edit safely."
                        ),
                        evidence=RegistryEvidence(
                            key=entry.get("file", "sudoers"),
                            value=content,
                            expected="Restricted command set in sudoers",
                            source=entry.get("file", "sudoers"),
                        ),
                        detected_value=f"ALL access for {user_spec}",
                        expected_value="Restricted sudo commands",
                        affected_component=f"sudo entry: {user_spec}",
                        confidence=Confidence.LOW,
                        false_positive_probability=0.5,
                        mitre_attack_ids=["T1548.003"],
                        cis_benchmarks=["CIS Ubuntu 20.04: 5.4"],
                        tags=["sudo", "privilege"],
                    )
                )

        return findings
