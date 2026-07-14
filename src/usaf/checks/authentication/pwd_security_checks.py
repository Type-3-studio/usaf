from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

COMMON_PASSWORD = Path("/etc/pam.d/common-password")
LOGIN_DEFS = Path("/etc/login.defs")
COMMON_AUTH = Path("/etc/pam.d/common-auth")


def _get_login_defs_value(key: str) -> int | None:
    try:
        for line in LOGIN_DEFS.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            parts = stripped.split()
            if len(parts) >= 2 and parts[0] == key:
                return int(parts[1])
    except (OSError, ValueError, TypeError):
        pass
    return None


def _get_pam_value(key: str, filepath: Path = COMMON_PASSWORD) -> str | None:
    try:
        for line in filepath.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for part in stripped.split():
                if "=" in part and part.split("=", 1)[0].strip() == key:
                    return part.split("=", 1)[1].strip()
                if part.strip() == key:
                    return "yes"
    except OSError:
        pass
    return None


def _get_pam_module(filepath: Path, module_name: str) -> dict[str, str] | None:
    try:
        for line in filepath.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if module_name in stripped:
                params: dict[str, str] = {}
                for part in stripped.split():
                    if "=" in part:
                        k, v = part.split("=", 1)
                        params[k.strip()] = v.strip()
                return params
    except OSError:
        pass
    return None


@register_check
class PasswordReuseCheck(AuditCheck):
    id = "PWD-201"
    name = "Password History / Reuse"
    category = CheckCategory.AUTHENTICATION
    severity = Severity.MEDIUM
    description = "Checks that password history is enforced to prevent password reuse"
    depends = []
    tags = ["passwords", "authentication", "hardening"]

    MIN_REMEMBER = 5

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        remember = _get_pam_value("remember")

        if remember is not None:
            try:
                count = int(remember)
                if count >= self.MIN_REMEMBER:
                    return findings
            except (ValueError, TypeError):
                pass

        if remember is not None:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Password history too short",
                    description=(
                        f"pam_unix remember={remember} in common-password. "
                        f"At least {self.MIN_REMEMBER} previous passwords should be "
                        f"remembered to prevent reuse."
                    ),
                    rationale=(
                        "Without adequate password history, users can cycle through "
                        "a small set of passwords, undermining the password policy. "
                        "Attackers who discover a current password can wait for the "
                        "user to change it and try the same password again."
                    ),
                    remediation=(
                        f"Add 'remember={self.MIN_REMEMBER}' to pam_unix in "
                        f"/etc/pam.d/common-password."
                    ),
                    evidence=RegistryEvidence(
                        key="pam.unix.remember",
                        value=str(remember) if remember else "not set",
                        expected=str(self.MIN_REMEMBER),
                        source="/etc/pam.d/common-password",
                    ),
                    detected_value=f"remember={remember}",
                    expected_value=f"remember>={self.MIN_REMEMBER}",
                    affected_component="PAM password policy",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1110"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.3.3"],
                    tags=["passwords", "authentication", "hardening"],
                )
            )
        else:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Password history not configured",
                    description="pam_unix remember= is not set in common-password. "
                    "No password history is enforced.",
                    rationale=(
                        "Without the remember parameter, pam_unix does not prevent "
                        "password reuse. Users can immediately reuse their current "
                        "password after a change, defeating the purpose of password "
                        "rotation policies."
                    ),
                    remediation=(
                        f"Add 'remember={self.MIN_REMEMBER}' to the pam_unix line in "
                        f"/etc/pam.d/common-password."
                    ),
                    evidence=RegistryEvidence(
                        key="pam.unix.remember",
                        value="not set",
                        expected=str(self.MIN_REMEMBER),
                        source="/etc/pam.d/common-password",
                    ),
                    detected_value="remember not set",
                    expected_value=f"remember>={self.MIN_REMEMBER}",
                    affected_component="PAM password policy",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1110"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.3.3"],
                    tags=["passwords", "authentication", "hardening"],
                )
            )
        return findings


@register_check
class PasswordMinAgeCheck(AuditCheck):
    id = "PWD-202"
    name = "Password Minimum Age"
    category = CheckCategory.AUTHENTICATION
    severity = Severity.MEDIUM
    description = "Checks that PASS_MIN_DAYS is set to prevent rapid password cycling"
    depends = []
    tags = ["passwords", "aging", "hardening"]

    MIN_DAYS = 7

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        min_days = _get_login_defs_value("PASS_MIN_DAYS")

        if min_days is not None and min_days >= self.MIN_DAYS:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Password minimum age too low",
                description=(
                    f"PASS_MIN_DAYS={min_days} in /etc/login.defs. "
                    f"Users can change passwords immediately, bypassing history."
                ),
                rationale=(
                    "Without a minimum password age, users can change their password "
                    "multiple times in quick succession to cycle through old passwords "
                    "and bypass the remember history setting. Minimum age prevents "
                    "this immediate cycling."
                ),
                remediation=(
                    f"Set PASS_MIN_DAYS {self.MIN_DAYS} in /etc/login.defs."
                ),
                evidence=RegistryEvidence(
                    key="login.defs.PASS_MIN_DAYS",
                    value=str(min_days) if min_days is not None else "not set",
                    expected=str(self.MIN_DAYS),
                    source="/etc/login.defs",
                ),
                detected_value=f"PASS_MIN_DAYS={min_days}",
                expected_value=f"PASS_MIN_DAYS>={self.MIN_DAYS}",
                affected_component="Password aging policy",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                mitre_attack_ids=["T1110"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.4.1"],
                tags=["passwords", "aging", "hardening"],
            )
        )
        return findings


@register_check
class PasswordMaxAgeCheck(AuditCheck):
    id = "PWD-203"
    name = "Password Maximum Age"
    category = CheckCategory.AUTHENTICATION
    severity = Severity.HIGH
    description = "Checks that PASS_MAX_DAYS enforces regular password rotation"
    depends = []
    tags = ["passwords", "aging", "hardening"]

    MAX_DAYS = 90

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        max_days = _get_login_defs_value("PASS_MAX_DAYS")

        if max_days is not None and max_days <= self.MAX_DAYS and max_days > 0:
            return findings

        if max_days == 0 or (max_days is not None and max_days > 9999):
            msg = f"{max_days} (effectively never expires — 274+ years)"
        elif max_days is None:
            msg = "not set"
        else:
            msg = str(max_days)

        findings.append(
            self.finding(
                finding_id="001",
                title="Password maximum age is too permissive",
                description=(
                    f"PASS_MAX_DAYS={msg} in /etc/login.defs. "
                    f"Passwords should expire after {self.MAX_DAYS} days."
                ),
                rationale=(
                    "Passwords that never expire or have very long maximum ages remain "
                    "valid indefinitely. If a password hash is stolen, the attacker has "
                    "an unlimited window to crack it. Regular rotation limits the "
                    "window of exposure."
                ),
                remediation=(
                    f"Set PASS_MAX_DAYS {self.MAX_DAYS} in /etc/login.defs."
                ),
                evidence=RegistryEvidence(
                    key="login.defs.PASS_MAX_DAYS",
                    value=msg,
                    expected=str(self.MAX_DAYS),
                    source="/etc/login.defs",
                ),
                detected_value=f"PASS_MAX_DAYS={msg}",
                expected_value=f"PASS_MAX_DAYS<={self.MAX_DAYS}",
                affected_component="Password aging policy",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                mitre_attack_ids=["T1110"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.4.1"],
                tags=["passwords", "aging", "hardening"],
            )
        )
        return findings


@register_check
class PasswordWarnAgeCheck(AuditCheck):
    id = "PWD-204"
    name = "Password Expiry Warning"
    category = CheckCategory.AUTHENTICATION
    severity = Severity.LOW
    description = "Checks that PASS_WARN_AGE provides adequate notice before password expiry"
    depends = []
    tags = ["passwords", "aging", "user-experience"]

    MIN_WARN_DAYS = 7

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        warn_age = _get_login_defs_value("PASS_WARN_AGE")

        if warn_age is not None and warn_age >= self.MIN_WARN_DAYS:
            return findings

        warnings_days = warn_age if warn_age is not None else 0

        findings.append(
            self.finding(
                finding_id="001",
                title="Password expiry warning too short",
                description=(
                    f"PASS_WARN_AGE={warnings_days} in /etc/login.defs. "
                    f"Users should be warned at least {self.MIN_WARN_DAYS} days "
                    f"before password expiry."
                ),
                rationale=(
                    "Insufficient warning before password expiry can lead to users "
                    "being locked out and seeking helpdesk support. Adequate warning "
                    "ensures users have time to change passwords before expiry."
                ),
                remediation=(
                    f"Set PASS_WARN_AGE {self.MIN_WARN_DAYS} in /etc/login.defs."
                ),
                evidence=RegistryEvidence(
                    key="login.defs.PASS_WARN_AGE",
                    value=str(warnings_days),
                    expected=str(self.MIN_WARN_DAYS),
                    source="/etc/login.defs",
                ),
                detected_value=f"PASS_WARN_AGE={warnings_days}",
                expected_value=f"PASS_WARN_AGE>={self.MIN_WARN_DAYS}",
                affected_component="Password aging policy",
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1110"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.4.1"],
                tags=["passwords", "aging", "user-experience"],
            )
        )
        return findings


@register_check
class AccountLockoutCheck(AuditCheck):
    id = "PWD-301"
    name = "Account Lockout Policy"
    category = CheckCategory.AUTHENTICATION
    severity = Severity.HIGH
    description = "Checks that account lockout is configured to prevent brute-force attacks"
    depends = []
    tags = ["passwords", "lockout", "authentication", "hardening"]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        if not COMMON_AUTH.exists():
            return findings

        faillock = _get_pam_module(COMMON_AUTH, "pam_faillock")
        tally2 = _get_pam_module(COMMON_AUTH, "pam_tally2")

        if faillock:
            deny = faillock.get("deny", "")
            unlock_time = faillock.get("unlock_time", "")
            if deny and unlock_time:
                return findings

        if tally2:
            deny = tally2.get("deny", "")
            unlock_time = tally2.get("unlock_time", "")
            if deny and unlock_time:
                return findings

        if faillock or tally2:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Account lockout not fully configured",
                    description=(
                        "Lockout module is present but missing deny or unlock_time."
                    ),
                    rationale=(
                        "Account lockout prevents brute-force password guessing. "
                        "Without both deny (max attempts) and unlock_time (lockout "
                        "duration), the lockout is ineffective."
                    ),
                    remediation="Configure pam_faillock with deny=5 and unlock_time=900 in /etc/pam.d/common-auth.",
                    evidence=RegistryEvidence(
                        key="pam.faillock.deny",
                        value=str(faillock.get("deny", "missing") if faillock else "not present"),
                        expected="5",
                        source="/etc/pam.d/common-auth",
                    ),
                    detected_value="Lockout module present but incomplete",
                    expected_value="deny=5 and unlock_time=900 configured",
                    affected_component="PAM authentication policy",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1110"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.3.2"],
                    tags=["passwords", "lockout", "authentication", "hardening"],
                )
            )
        else:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Account lockout not configured",
                    description=(
                        "No pam_faillock or pam_tally2 module found in common-auth. "
                        "Accounts are not locked after failed login attempts."
                    ),
                    rationale=(
                        "Without account lockout, attackers can perform unlimited "
                        "brute-force password guessing against local accounts. "
                        "Even with strong passwords, unlimited attempts eventually "
                        "succeed. Lockout after 5 failed attempts is the standard."
                    ),
                    remediation=(
                        "Add pam_faillock configuration to /etc/pam.d/common-auth: "
                        "auth required pam_faillock.so preauth silent deny=5 unlock_time=900. "
                        "auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900."
                    ),
                    evidence=RegistryEvidence(
                        key="pam.faillock",
                        value="not configured",
                        expected="pam_faillock with deny and unlock_time",
                        source="/etc/pam.d/common-auth",
                    ),
                    detected_value="No account lockout module",
                    expected_value="pam_faillock configured with deny and unlock_time",
                    affected_component="PAM authentication policy",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1110"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.3.2"],
                    tags=["passwords", "lockout", "authentication", "hardening"],
                )
            )
        return findings


@register_check
class PasswordHashAlgorithmCheck(AuditCheck):
    id = "PWD-302"
    name = "Password Hashing Algorithm"
    category = CheckCategory.AUTHENTICATION
    severity = Severity.HIGH
    description = "Checks that a strong password hashing algorithm is configured"
    depends = []
    tags = ["passwords", "hashing", "authentication", "hardening"]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        sha_modules = ["pam_unix.so", "pam_yescrypt.so"]

        for mod in sha_modules:
            params = _get_pam_module(COMMON_PASSWORD, mod.removesuffix(".so"))
            if params is not None:
                break
        else:
            return findings

        sha_password = _get_pam_value("sha512")
        yescrypt = _get_pam_value("yescrypt")

        if yescrypt or sha_password:
            return findings

        md5 = _get_pam_value("md5")
        bigcrypt = _get_pam_value("bigcrypt")
        gost_yescrypt = _get_pam_value("gost_yescrypt")
        blowfish = _get_pam_value("blowfish")

        current = "unknown"
        if md5:
            current = "md5"
        elif bigcrypt:
            current = "bigcrypt"
        elif blowfish:
            current = "blowfish"
        elif gost_yescrypt:
            current = "gost_yescrypt"

        findings.append(
            self.finding(
                finding_id="001",
                title="Weak password hashing algorithm",
                description=(
                    f"Password hashing algorithm '{current}' is configured in "
                    f"common-password. SHA512 or yescrypt should be used."
                ),
                rationale=(
                    "Weak password hashes (MD5, bigcrypt) can be cracked orders of "
                    "magnitude faster than SHA512 or yescrypt. Even if password hashes "
                    "are leaked, strong algorithms provide more time to respond."
                ),
                remediation=(
                    "Use sha512 or yescrypt in /etc/pam.d/common-password: "
                    "password [success=1 default=ignore] pam_unix.so obscure sha512."
                ),
                evidence=RegistryEvidence(
                    key="pam.unix.password_hash",
                    value=current,
                    expected="sha512 or yescrypt",
                    source="/etc/pam.d/common-password",
                ),
                detected_value=f"Hash: {current}",
                expected_value="SHA512 or yescrypt",
                affected_component="PAM password policy",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                mitre_attack_ids=["T1110"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.3.1"],
                tags=["passwords", "hashing", "authentication", "hardening"],
            )
        )
        return findings


@register_check
class PasswordQualityCheck(AuditCheck):
    id = "PWD-303"
    name = "Password Quality Requirements"
    category = CheckCategory.AUTHENTICATION
    severity = Severity.MEDIUM
    description = "Checks that password quality enforcement (pwquality/cracklib) is configured"
    depends = []
    tags = ["passwords", "quality", "complexity", "hardening"]

    PWQUALITY_CONF = Path("/etc/security/pwquality.conf")

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []

        if not self.PWQUALITY_CONF.exists():
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Password quality not configured",
                    description=(
                        "pwquality.conf is missing. Password complexity requirements "
                        "are not enforced."
                    ),
                    rationale=(
                        "Without password quality enforcement via pwquality or cracklib, "
                        "users can choose weak passwords. This dramatically increases "
                        "the risk of password-based attacks."
                    ),
                    remediation=(
                        "Install libpam-pwquality and configure "
                        "/etc/security/pwquality.conf with minimum requirements."
                    ),
                    evidence=RegistryEvidence(
                        key="pwquality.conf",
                        value="not found",
                        expected="present with minlen, minclass, etc.",
                        source="/etc/security/pwquality.conf",
                    ),
                    detected_value="No pwquality configuration",
                    expected_value="pwquality.conf with quality requirements",
                    affected_component="Password quality policy",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1110"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 5.3.1"],
                    tags=["passwords", "quality", "complexity", "hardening"],
                )
            )
            return findings

        config = self._parse_pwquality()
        issues: list[str] = []

        minlen = config.get("minlen")
        if minlen is not None and minlen < 12:
            issues.append(f"minlen={minlen} (< 12)")

        minclass = config.get("minclass")
        if minclass is not None and minclass < 3:
            issues.append(f"minclass={minclass} (< 3)")

        maxrepeat = config.get("maxrepeat")
        if maxrepeat is not None and maxrepeat > 3:
            issues.append(f"maxrepeat={maxrepeat} (> 3)")

        if not issues:
            return findings

        findings.append(
            self.finding(
                finding_id="002",
                title="Weak password quality configuration",
                description=(
                    f"Issues found: {'; '.join(issues)}. Strengthen pwquality.conf."
                ),
                rationale=(
                    "Weak password quality settings allow users to create passwords "
                    "that are vulnerable to brute-force and dictionary attacks."
                ),
                remediation=(
                    "Set in /etc/security/pwquality.conf: "
                    "minlen=12 minclass=3 maxrepeat=3."
                ),
                evidence=RegistryEvidence(
                    key="pwquality.conf",
                    value="; ".join(issues),
                    expected="minlen>=12, minclass>=3, maxrepeat<=3",
                    source="/etc/security/pwquality.conf",
                ),
                detected_value="; ".join(issues),
                expected_value="Strong password quality settings",
                affected_component="Password quality policy",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.2,
                mitre_attack_ids=["T1110"],
                cis_benchmarks=["CIS Ubuntu 20.04: 5.3.1"],
                tags=["passwords", "quality", "complexity", "hardening"],
            )
        )
        return findings

    def _parse_pwquality(self) -> dict[str, int]:
        config: dict[str, int] = {}
        try:
            for line in self.PWQUALITY_CONF.read_text().splitlines():
                stripped = line.strip()
                if stripped.startswith("#") or "=" not in stripped:
                    continue
                key, val = stripped.split("=", 1)
                k = key.strip()
                with contextlib.suppress(ValueError, TypeError):
                    config[k] = int(val.strip())
        except OSError:
            pass
        return config


@register_check
class DefaultPasswordCheck(AuditCheck):
    id = "PWD-304"
    name = "Default User Passwords"
    category = CheckCategory.AUTHENTICATION
    severity = Severity.CRITICAL
    description = "Detects accounts with weak or default-style password hashes"
    depends = ["users"]
    tags = ["passwords", "defaults", "authentication", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")

        for shadow_entry in users_data.get("shadow", []):
            username = shadow_entry.get("username", "")
            pw_hash = shadow_entry.get("password_hash", "")

            if not pw_hash or pw_hash in ("!", "*", "!!", "!*"):
                continue

            hash_upper = pw_hash.upper()

            default_patterns = [
                ("$1$", "MD5"),
                ("$2A$", "Blowfish"),
                ("$2Y$", "Blowfish"),
            ]

            matched_old = any(hash_upper.startswith(p) for p, _ in default_patterns)

            empty_or_known_default = pw_hash in ("", "NP", "NP:")
            is_blank_password = pw_hash in ("", "!")

            if not matched_old and not empty_or_known_default:
                continue

            if username == "root" and is_blank_password:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Weak password hash type for '{username}'",
                    description=(
                        f"Account '{username}' uses a weak or legacy hash type. "
                        + (f"Hash prefix: {pw_hash[:4]}." if matched_old else
                           "Password hash is in legacy format.")
                    ),
                    rationale=(
                        "Weak password hashes (MD5, Blowfish) can be cracked rapidly. "
                        "Default or blank passwords indicate accounts that were never "
                        "properly configured."
                    ),
                    remediation=(
                        f"Force password change: 'chage -d 0 {username}'. "
                        f"Ensure password uses SHA512 or yescrypt."
                    ),
                    evidence=RegistryEvidence(
                        key=f"shadow.{username}.hash_type",
                        value=pw_hash[:10] if pw_hash else "empty",
                        expected="SHA512 ($6$) or yescrypt",
                        source="/etc/shadow",
                    ),
                    detected_value=f"Weak hash: {pw_hash[:10] if pw_hash else 'empty'}",
                    expected_value="SHA512 or yescrypt hash",
                    affected_component=f"User: {username}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1110"],
                    tags=["passwords", "defaults", "authentication", "hardening"],
                )
            )
        return findings
