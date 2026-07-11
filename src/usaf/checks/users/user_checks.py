from __future__ import annotations

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence, UserEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class RootAccountCheck(AuditCheck):
    """Check that only root has UID 0."""

    id = "USR-001"
    name = "Unique UID 0 (Root)"
    category = CheckCategory.USERS
    severity = Severity.CRITICAL
    description = "Checks that only the root user has UID 0"
    depends = ["users"]
    tags = ["users", "authentication", "privilege-escalation"]

    def _run_check(self, collectors: dict) -> list:
        users_data = self._get_data(collectors, "users")
        findings = []

        root_users = [u for u in users_data.get("users", []) if u.get("uid") == 0]
        non_root_accounts = [u for u in root_users if u.get("username") != "root"]

        for account in non_root_accounts:
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Non-root user has UID 0: {account['username']}",
                    description=(
                        f"User '{account['username']}' (UID 0) has root-level privileges "
                        f"but is not the root account"
                    ),
                    rationale=(
                        "Only the root account should have UID 0. Any additional user with UID 0 "
                        "has full root privileges without appearing in standard root audits. This is "
                        "a common persistence technique used by attackers to maintain backdoor access. "
                        "It can also occur accidentally through user management errors."
                    ),
                    remediation=(
                        f"Remove the duplicate UID 0 entry for '{account['username']}': "
                        f"'userdel {account['username']}'. If the account is needed, assign a "
                        f"unique UID > 1000 and use sudo for privilege escalation instead."
                    ),
                    evidence=UserEvidence(
                        username=account["username"],
                        uid=0,
                        gid=account.get("gid", 0),
                        home=account.get("home") or None,
                        shell=account.get("shell") or None,
                    ),
                    detected_value=f"User '{account['username']}' has UID 0",
                    expected_value="Only root should have UID 0",
                    affected_component=f"/etc/passwd user: {account['username']}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1078.002", "T1136"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 6.2.1"],
                    tags=["persistence", "backdoor", "privilege-escalation"],
                )
            )

        return findings


@register_check
class EmptyPasswordCheck(AuditCheck):
    """Check for users with empty passwords."""

    id = "USR-002"
    name = "Empty Password Accounts"
    category = CheckCategory.USERS
    severity = Severity.CRITICAL
    description = "Checks that no user accounts have empty passwords"
    depends = ["users"]
    tags = ["users", "authentication", "passwords"]

    def _run_check(self, collectors: dict) -> list:
        users_data = self._get_data(collectors, "users")
        shadow_data = users_data.get("shadow", [])
        passwd_data = users_data.get("users", [])
        findings = []

        empty_password_users = [
            s for s in shadow_data
            if s.get("password_hash") in ("", None, "NP")
        ]

        passwd_map = {u["username"]: u for u in passwd_data if u.get("username")}

        for account in empty_password_users:
            username = account["username"]
            user_info = passwd_map.get(username, {})

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"User '{username}' has an empty password",
                    description=f"User '{username}' has no password set, allowing login without authentication",
                    rationale=(
                        "Accounts with empty passwords allow anyone to log in without providing "
                        "a password. This is an extremely critical finding as it provides unauthenticated "
                        "access to the system. Attackers scanning for empty password accounts can gain "
                        "immediate access. This affects both local logins and network logins depending "
                        "on PAM configuration."
                    ),
                    remediation=(
                        f"Set a password for '{username}': 'passwd {username}'. "
                        f"If the account is not needed: 'userdel {username}'. "
                        f"Lock the account: 'passwd -l {username}'."
                    ),
                    evidence=RegistryEvidence(
                        key=f"/etc/shadow:{username}",
                        value="<empty>",
                        expected="<password hash or * for locked>",
                        source="/etc/shadow",
                    ),
                    detected_value=f"Empty password hash for '{username}'",
                    expected_value="Non-empty password hash or locked account (*)",
                    affected_component=f"User: {username}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1078", "T1110"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 6.2.2"],
                    tags=["authentication", "critical"],
                )
            )

        return findings


@register_check
class ShadowedPasswordsCheck(AuditCheck):
    """Check that all accounts use shadowed passwords."""

    id = "USR-003"
    name = "Shadowed Passwords"
    category = CheckCategory.USERS
    severity = Severity.HIGH
    description = "Checks that all user passwords are stored in /etc/shadow (not /etc/passwd)"
    depends = ["users"]
    tags = ["users", "authentication", "passwords"]

    def _run_check(self, collectors: dict) -> list:
        users_data = self._get_data(collectors, "users")
        findings = []

        for user in users_data.get("users", []):
            password_field = user.get("password", "x")
            if password_field not in ("x", "*"):
                findings.append(
                    self.finding(
                        finding_id="001",
                        title=f"Password hash in /etc/passwd for user '{user['username']}'",
                        description=(
                            f"User '{user['username']}' has a password hash in /etc/passwd "
                            f"instead of /etc/shadow"
                        ),
                        rationale=(
                            "Password hashes in /etc/passwd are world-readable. Anyone with "
                            "access to the system can read and attempt to crack these hashes. "
                            "Shadow passwords place hashes in /etc/shadow which is readable only "
                            "by root and the shadow group."
                        ),
                        remediation=(
                            f"Run 'pwconv' to migrate passwords to /etc/shadow. "
                            f"Verify with 'pwck' afterwards."
                        ),
                        evidence=RegistryEvidence(
                            key=f"/etc/passwd:{user['username']}",
                            value=password_field[:20] + "..." if len(password_field) > 20 else password_field,
                            expected="x",
                            source="/etc/passwd",
                        ),
                        detected_value="Password hash present in /etc/passwd",
                        expected_value="x (shadowed password reference)",
                        affected_component=f"User: {user['username']}",
                        confidence=Confidence.HIGH,
                        false_positive_probability=0.0,
                        cis_benchmarks=["CIS Ubuntu 20.04: 6.2.3"],
                        tags=["authentication", "passwords"],
                    )
                )

        return findings
