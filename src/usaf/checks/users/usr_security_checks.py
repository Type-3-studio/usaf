from __future__ import annotations

import datetime
import stat
from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import FileEvidence, RegistryEvidence, UserEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity

VALID_LOGIN_SHELLS: set[str] = {
    "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/ksh",
    "/bin/tcsh", "/bin/csh", "/bin/fish",
    "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/zsh", "/usr/bin/dash",
    "/usr/bin/ksh", "/usr/bin/tcsh", "/usr/bin/csh", "/usr/bin/fish",
    "/usr/local/bin/bash", "/usr/local/bin/zsh",
}


@register_check
class ServiceAccountsWithShellCheck(AuditCheck):
    id = "USR-501"
    name = "Service Accounts With Login Shells"
    category = CheckCategory.USERS
    severity = Severity.MEDIUM
    description = "Detects system/service accounts (UID < 1000) with valid login shells"
    depends = ["users"]
    tags = ["users", "service-accounts", "hardening"]

    KNOWN_EXCEPTIONS: set[str] = {
        "root",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")

        for entry in users_data.get("users", []):
            username = entry.get("username", "")
            uid = entry.get("uid", 0)
            shell = entry.get("shell", "")

            if uid >= 1000:
                continue
            if username in self.KNOWN_EXCEPTIONS:
                continue
            if shell in ("/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false"):
                continue
            if not shell:
                continue
            if shell not in VALID_LOGIN_SHELLS:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Service account '{username}' has login shell",
                    description=(
                        f"System account '{username}' (UID {uid}) has a valid "
                        f"login shell '{shell}'. Service accounts should use "
                        f"/sbin/nologin or /bin/false."
                    ),
                    rationale=(
                        "Service accounts with login shells allow interactive logins. "
                        "Compromised service accounts with shell access can be used for "
                        "lateral movement and privilege escalation. Service accounts should "
                        "only have the minimum access required for their function."
                    ),
                    remediation=(
                        f"Change shell: 'usermod -s /sbin/nologin {username}'. "
                        f"Verify the service still functions correctly after the change."
                    ),
                    evidence=UserEvidence(
                        username=username,
                        uid=uid,
                        gid=entry.get("gid", 0),
                        shell=shell,
                    ),
                    detected_value=f"Shell: {shell}",
                    expected_value="/sbin/nologin or /bin/false",
                    affected_component=f"User: {username}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1078.002"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 6.2.10"],
                    tags=["users", "service-accounts", "hardening"],
                )
            )
        return findings


@register_check
class UsersInPrivilegedGroupsCheck(AuditCheck):
    id = "USR-502"
    name = "Users in Privileged Groups"
    category = CheckCategory.USERS
    severity = Severity.HIGH
    description = "Detects users who are members of multiple privileged groups"
    depends = ["users", "groups"]
    tags = ["users", "groups", "privilege", "hardening"]

    PRIVILEGED_GROUPS: set[str] = {
        "sudo", "admin", "wheel", "root",
        "docker", "lxd", "libvirt", "kvm",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")
        groups_data = self._get_data(collectors, "groups")

        username_set: set[str] = {u.get("username", "") for u in users_data.get("users", [])}

        user_priv_groups: dict[str, list[str]] = {}
        for group_entry in groups_data.get("groups", []):
            group_name = group_entry.get("name", "")
            if group_name not in self.PRIVILEGED_GROUPS:
                continue
            for member in group_entry.get("members", []):
                if member not in username_set:
                    continue
                if member not in user_priv_groups:
                    user_priv_groups[member] = []
                user_priv_groups[member].append(group_name)

        for username, priv_groups in sorted(user_priv_groups.items()):
            if len(priv_groups) < 2:
                continue

            uid = 0
            for u in users_data.get("users", []):
                if u.get("username") == username:
                    uid = u.get("uid", 0)
                    break

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"User '{username}' in multiple privileged groups",
                    description=(
                        f"User '{username}' is a member of {len(priv_groups)} "
                        f"privileged groups: {', '.join(sorted(priv_groups))}."
                    ),
                    rationale=(
                        "Users who are members of multiple privileged groups (e.g., "
                        "sudo + docker, or sudo + lxd) have excessive privileges. Each "
                        "group provides a distinct privilege escalation path. Compromise "
                        "of this user grants broad system access."
                    ),
                    remediation=(
                        f"Review group memberships: 'groups {username}'. "
                        f"Remove from unnecessary privileged groups: "
                        f"'gpasswd -d {username} <group>'."
                    ),
                    evidence=UserEvidence(
                        username=username,
                        uid=uid,
                        gid=uid,
                        groups=sorted(priv_groups),
                    ),
                    detected_value=f"Privileged groups: {', '.join(sorted(priv_groups))}",
                    expected_value="User should not be in multiple privileged groups",
                    affected_component=f"User: {username}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1078.002"],
                    tags=["users", "groups", "privilege", "hardening"],
                )
            )
        return findings


@register_check
class InactiveUserAccountsCheck(AuditCheck):
    id = "USR-503"
    name = "Inactive User Accounts"
    category = CheckCategory.USERS
    severity = Severity.MEDIUM
    description = "Detects user accounts with passwords that haven't been changed in a long time"
    depends = ["users"]
    tags = ["users", "inactive", "hardening"]

    MAX_INACTIVE_DAYS = 180

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")

        now = datetime.datetime.now()

        for shadow_entry in users_data.get("shadow", []):
            username = shadow_entry.get("username", "")
            last_changed = shadow_entry.get("last_changed")

            if last_changed is None:
                continue

            try:
                last_change_date = datetime.datetime.fromtimestamp(last_changed * 86400)
            except (OSError, ValueError, OverflowError):
                continue

            days_since_change = (now - last_change_date).days
            if days_since_change <= self.MAX_INACTIVE_DAYS:
                continue

            uid = 0
            for u in users_data.get("users", []):
                if u.get("username") == username:
                    uid = u.get("uid", 0)
                    break

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Inactive account: '{username}'",
                    description=(
                        f"Account '{username}' password was last changed "
                        f"{days_since_change} days ago ({last_change_date.date()}). "
                        f"Accounts inactive for over {self.MAX_INACTIVE_DAYS} days "
                        f"should be reviewed."
                    ),
                    rationale=(
                        "Accounts with long-inactive passwords may belong to former "
                        "employees, unused service accounts, or dormant backdoors. "
                        "Stale accounts increase the attack surface and are a common "
                        "initial access vector for attackers."
                    ),
                    remediation=(
                        f"Review account '{username}'. If unused: "
                        f"'userdel {username}'. If still needed: "
                        f"'chage -d 0 {username}' to force password change."
                    ),
                    evidence=UserEvidence(
                        username=username,
                        uid=uid,
                        gid=uid,
                        password_expires=last_change_date,
                    ),
                    detected_value=f"Last password change: {days_since_change} days ago",
                    expected_value=f"Password changed within {self.MAX_INACTIVE_DAYS} days",
                    affected_component=f"User: {username}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1078.002"],
                    tags=["users", "inactive", "hardening"],
                )
            )
        return findings


@register_check
class HomeDirectoryMismatchCheck(AuditCheck):
    id = "USR-504"
    name = "Non-Standard Home Directories"
    category = CheckCategory.USERS
    severity = Severity.LOW
    description = "Detects user accounts with home directories outside the standard /home location"
    depends = ["users"]
    tags = ["users", "home", "audit"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")

        for entry in users_data.get("users", []):
            username = entry.get("username", "")
            uid = entry.get("uid", 0)
            home = entry.get("home", "")

            if not home or home == "/nonexistent":
                continue
            if uid < 1000:
                continue
            if home.startswith("/home/"):
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Non-standard home directory: {home}",
                    description=(
                        f"User '{username}' (UID {uid}) has home directory '{home}' "
                        f"outside /home. This may complicate backup, quota, and "
                        f"security policy enforcement."
                    ),
                    rationale=(
                        "Home directories outside /home may be overlooked during "
                        "backups, audits, and permission reviews. They may also "
                        "indicate manually created accounts, chroot environments, "
                        "or unusual system configurations that warrant review."
                    ),
                    remediation=(
                        f"Review account: 'getent passwd {username}'. "
                        f"If appropriate, move home: "
                        f"'usermod -d /home/{username} -m {username}'."
                    ),
                    evidence=UserEvidence(
                        username=username,
                        uid=uid,
                        gid=entry.get("gid", 0),
                        home=home,
                    ),
                    detected_value=f"Home: {home}",
                    expected_value=f"/home/{username}",
                    affected_component=f"User: {username}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1078.002"],
                    tags=["users", "home", "audit"],
                )
            )
        return findings


@register_check
class EmptyGroupsCheck(AuditCheck):
    id = "USR-505"
    name = "Empty Groups"
    category = CheckCategory.USERS
    severity = Severity.LOW
    description = "Detects group entries with no members"
    depends = ["groups"]
    tags = ["users", "groups", "housekeeping"]

    SKIP_GROUPS: set[str] = {
        "nogroup", "nobody",
    }

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        groups_data = self._get_data(collectors, "groups")

        for group_entry in groups_data.get("groups", []):
            name = group_entry.get("name", "")
            gid = group_entry.get("gid", 0)
            members = group_entry.get("members", [])

            if name in self.SKIP_GROUPS:
                continue
            if gid < 1000:
                continue
            if members:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Empty group: '{name}'",
                    description=(
                        f"Group '{name}' (GID {gid}) has no members. This may "
                        f"indicate a leftover group from removed packages or users."
                    ),
                    rationale=(
                        "Groups without members are unnecessary and may indicate "
                        "incomplete package removal or orphaned configuration. "
                        "Cleaning up unused groups reduces the attack surface and "
                        "simplifies system administration."
                    ),
                    remediation=(
                        f"Review group: 'getent group {name}'. "
                        f"Remove if unused: 'groupdel {name}'."
                    ),
                    evidence=RegistryEvidence(
                        key=f"group.{name}.members",
                        value="none",
                        expected="at least one member",
                        source="/etc/group",
                    ),
                    detected_value=f"Group '{name}' (GID {gid}) has no members",
                    expected_value="Groups should have at least one member",
                    affected_component=f"Group: {name}",
                    confidence=Confidence.LOW,
                    false_positive_probability=0.5,
                    mitre_attack_ids=["T1078.002"],
                    tags=["users", "groups", "housekeeping"],
                )
            )
        return findings


@register_check
class DuplicateGroupEntryCheck(AuditCheck):
    id = "USR-506"
    name = "Duplicate Group Entries"
    category = CheckCategory.USERS
    severity = Severity.HIGH
    description = "Detects duplicate group names or GIDs in /etc/group"
    depends = ["groups"]
    tags = ["users", "groups", "integrity"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        groups_data = self._get_data(collectors, "groups")

        name_count: dict[str, int] = {}
        gid_count: dict[int, int] = {}

        for entry in groups_data.get("groups", []):
            name = entry.get("name", "")
            gid = entry.get("gid", 0)

            name_count[name] = name_count.get(name, 0) + 1
            gid_count[gid] = gid_count.get(gid, 0) + 1

        for name, count in sorted(name_count.items()):
            if count <= 1:
                continue
            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Duplicate group name: '{name}'",
                    description=(
                        f"Group name '{name}' appears {count} times in /etc/group. "
                        f"Duplicate group entries can cause unpredictable behavior."
                    ),
                    rationale=(
                        "Duplicate group names create ambiguity — system commands "
                        "may return inconsistent results, and privilege checks may "
                        "fail silently. This could be a configuration error or "
                        "tampering."
                    ),
                    remediation=(
                        f"Review /etc/group for duplicate '{name}' entries. "
                        f"Remove duplicates with 'groupdel' or edit /etc/group directly."
                    ),
                    evidence=RegistryEvidence(
                        key=f"group.name.{name}.count",
                        value=str(count),
                        expected="1",
                        source="/etc/group",
                    ),
                    detected_value=f"Group '{name}' appears {count} times",
                    expected_value="Each group name should appear once",
                    affected_component=f"Group: {name}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1078.002"],
                    tags=["users", "groups", "integrity"],
                )
            )

        for gid, count in sorted(gid_count.items()):
            if count <= 1:
                continue
            findings.append(
                self.finding(
                    finding_id="002",
                    title=f"Duplicate GID {gid}",
                    description=(
                        f"GID {gid} is used by {count} groups in /etc/group. "
                        f"Duplicate GIDs cause ambiguous group ownership."
                    ),
                    rationale=(
                        "Duplicate GIDs mean multiple groups share the same numerical "
                        "identifier. File ownership checks and permission evaluations "
                        "may attribute files to the wrong group."
                    ),
                    remediation=(
                        f"Review /etc/group for duplicate GID {gid}. "
                        f"Assign unique GIDs to each group."
                    ),
                    evidence=RegistryEvidence(
                        key=f"group.gid.{gid}.count",
                        value=str(count),
                        expected="1",
                        source="/etc/group",
                    ),
                    detected_value=f"GID {gid} used by {count} groups",
                    expected_value="Each GID should be unique",
                    affected_component=f"GID: {gid}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1078.002"],
                    tags=["users", "groups", "integrity"],
                )
            )
        return findings


@register_check
class UidGidMismatchCheck(AuditCheck):
    id = "USR-507"
    name = "UID-GID Mismatch"
    category = CheckCategory.USERS
    severity = Severity.MEDIUM
    description = "Detects users whose primary GID does not match any group in /etc/group"
    depends = ["users", "groups"]
    tags = ["users", "groups", "integrity"]

    SKIP_USERS: set[str] = {"root"}

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")
        groups_data = self._get_data(collectors, "groups")

        existing_gids: set[int] = set()
        for entry in groups_data.get("groups", []):
            gid = entry.get("gid", 0)
            existing_gids.add(gid)

        for entry in users_data.get("users", []):
            username = entry.get("username", "")
            uid = entry.get("uid", 0)
            gid = entry.get("gid", 0)

            if username in self.SKIP_USERS:
                continue
            if uid < 1000:
                continue
            if gid in existing_gids:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"User '{username}' has no matching group for GID {gid}",
                    description=(
                        f"User '{username}' (UID {uid}) has primary GID {gid}, "
                        f"but no group with that GID exists in /etc/group."
                    ),
                    rationale=(
                        "A user with a GID that doesn't match any group means the "
                        "'groups' command and id(1) may show inconsistent results. "
                        "This can cause file ownership to display as a numeric GID "
                        "instead of a group name, and may indicate incomplete user "
                        "creation or orphaned configuration."
                    ),
                    remediation=(
                        f"Create missing group: 'groupadd -g {gid} {username}'. "
                        f"Or change user's primary group: 'usermod -g <existing_group> {username}'."
                    ),
                    evidence=UserEvidence(
                        username=username,
                        uid=uid,
                        gid=gid,
                    ),
                    detected_value=f"Primary GID {gid} has no group entry",
                    expected_value="User's primary GID should exist in /etc/group",
                    affected_component=f"User: {username}",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1078.002"],
                    tags=["users", "groups", "integrity"],
                )
            )
        return findings


@register_check
class HomeSshDirPermissionsCheck(AuditCheck):
    id = "USR-508"
    name = "World-Readable SSH Directories"
    category = CheckCategory.USERS
    severity = Severity.HIGH
    description = "Checks that user .ssh directories are not world-readable or world-writable"
    depends = ["users"]
    tags = ["users", "ssh", "permissions", "authentication"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        users_data = self._get_data(collectors, "users")

        for entry in users_data.get("users", []):
            username = entry.get("username", "")
            uid = entry.get("uid", 0)
            home = entry.get("home", "")

            if not home or home == "/nonexistent" or uid < 1000:
                continue

            ssh_dir = Path(home) / ".ssh"
            if not ssh_dir.is_dir():
                continue

            try:
                st = ssh_dir.stat()
            except OSError:
                continue

            mode = stat.S_IMODE(st.st_mode)
            issues: list[str] = []

            if mode & stat.S_IWOTH:
                issues.append("world-writable")
            if mode & stat.S_IROTH:
                issues.append("world-readable")
            if mode & stat.S_IXOTH:
                issues.append("world-executable")

            if not issues:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Insecure .ssh directory: {home}/.ssh",
                    description=(
                        f"SSH directory '{ssh_dir}' for user '{username}' has "
                        f"{' and '.join(issues)} permissions ({oct(mode)[2:]}). "
                        f"SSH requires .ssh to be private to the user."
                    ),
                    rationale=(
                        "SSH strictly requires .ssh directories to have restricted "
                        "permissions (0700). World-accessible .ssh directories cause "
                        "SSH to ignore authorized_keys, effectively disabling "
                        "key-based authentication. They also expose SSH keys and "
                        "configuration to other users."
                    ),
                    remediation=(
                        f"Fix permissions: 'chmod 700 {ssh_dir}'. "
                        f"Fix authorized_keys: 'chmod 600 {ssh_dir}/authorized_keys'. "
                        f"Fix private keys: 'chmod 600 {ssh_dir}/id_*'."
                    ),
                    evidence=FileEvidence(
                        path=str(ssh_dir),
                        permission=oct(mode)[2:],
                        owner=str(st.st_uid),
                        content=f"{' and '.join(issues)}",
                    ),
                    detected_value=f"Permissions {oct(mode)[2:]} on {ssh_dir}",
                    expected_value="Permissions 0700 on .ssh directory",
                    affected_component=str(ssh_dir),
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1222"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 6.2.12"],
                    tags=["users", "ssh", "permissions", "authentication"],
                )
            )
        return findings
