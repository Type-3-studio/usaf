from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.users.usr_security_checks import (
    DuplicateGroupEntryCheck,
    EmptyGroupsCheck,
    HomeDirectoryMismatchCheck,
    HomeSshDirPermissionsCheck,
    InactiveUserAccountsCheck,
    ServiceAccountsWithShellCheck,
    UidGidMismatchCheck,
    UsersInPrivilegedGroupsCheck,
)
from usaf.models.severity import Confidence, Severity


BASE_USERS = [
    {"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"},
    {"username": "daemon", "uid": 1, "gid": 1, "home": "/usr/sbin", "shell": "/usr/sbin/nologin"},
    {"username": "alice", "uid": 1001, "gid": 1001, "home": "/home/alice", "shell": "/bin/bash"},
    {"username": "bob", "uid": 1002, "gid": 1002, "home": "/home/bob", "shell": "/bin/bash"},
]

BASE_SHADOW = [
    {"username": "root", "last_changed": 20650, "locked": None},
    {"username": "alice", "last_changed": 20651, "locked": None},
    {"username": "bob", "last_changed": 20652, "locked": None},
]

BASE_GROUPS = [
    {"name": "root", "gid": 0, "members": ["root"]},
    {"name": "daemon", "gid": 1, "members": ["daemon"]},
    {"name": "sudo", "gid": 27, "members": ["admin_user"]},
    {"name": "alice", "gid": 1001, "members": ["alice"]},
    {"name": "bob", "gid": 1002, "members": ["bob"]},
    {"name": "docker", "gid": 999, "members": ["bob"]},
    {"name": "staff", "gid": 1004, "members": ["bob"]},
]


class TestServiceAccountsWithShellCheck:
    def test_passes_with_service_accounts_locked(self):
        check = ServiceAccountsWithShellCheck()
        collectors = {"users": {"users": BASE_USERS, "shadow": []}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_service_account_with_shell(self):
        check = ServiceAccountsWithShellCheck()
        users = BASE_USERS + [
            {"username": "mysql", "uid": 102, "gid": 102, "home": "/nonexistent", "shell": "/bin/bash"},
        ]
        collectors = {"users": {"users": users, "shadow": []}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "mysql" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_skips_root(self):
        check = ServiceAccountsWithShellCheck()
        collectors = {"users": {"users": BASE_USERS, "shadow": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = ServiceAccountsWithShellCheck()
        collectors = {"users": {"users": [], "shadow": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_cis_benchmark(self):
        check = ServiceAccountsWithShellCheck()
        users = BASE_USERS + [
            {"username": "mysql", "uid": 102, "gid": 102, "home": "/nonexistent", "shell": "/bin/bash"},
        ]
        collectors = {"users": {"users": users, "shadow": []}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = ServiceAccountsWithShellCheck()
        users = BASE_USERS + [
            {"username": "mysql", "uid": 102, "gid": 102, "home": "/nonexistent", "shell": "/bin/bash"},
        ]
        collectors = {"users": {"users": users, "shadow": []}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestUsersInPrivilegedGroupsCheck:
    def test_passes_with_no_excessive_privilege(self):
        check = UsersInPrivilegedGroupsCheck()
        collectors = {"users": {"users": BASE_USERS}, "groups": {"groups": BASE_GROUPS}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_user_in_two_priv_groups(self):
        check = UsersInPrivilegedGroupsCheck()
        groups = BASE_GROUPS + [
            {"name": "lxd", "gid": 1005, "members": ["bob"]},
        ]
        collectors = {"users": {"users": BASE_USERS}, "groups": {"groups": groups}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1
        titles = [f.title for f in result.findings]
        assert any("bob" in t for t in titles) or any("docker" in t for t in titles)
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].confidence == Confidence.MEDIUM

    def test_handles_empty_data(self):
        check = UsersInPrivilegedGroupsCheck()
        collectors = {"users": {"users": []}, "groups": {"groups": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = UsersInPrivilegedGroupsCheck()
        groups = BASE_GROUPS + [
            {"name": "lxd", "gid": 1005, "members": ["bob"]},
        ]
        collectors = {"users": {"users": BASE_USERS}, "groups": {"groups": groups}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestInactiveUserAccountsCheck:
    def test_passes_with_recent_passwords(self):
        check = InactiveUserAccountsCheck()
        collectors = {"users": {"users": BASE_USERS, "shadow": BASE_SHADOW}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_old_password(self):
        check = InactiveUserAccountsCheck()
        shadow = BASE_SHADOW + [
            {"username": "old_user", "last_changed": 19000, "locked": None},
        ]
        collectors = {"users": {"users": BASE_USERS, "shadow": shadow}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "old_user" in f.title or "inactive" in f.title.lower()
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM

    def test_handles_empty_data(self):
        check = InactiveUserAccountsCheck()
        collectors = {"users": {"users": [], "shadow": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = InactiveUserAccountsCheck()
        shadow = BASE_SHADOW + [
            {"username": "old_user", "last_changed": 19000, "locked": None},
        ]
        collectors = {"users": {"users": BASE_USERS, "shadow": shadow}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestHomeDirectoryMismatchCheck:
    def test_passes_with_standard_homes(self):
        check = HomeDirectoryMismatchCheck()
        collectors = {"users": {"users": BASE_USERS}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_non_standard_home(self):
        check = HomeDirectoryMismatchCheck()
        users = BASE_USERS + [
            {"username": "custom", "uid": 1003, "gid": 1003, "home": "/opt/custom", "shell": "/bin/bash"},
        ]
        collectors = {"users": {"users": users}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "/opt/custom" in f.title or "custom" in f.title
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW

    def test_skips_system_accounts(self):
        check = HomeDirectoryMismatchCheck()
        users = BASE_USERS + [
            {"username": "custom_svc", "uid": 101, "gid": 101, "home": "/var/lib/custom", "shell": "/sbin/nologin"},
        ]
        collectors = {"users": {"users": users}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_skips_nonexistent_home(self):
        check = HomeDirectoryMismatchCheck()
        users = BASE_USERS + [
            {"username": "nobody", "uid": 65534, "gid": 65534, "home": "/nonexistent", "shell": "/sbin/nologin"},
        ]
        collectors = {"users": {"users": users}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = HomeDirectoryMismatchCheck()
        collectors = {"users": {"users": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = HomeDirectoryMismatchCheck()
        users = BASE_USERS + [
            {"username": "custom", "uid": 1003, "gid": 1003, "home": "/opt/custom", "shell": "/bin/bash"},
        ]
        collectors = {"users": {"users": users}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestEmptyGroupsCheck:
    def test_passes_with_populated_groups(self):
        check = EmptyGroupsCheck()
        collectors = {"groups": {"groups": BASE_GROUPS}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_empty_group(self):
        check = EmptyGroupsCheck()
        groups = BASE_GROUPS + [
            {"name": "orphans", "gid": 1005, "members": []},
        ]
        collectors = {"groups": {"groups": groups}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "orphans" in f.title or "Empty" in f.title
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW

    def test_skips_system_groups(self):
        check = EmptyGroupsCheck()
        groups = BASE_GROUPS + [
            {"name": "mail", "gid": 8, "members": []},
        ]
        collectors = {"groups": {"groups": groups}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_skips_nogroup(self):
        check = EmptyGroupsCheck()
        groups = BASE_GROUPS + [
            {"name": "nogroup", "gid": 65534, "members": []},
        ]
        collectors = {"groups": {"groups": groups}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = EmptyGroupsCheck()
        collectors = {"groups": {"groups": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = EmptyGroupsCheck()
        groups = BASE_GROUPS + [
            {"name": "orphans", "gid": 1005, "members": []},
        ]
        collectors = {"groups": {"groups": groups}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestDuplicateGroupEntryCheck:
    def test_passes_with_unique_groups(self):
        check = DuplicateGroupEntryCheck()
        collectors = {"groups": {"groups": BASE_GROUPS}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_duplicate_name(self):
        check = DuplicateGroupEntryCheck()
        groups = BASE_GROUPS + [
            {"name": "sudo", "gid": 1006, "members": ["alice"]},
        ]
        collectors = {"groups": {"groups": groups}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1
        names = [f.title for f in result.findings]
        assert any("sudo" in t for t in names)
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].confidence == Confidence.HIGH

    def test_fails_with_duplicate_gid(self):
        check = DuplicateGroupEntryCheck()
        groups = BASE_GROUPS + [
            {"name": "sudo_clone", "gid": 27, "members": []},
        ]
        collectors = {"groups": {"groups": groups}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1
        gid_titles = [f.title for f in result.findings]
        assert any("27" in t for t in gid_titles)

    def test_handles_empty_data(self):
        check = DuplicateGroupEntryCheck()
        collectors = {"groups": {"groups": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = DuplicateGroupEntryCheck()
        groups = BASE_GROUPS + [
            {"name": "sudo", "gid": 1006, "members": []},
        ]
        collectors = {"groups": {"groups": groups}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestUidGidMismatchCheck:
    def test_passes_with_matching_gids(self):
        check = UidGidMismatchCheck()
        collectors = {"users": {"users": BASE_USERS}, "groups": {"groups": BASE_GROUPS}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_missing_gid(self):
        check = UidGidMismatchCheck()
        users = BASE_USERS + [
            {"username": "orphan", "uid": 1100, "gid": 9999, "home": "/home/orphan", "shell": "/bin/bash"},
        ]
        collectors = {"users": {"users": users}, "groups": {"groups": BASE_GROUPS}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "orphan" in f.title or "9999" in f.title
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM

    def test_skips_root(self):
        check = UidGidMismatchCheck()
        users = [
            {"username": "root", "uid": 0, "gid": 9999, "home": "/root", "shell": "/bin/bash"},
        ]
        collectors = {"users": {"users": users}, "groups": {"groups": BASE_GROUPS}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_skips_system_users(self):
        check = UidGidMismatchCheck()
        users = BASE_USERS + [
            {"username": "svc", "uid": 101, "gid": 9999, "home": "/nonexistent", "shell": "/sbin/nologin"},
        ]
        collectors = {"users": {"users": users}, "groups": {"groups": BASE_GROUPS}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = UidGidMismatchCheck()
        collectors = {"users": {"users": []}, "groups": {"groups": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = UidGidMismatchCheck()
        users = BASE_USERS + [
            {"username": "orphan", "uid": 1100, "gid": 9999, "home": "/home/orphan", "shell": "/bin/bash"},
        ]
        collectors = {"users": {"users": users}, "groups": {"groups": BASE_GROUPS}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestHomeSshDirPermissionsCheck:
    def test_passes_with_secure_ssh_dir(self):
        check = HomeSshDirPermissionsCheck()
        collectors = {"users": {"users": BASE_USERS}}

        with (
            patch("usaf.checks.users.usr_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.users.usr_security_checks.Path.stat", return_value=type("Mock", (), {"st_mode": 0o40700, "st_uid": 1001})()),
        ):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_world_readable_ssh(self):
        check = HomeSshDirPermissionsCheck()
        collectors = {"users": {"users": BASE_USERS}}

        with (
            patch("usaf.checks.users.usr_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.users.usr_security_checks.Path.stat", return_value=type("Mock", (), {"st_mode": 0o40755, "st_uid": 1001})()),
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "insecure" in f.title.lower() or "world" in f.description.lower()
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_skips_missing_ssh_dir(self):
        check = HomeSshDirPermissionsCheck()
        collectors = {"users": {"users": BASE_USERS}}

        with patch("usaf.checks.users.usr_security_checks.Path.is_dir", return_value=False):
            result = check.evaluate(collectors)
        assert result.passed

    def test_has_cis_benchmark(self):
        check = HomeSshDirPermissionsCheck()
        collectors = {"users": {"users": BASE_USERS}}

        with (
            patch("usaf.checks.users.usr_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.users.usr_security_checks.Path.stat", return_value=type("Mock", (), {"st_mode": 0o40755, "st_uid": 1001})()),
        ):
            result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = HomeSshDirPermissionsCheck()
        collectors = {"users": {"users": BASE_USERS}}

        with (
            patch("usaf.checks.users.usr_security_checks.Path.is_dir", return_value=True),
            patch("usaf.checks.users.usr_security_checks.Path.stat", return_value=type("Mock", (), {"st_mode": 0o40755, "st_uid": 1001})()),
        ):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0
