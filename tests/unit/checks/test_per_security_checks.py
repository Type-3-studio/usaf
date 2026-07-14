from __future__ import annotations

from unittest.mock import patch

from usaf.checks.persistence.per_security_checks import (
    DbusActivatedServicesCheck,
    InitramfsHookCheck,
    LdConfigPersistenceCheck,
    ModuleLoadPersistenceCheck,
    PersistenceDirectoryAuditCheck,
    PolkitRulePersistenceCheck,
    ShellInitPersistenceExtCheck,
    SysctlPersistenceCheck,
    SystemdGeneratorCheck,
    TmpfilesDPersistenceCheck,
    UserTimerPersistenceCheck,
    WorldWritablePersistenceCheck,
)
from usaf.models.severity import Severity

BASE_USERS = [
    {"username": "alice", "uid": 1001, "gid": 1001, "home": "/home/alice", "shell": "/bin/bash"},
]


def test_persistence_directory_pass():
    check = PersistenceDirectoryAuditCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_world_writable_pass():
    check = WorldWritablePersistenceCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_systemd_generator_pass():
    check = SystemdGeneratorCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_dbus_pass():
    check = DbusActivatedServicesCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_polkit_pass():
    check = PolkitRulePersistenceCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_tmpfiles_pass():
    check = TmpfilesDPersistenceCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_module_load_pass():
    check = ModuleLoadPersistenceCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_initramfs_pass():
    check = InitramfsHookCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_ldconfig_pass():
    check = LdConfigPersistenceCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.exists", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_sysctl_pass():
    check = SysctlPersistenceCheck()
    with patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False):
        result = check.evaluate({})
    assert result.passed


def test_user_timer_pass():
    check = UserTimerPersistenceCheck()
    with (
        patch("usaf.checks.persistence.per_security_checks.Path.is_dir", return_value=False),
    ):
        result = check.evaluate({"users": {"users": BASE_USERS}})
    assert result.passed


def test_shell_init_wrong_owner():
    check = ShellInitPersistenceExtCheck()
    with (
        patch("usaf.checks.persistence.per_security_checks.Path.is_file", return_value=True),
        patch("usaf.checks.persistence.per_security_checks.Path.stat", return_value=type("Mock", (), {"st_mode": 0o100644, "st_uid": 1002, "st_size": 100})()),
    ):
        result = check.evaluate({"users": {"users": BASE_USERS}})
    assert not result.passed
    assert len(result.findings) >= 1
    assert result.findings[0].severity == Severity.MEDIUM
    assert len(result.findings[0].mitre_attack_ids) > 0


def test_shell_init_correct_owner():
    check = ShellInitPersistenceExtCheck()
    with (
        patch("usaf.checks.persistence.per_security_checks.Path.is_file", return_value=True),
        patch("usaf.checks.persistence.per_security_checks.Path.stat", return_value=type("Mock", (), {"st_mode": 0o100644, "st_uid": 1001, "st_size": 100})()),
    ):
        result = check.evaluate({"users": {"users": BASE_USERS}})
    assert result.passed
