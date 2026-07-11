from __future__ import annotations

from usaf.checks.users.user_checks import (
    EmptyPasswordCheck,
    RootAccountCheck,
    ShadowedPasswordsCheck,
)
from usaf.models.severity import Severity


class TestRootAccountCheck:
    def test_passes_when_only_root_uid_0(self):
        check = RootAccountCheck()
        result = check.evaluate(
            {
                "users": {
                    "users": [
                        {"username": "root", "uid": 0, "gid": 0},
                        {"username": "alice", "uid": 1000, "gid": 1000},
                    ]
                }
            }
        )
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_extra_uid_0_user(self):
        check = RootAccountCheck()
        result = check.evaluate(
            {
                "users": {
                    "users": [
                        {"username": "root", "uid": 0, "gid": 0},
                        {
                            "username": "backdoor",
                            "uid": 0,
                            "gid": 0,
                            "home": "/root",
                            "shell": "/bin/bash",
                        },
                    ]
                }
            }
        )
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "backdoor" in (f.detected_value or "")
        assert f.severity == Severity.CRITICAL

    def test_fails_with_multiple_extra(self):
        check = RootAccountCheck()
        result = check.evaluate(
            {
                "users": {
                    "users": [
                        {"username": "root", "uid": 0, "gid": 0},
                        {"username": "backdoor1", "uid": 0, "gid": 0},
                        {"username": "backdoor2", "uid": 0, "gid": 0},
                    ]
                }
            }
        )
        assert not result.passed
        assert len(result.findings) == 2


class TestEmptyPasswordCheck:
    def test_passes_when_all_have_passwords(self):
        check = EmptyPasswordCheck()
        result = check.evaluate(
            {
                "users": {
                    "shadow": [
                        {"username": "root", "password_hash": "$6$hash"},
                        {"username": "alice", "password_hash": "$6$hash2"},
                    ],
                    "users": [
                        {"username": "root"},
                        {"username": "alice"},
                    ],
                }
            }
        )
        assert result.passed
        assert len(result.findings) == 0

    def test_finds_empty_passwords(self):
        check = EmptyPasswordCheck()
        result = check.evaluate(
            {
                "users": {
                    "shadow": [
                        {"username": "root", "password_hash": "$6$hash"},
                        {"username": "baduser", "password_hash": ""},
                    ],
                    "users": [
                        {"username": "root"},
                        {"username": "baduser"},
                    ],
                }
            }
        )
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL

    def test_finds_none_password(self):
        check = EmptyPasswordCheck()
        result = check.evaluate(
            {
                "users": {
                    "shadow": [
                        {"username": "baduser", "password_hash": None},
                    ],
                    "users": [
                        {"username": "baduser"},
                    ],
                }
            }
        )
        assert not result.passed
        assert len(result.findings) == 1


class TestShadowedPasswordsCheck:
    def test_passes_with_shadowed_passwords(self):
        check = ShadowedPasswordsCheck()
        result = check.evaluate(
            {
                "users": {
                    "users": [
                        {"username": "root", "password": "x"},
                        {"username": "alice", "password": "x"},
                    ]
                }
            }
        )
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_hash_in_passwd(self):
        check = ShadowedPasswordsCheck()
        result = check.evaluate(
            {
                "users": {
                    "users": [
                        {"username": "root", "password": "x"},
                        {"username": "bob", "password": "$6$exposedhash123"},
                    ]
                }
            }
        )
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH
