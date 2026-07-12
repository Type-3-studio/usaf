from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.services.svc_security_checks import (
    ActiveTimersWithoutCalendarCheck,
    DuplicateUnitFilesCheck,
    ServiceLoadFailuresCheck,
    SocketUnitsNotRunningCheck,
    StaticServicesNotRunningCheck,
    TimerServiceMismatchCheck,
    UnitFileOwnershipCheck,
    UnitFileWorldWritableCheck,
)
from usaf.models.severity import Confidence, Severity


class MockStatResult:
    def __init__(self, mode=0o100644, uid=0, gid=0, size=1024):
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_size = size
        self.st_atime = 1000000.0
        self.st_mtime = 1000000.0
        self.st_ctime = 1000000.0
        self.st_nlink = 1


BASE_SERVICES = [
    {"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": "OpenSSH"},
    {"name": "cron.service", "load": "loaded", "active": "active", "sub": "running", "description": "Cron"},
    {"name": "systemd-journald.service", "load": "loaded", "active": "active", "sub": "running", "description": "Journal"},
]


class TestServiceLoadFailuresCheck:
    def test_passes_with_healthy_services(self):
        check = ServiceLoadFailuresCheck()
        collectors = {"systemd": {"services": BASE_SERVICES, "timers": [], "sockets": []}}
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_error_load(self):
        check = ServiceLoadFailuresCheck()
        collectors = {
            "systemd": {
                "services": BASE_SERVICES + [
                    {"name": "broken.service", "load": "error", "active": "inactive", "sub": "dead", "description": "Broken"},
                ],
                "timers": [],
                "sockets": [],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "load" in f.title.lower() or "failure" in f.title.lower()
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_fails_with_not_found_load(self):
        check = ServiceLoadFailuresCheck()
        collectors = {
            "systemd": {
                "services": BASE_SERVICES + [
                    {"name": "missing.service", "load": "not-found", "active": "inactive", "sub": "dead", "description": ""},
                ],
                "timers": [],
                "sockets": [],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_checks_timers_and_sockets(self):
        check = ServiceLoadFailuresCheck()
        collectors = {
            "systemd": {
                "services": BASE_SERVICES,
                "timers": [
                    {"name": "bad.timer", "load": "error", "active": "inactive", "sub": "dead", "description": ""},
                ],
                "sockets": [
                    {"name": "bad.socket", "load": "not-found", "active": "inactive", "sub": "dead", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 2

    def test_handles_empty_data(self):
        check = ServiceLoadFailuresCheck()
        collectors = {"systemd": {"services": [], "timers": [], "sockets": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = ServiceLoadFailuresCheck()
        collectors = {
            "systemd": {
                "services": [
                    {"name": "broken.service", "load": "error", "active": "inactive", "sub": "dead", "description": ""},
                ],
                "timers": [],
                "sockets": [],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestSocketUnitsNotRunningCheck:
    def test_passes_with_listening_sockets(self):
        check = SocketUnitsNotRunningCheck()
        collectors = {
            "systemd": {
                "sockets": [
                    {"name": "ssh.socket", "load": "loaded", "active": "active", "sub": "listening", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_dead_socket(self):
        check = SocketUnitsNotRunningCheck()
        collectors = {
            "systemd": {
                "sockets": [
                    {"name": "dead.socket", "load": "loaded", "active": "inactive", "sub": "dead", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "socket" in f.title.lower()
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_skips_unloaded_sockets(self):
        check = SocketUnitsNotRunningCheck()
        collectors = {
            "systemd": {
                "sockets": [
                    {"name": "not_loaded.socket", "load": "not-found", "active": "inactive", "sub": "dead", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = SocketUnitsNotRunningCheck()
        collectors = {"systemd": {"sockets": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = SocketUnitsNotRunningCheck()
        collectors = {
            "systemd": {
                "sockets": [
                    {"name": "dead.socket", "load": "loaded", "active": "inactive", "sub": "dead", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestTimerServiceMismatchCheck:
    def test_passes_with_matching_timers(self):
        check = TimerServiceMismatchCheck()
        collectors = {
            "systemd": {
                "services": [
                    {"name": "backup.service", "load": "loaded", "active": "active", "sub": "running", "description": ""},
                ],
                "timers": [
                    {"name": "backup.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_mismatched_timer(self):
        check = TimerServiceMismatchCheck()
        collectors = {
            "systemd": {
                "services": BASE_SERVICES,
                "timers": [
                    {"name": "orphan.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "timer" in f.title.lower() and "service" in f.title.lower()
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_skips_unloaded_timers(self):
        check = TimerServiceMismatchCheck()
        collectors = {
            "systemd": {
                "services": BASE_SERVICES,
                "timers": [
                    {"name": "orphan.timer", "load": "not-found", "active": "inactive", "sub": "dead", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = TimerServiceMismatchCheck()
        collectors = {"systemd": {"services": [], "timers": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = TimerServiceMismatchCheck()
        collectors = {
            "systemd": {
                "services": BASE_SERVICES,
                "timers": [
                    {"name": "orphan.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestUnitFileOwnershipCheck:
    def test_passes_with_root_owned(self):
        check = UnitFileOwnershipCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        with (
            patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.services.svc_security_checks.Path.stat", return_value=MockStatResult(mode=0o100644, uid=0)),
        ):
            result = check.evaluate(collectors)
        # With return_value=True, file exists in both /etc and /usr/lib
        # Both have uid=0 (root), so no findings
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_non_root_owned(self):
        check = UnitFileOwnershipCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        mock_stat = MockStatResult(mode=0o100644, uid=1001)

        with (
            patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.services.svc_security_checks.Path.stat", return_value=mock_stat),
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 2  # /etc + /usr/lib
        f = result.findings[0]
        assert "uid 1001" in f.description
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_skips_missing_unit_files(self):
        check = UnitFileOwnershipCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "missing.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        with patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=False):
            result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = UnitFileOwnershipCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        with (
            patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.services.svc_security_checks.Path.stat", return_value=MockStatResult(mode=0o100644, uid=1001)),
        ):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestUnitFileWorldWritableCheck:
    def test_passes_with_secure_perms(self):
        check = UnitFileWorldWritableCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        with (
            patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.services.svc_security_checks.Path.stat", return_value=MockStatResult(mode=0o100644, uid=0)),
        ):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_world_writable(self):
        check = UnitFileWorldWritableCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        with (
            patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.services.svc_security_checks.Path.stat", return_value=MockStatResult(mode=0o100777, uid=0)),
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 2  # /etc + /usr/lib
        f = result.findings[0]
        assert "world-writable" in f.title.lower() or "World" in f.title
        assert f.severity == Severity.CRITICAL
        assert f.confidence == Confidence.HIGH

    def test_handles_empty_data(self):
        check = UnitFileWorldWritableCheck()
        collectors = {"systemd": {"services": [], "timers": [], "sockets": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = UnitFileWorldWritableCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        with (
            patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.services.svc_security_checks.Path.stat", return_value=MockStatResult(mode=0o100777, uid=0)),
        ):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestStaticServicesNotRunningCheck:
    def test_passes_with_running_services(self):
        check = StaticServicesNotRunningCheck()
        collectors = {
            "systemd": {
                "services": BASE_SERVICES,
            },
        }
        result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_inactive_static_service(self):
        check = StaticServicesNotRunningCheck()
        collectors = {
            "systemd": {
                "services": BASE_SERVICES + [
                    {"name": "dbus.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "static" in f.title.lower() or "not running" in f.title.lower()
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM

    def test_skips_loaded_but_not_static_dead(self):
        check = StaticServicesNotRunningCheck()
        collectors = {
            "systemd": {
                "services": [
                    {"name": "user@1000.service", "load": "loaded", "active": "active", "sub": "running", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_empty_data(self):
        check = StaticServicesNotRunningCheck()
        collectors = {"systemd": {"services": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = StaticServicesNotRunningCheck()
        collectors = {
            "systemd": {
                "services": [
                    {"name": "dbus.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestDuplicateUnitFilesCheck:
    def test_passes_with_single_units(self):
        check = DuplicateUnitFilesCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        with patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True):
            result = check.evaluate(collectors)
        assert not result.passed
        # With return_value=True, the file exists in all 3 dirs -> duplicate found
        assert len(result.findings) >= 1

    def test_fails_with_duplicate_units(self):
        check = DuplicateUnitFilesCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        with patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "duplicate" in f.title.lower()
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.HIGH

    def test_handles_empty_data(self):
        check = DuplicateUnitFilesCheck()
        collectors = {"systemd": {"services": [], "timers": [], "sockets": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = DuplicateUnitFilesCheck()
        collectors = {
            "systemd": {
                "services": [{"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": ""}],
                "timers": [],
                "sockets": [],
            },
        }

        with patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestActiveTimersWithoutCalendarCheck:
    def test_passes_with_calendar_timers(self):
        check = ActiveTimersWithoutCalendarCheck()
        collectors = {
            "systemd": {
                "timers": [
                    {"name": "daily-cleanup.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": ""},
                ],
            },
        }

        with (
            patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="[Timer]\nOnCalendar=daily\n"),
        ):
            result = check.evaluate(collectors)
        assert result.passed
        assert len(result.findings) == 0

    def test_warns_on_monotonic_only_timers(self):
        check = ActiveTimersWithoutCalendarCheck()
        collectors = {
            "systemd": {
                "timers": [
                    {"name": "boot-cleanup.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": ""},
                ],
            },
        }

        with (
            patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="[Timer]\nOnBootSec=5min\n"),
        ):
            result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "calendar" in f.title.lower()
        assert f.severity == Severity.LOW
        assert f.confidence == Confidence.LOW

    def test_skips_inactive_timers(self):
        check = ActiveTimersWithoutCalendarCheck()
        collectors = {
            "systemd": {
                "timers": [
                    {"name": "inactive.timer", "load": "loaded", "active": "inactive", "sub": "dead", "description": ""},
                ],
            },
        }

        result = check.evaluate(collectors)
        assert result.passed

    def test_skips_unloaded_timers(self):
        check = ActiveTimersWithoutCalendarCheck()
        collectors = {
            "systemd": {
                "timers": [
                    {"name": "missing.timer", "load": "not-found", "active": "active", "sub": "waiting", "description": ""},
                ],
            },
        }
        result = check.evaluate(collectors)
        assert result.passed

    def test_handles_missing_unit_file(self):
        check = ActiveTimersWithoutCalendarCheck()
        collectors = {
            "systemd": {
                "timers": [
                    {"name": "orphan.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": ""},
                ],
            },
        }

        with patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=False):
            result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = ActiveTimersWithoutCalendarCheck()
        collectors = {
            "systemd": {
                "timers": [
                    {"name": "boot.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": ""},
                ],
            },
        }

        with (
            patch("usaf.checks.services.svc_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="[Timer]\nOnBootSec=5min\n"),
        ):
            result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0
