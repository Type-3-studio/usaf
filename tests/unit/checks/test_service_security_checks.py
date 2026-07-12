from __future__ import annotations

import os
from unittest.mock import patch

from usaf.checks.services.service_security_checks import (
    MaskedActiveServicesCheck,
    OrphanedTimerUnitsCheck,
    ServiceMissingBinaryCheck,
    ServicesMissingHardeningCheck,
    ServiceWorldWritableBinaryCheck,
    StoppedEnabledServicesCheck,
    SuspiciousServiceNamesCheck,
)


def _sys_data(services=None, timers=None, sockets=None) -> dict:
    return {
        "systemd": {
            "services": services or [],
            "timers": timers or [],
            "sockets": sockets or [],
        }
    }


class TestServicesMissingHardeningCheck:
    def test_passes_when_no_services(self):
        check = ServicesMissingHardeningCheck()
        result = check.evaluate(_sys_data(services=[]))
        assert result.passed

    def test_passes_when_hardened(self, monkeypatch):
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._read_unit_file",
            lambda _: ("/lib/systemd/system/test.service",
                       "[Service]\nNoNewPrivileges=yes\nPrivateTmp=yes\n"
                       "PrivateDevices=yes\nProtectSystem=strict\n"),
        )
        check = ServicesMissingHardeningCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "active": "active"},
        ]))
        assert result.passed

    def test_fails_when_missing_hardening(self, monkeypatch):
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._read_unit_file",
            lambda _: ("/lib/systemd/system/test.service",
                       "[Service]\nExecStart=/usr/bin/test\n"),
        )
        check = ServicesMissingHardeningCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "active": "active"},
        ]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_skips_inactive_services(self, monkeypatch):
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._read_unit_file",
            lambda _: ("/lib/systemd/system/test.service",
                       "[Service]\nExecStart=/usr/bin/test\n"),
        )
        check = ServicesMissingHardeningCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "active": "inactive"},
        ]))
        assert result.passed

    def test_has_mitre_mapping(self, monkeypatch):
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._read_unit_file",
            lambda _: ("/lib/systemd/system/test.service",
                       "[Service]\nExecStart=/usr/bin/test\n"),
        )
        check = ServicesMissingHardeningCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "active": "active"},
        ]))
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestServiceMissingBinaryCheck:
    def test_passes_with_valid_binary(self, monkeypatch):
        monkeypatch.setattr(os.path, "exists", lambda _: True)
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._read_unit_file",
            lambda _: ("/lib/systemd/system/test.service",
                       "[Service]\nExecStart=/usr/bin/valid\n"),
        )
        check = ServiceMissingBinaryCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "active": "active"},
        ]))
        assert result.passed

    def test_fails_when_binary_missing(self, monkeypatch):
        monkeypatch.setattr(os.path, "exists", lambda _: False)
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._read_unit_file",
            lambda _: ("/lib/systemd/system/test.service",
                       "[Service]\nExecStart=/usr/bin/missing\n"),
        )
        check = ServiceMissingBinaryCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "active": "active"},
        ]))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_relative_path(self, monkeypatch):
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._read_unit_file",
            lambda _: ("/lib/systemd/system/test.service",
                       "[Service]\nExecStart=mybinary\n"),
        )
        check = ServiceMissingBinaryCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "active": "active"},
        ]))
        assert not result.passed
        assert len(result.findings) == 1


class TestOrphanedTimerUnitsCheck:
    def test_passes_when_service_exists(self):
        check = OrphanedTimerUnitsCheck()
        result = check.evaluate(_sys_data(
            services=[{"name": "test.service", "active": "active"}],
            timers=[{"name": "test.timer", "active": "active"}],
        ))
        assert result.passed

    def test_passes_when_no_timers(self):
        check = OrphanedTimerUnitsCheck()
        result = check.evaluate(_sys_data(services=[{"name": "test.service", "active": "active"}]))
        assert result.passed


class TestServiceWorldWritableBinaryCheck:
    def test_passes_with_safe_binary(self, monkeypatch):
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._read_unit_file",
            lambda _: ("/lib/systemd/system/test.service",
                       "[Service]\nExecStart=/usr/bin/safe\n"),
        )
        monkeypatch.setattr(os, "stat", lambda _: os.stat_result([0o100755, 0, 0, 0, 0, 0, 100, 0, 0, 0]))
        check = ServiceWorldWritableBinaryCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "active": "active"},
        ]))
        assert result.passed

    def test_fails_with_ww_binary(self, monkeypatch):
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._read_unit_file",
            lambda _: ("/lib/systemd/system/test.service",
                       "[Service]\nExecStart=/usr/bin/ww\n"),
        )
        monkeypatch.setattr(os, "stat", lambda _: os.stat_result([0o100777, 0, 0, 0, 0, 0, 100, 0, 0, 0]))
        check = ServiceWorldWritableBinaryCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "active": "active"},
        ]))
        assert not result.passed
        assert len(result.findings) == 1


class TestSuspiciousServiceNamesCheck:
    def test_passes_with_legitimate_descriptions(self):
        check = SuspiciousServiceNamesCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "ssh.service", "load": "loaded", "description": "OpenSSH daemon"},
            {"name": "cron.service", "load": "loaded", "description": "Regular background program"},
        ]))
        assert result.passed

    def test_fails_with_suspicious_description(self):
        check = SuspiciousServiceNamesCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "evil.service", "load": "loaded", "description": "cryptominer service"},
        ]))
        assert not result.passed
        assert len(result.findings) >= 1


class TestStoppedEnabledServicesCheck:
    def test_passes_when_running(self):
        check = StoppedEnabledServicesCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running"},
        ]))
        assert result.passed

    def test_fails_when_dead(self):
        check = StoppedEnabledServicesCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "load": "loaded", "active": "inactive", "sub": "dead"},
        ]))
        assert not result.passed
        assert len(result.findings) == 1


class TestMaskedActiveServicesCheck:
    def test_passes_when_not_masked(self):
        check = MaskedActiveServicesCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "ssh.service", "load": "loaded", "active": "active"},
        ]))
        assert result.passed

    def test_passes_when_masked_without_unit_file(self, monkeypatch):
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._find_unit_file_path",
            lambda _: None,
        )
        check = MaskedActiveServicesCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "load": "masked", "active": "inactive"},
        ]))
        assert result.passed

    def test_fails_when_masked_with_unit_file(self, monkeypatch):
        monkeypatch.setattr(
            "usaf.checks.services.service_security_checks._find_unit_file_path",
            lambda _: "/etc/systemd/system/test.service",
        )
        check = MaskedActiveServicesCheck()
        result = check.evaluate(_sys_data(services=[
            {"name": "test.service", "load": "masked", "active": "inactive"},
        ]))
        assert not result.passed
        assert len(result.findings) == 1
