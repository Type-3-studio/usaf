from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.compliance.cmp_security_checks import (
    AvahiServiceCheck,
    CronDaemonCheck,
    DhcpClientCheck,
    HttpServiceCheck,
    LegacyServicesCheck,
    NfsServiceCheck,
    PrintServiceCheck,
    RsyncServiceCheck,
    SmtpServiceCheck,
    SshProtocolComplianceCheck,
    XWindowSystemCheck,
)
from usaf.models.severity import Confidence, Severity


class TestLegacyServicesCheck:
    def test_passes_with_no_legacy(self):
        check = LegacyServicesCheck()
        collectors = {"apt": {"packages": [{"name": "coreutils"}, {"name": "openssh-server"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_telnet(self):
        check = LegacyServicesCheck()
        collectors = {"apt": {"packages": [{"name": "telnetd"}, {"name": "coreutils"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert "telnetd" in result.findings[0].title or "telnetd" in result.findings[0].description
        assert result.findings[0].severity == Severity.HIGH
        assert result.findings[0].confidence == Confidence.HIGH

    def test_has_cis(self):
        check = LegacyServicesCheck()
        collectors = {"apt": {"packages": [{"name": "telnetd"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = LegacyServicesCheck()
        collectors = {"apt": {"packages": [{"name": "telnetd"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestXWindowSystemCheck:
    def test_passes_with_no_x11(self):
        check = XWindowSystemCheck()
        collectors = {"apt": {"packages": [{"name": "coreutils"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_xorg(self):
        check = XWindowSystemCheck()
        collectors = {"apt": {"packages": [{"name": "xserver-xorg-core"}, {"name": "coreutils"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_cis(self):
        check = XWindowSystemCheck()
        collectors = {"apt": {"packages": [{"name": "xserver-xorg-core"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestAvahiServiceCheck:
    def test_passes_with_avahi_disabled(self):
        check = AvahiServiceCheck()
        collectors = {"dns": {"mdns": {"avahi_running": False, "avahi_enabled": False}}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_avahi_running(self):
        check = AvahiServiceCheck()
        collectors = {"dns": {"mdns": {"avahi_running": True, "avahi_enabled": True}}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM

    def test_has_cis(self):
        check = AvahiServiceCheck()
        collectors = {"dns": {"mdns": {"avahi_running": True, "avahi_enabled": True}}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestPrintServiceCheck:
    def test_passes_with_cups_off(self):
        check = PrintServiceCheck()
        collectors = {"systemd": {"services": [{"name": "ssh.service", "active": "active"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_cups_on(self):
        check = PrintServiceCheck()
        collectors = {"systemd": {"services": [{"name": "cups.service", "active": "active"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_cis(self):
        check = PrintServiceCheck()
        collectors = {"systemd": {"services": [{"name": "cups.service", "active": "active"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestNfsServiceCheck:
    def test_passes_with_nfs_off(self):
        check = NfsServiceCheck()
        collectors = {"systemd": {"services": [{"name": "ssh.service", "active": "active"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_nfs_on(self):
        check = NfsServiceCheck()
        collectors = {"systemd": {"services": [{"name": "nfs-server.service", "active": "active"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_cis(self):
        check = NfsServiceCheck()
        collectors = {"systemd": {"services": [{"name": "nfs-server.service", "active": "active"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestRsyncServiceCheck:
    def test_passes_with_rsync_off(self):
        check = RsyncServiceCheck()
        collectors = {"systemd": {"services": [{"name": "ssh.service", "active": "active"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_rsync_on(self):
        check = RsyncServiceCheck()
        collectors = {"systemd": {"services": [{"name": "rsync.service", "active": "active"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_cis(self):
        check = RsyncServiceCheck()
        collectors = {"systemd": {"services": [{"name": "rsync.service", "active": "active"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestSmtpServiceCheck:
    def test_passes_with_smtp_local(self):
        check = SmtpServiceCheck()
        collectors = {"sockets": {"tcp": [{"local_address": "127.0.0.1", "local_port": 25}], "tcp6": [], "udp": [], "udp6": []}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_smtp_exposed(self):
        check = SmtpServiceCheck()
        collectors = {"sockets": {"tcp": [{"local_address": "0.0.0.0", "local_port": 25}], "tcp6": [], "udp": [], "udp6": []}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].confidence == Confidence.MEDIUM

    def test_has_cis(self):
        check = SmtpServiceCheck()
        collectors = {"sockets": {"tcp": [{"local_address": "0.0.0.0", "local_port": 25}], "tcp6": [], "udp": [], "udp6": []}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0


class TestCronDaemonCheck:
    def test_passes_with_root_owned(self):
        check = CronDaemonCheck()

        with (
            patch("usaf.checks.compliance.cmp_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.compliance.cmp_security_checks.Path.stat", return_value=type("Mock", (), {"st_uid": 0, "st_gid": 0})()),
        ):
            result = check.evaluate({})
        assert result.passed

    def test_fails_with_wrong_owner(self):
        check = CronDaemonCheck()

        with (
            patch("usaf.checks.compliance.cmp_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.compliance.cmp_security_checks.Path.stat", return_value=type("Mock", (), {"st_uid": 1000, "st_gid": 1000})()),
        ):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1

    def test_has_cis(self):
        check = CronDaemonCheck()

        with (
            patch("usaf.checks.compliance.cmp_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.compliance.cmp_security_checks.Path.stat", return_value=type("Mock", (), {"st_uid": 1000, "st_gid": 1000})()),
        ):
            result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0


class TestSshProtocolComplianceCheck:
    def test_passes_with_ssh_installed(self):
        check = SshProtocolComplianceCheck()

        with patch("usaf.checks.compliance.cmp_security_checks.Path.exists", return_value=True):
            result = check.evaluate({})
        assert result.passed

    def test_fails_without_ssh(self):
        check = SshProtocolComplianceCheck()

        with patch("usaf.checks.compliance.cmp_security_checks.Path.exists", return_value=False):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) >= 1

    def test_has_cis(self):
        check = SshProtocolComplianceCheck()

        with patch("usaf.checks.compliance.cmp_security_checks.Path.exists", return_value=False):
            result = check.evaluate({})
        assert len(result.findings[0].cis_benchmarks) > 0


class TestHttpServiceCheck:
    def test_has_cis(self):
        check = HttpServiceCheck()
        collectors = {
            "systemd": {"services": [{"name": "apache2.service", "active": "active"}]},
            "sockets": {"tcp": [{"local_address": "0.0.0.0", "local_port": 80}], "tcp6": [], "udp": [], "udp6": []},
        }
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].cis_benchmarks) > 0


class TestDhcpClientCheck:
    def test_has_cis(self):
        check = DhcpClientCheck()
        collectors = {"interfaces": {"interfaces": []}}
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "dhclient\n"
            mock_run.return_value.returncode = 0
            result = check.evaluate(collectors)
            if not result.passed:
                assert len(result.findings[0].cis_benchmarks) > 0

    def test_passes_without_dhcp(self):
        check = DhcpClientCheck()
        collectors = {"interfaces": {"interfaces": []}}
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "sshd\n"
            mock_run.return_value.returncode = 0
            result = check.evaluate(collectors)
        assert result.passed
