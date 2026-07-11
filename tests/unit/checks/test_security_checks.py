from __future__ import annotations

from pathlib import Path

from usaf.checks.security.apparmor_status import AppArmorStatusCheck
from usaf.checks.security.firewall_check import FirewallActiveCheck
from usaf.checks.security.usbguard_check import USBGuardCheck
from usaf.models.severity import Severity


class TestFirewallActiveCheck:
    def test_passes_when_ufw_active(self):
        check = FirewallActiveCheck()
        result = check.evaluate({
            "firewall": {
                "ufw": {"active": True, "installed": True, "raw": ""},
                "nftables": {"active": False, "installed": True},
                "iptables": {"active": False, "installed": True},
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_nftables_active(self):
        check = FirewallActiveCheck()
        result = check.evaluate({
            "firewall": {
                "ufw": {"active": False, "installed": False},
                "nftables": {"active": True, "installed": True},
                "iptables": {"active": False, "installed": True},
            }
        })
        assert result.passed

    def test_passes_when_iptables_active(self):
        check = FirewallActiveCheck()
        result = check.evaluate({
            "firewall": {
                "ufw": {"active": False, "installed": False},
                "nftables": {"active": False, "installed": False},
                "iptables": {"active": True, "installed": True},
            }
        })
        assert result.passed

    def test_fails_when_no_firewall_installed(self):
        check = FirewallActiveCheck()
        result = check.evaluate({
            "firewall": {
                "ufw": {"active": False, "installed": False},
                "nftables": {"active": False, "installed": False},
                "iptables": {"active": False, "installed": False},
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "no host-based firewall" in f.title.lower() or "not installed" in f.title.lower()
        assert f.severity == Severity.HIGH

    def test_fails_when_firewall_installed_but_inactive(self):
        check = FirewallActiveCheck()
        result = check.evaluate({
            "firewall": {
                "ufw": {"active": False, "installed": True, "raw": ""},
                "nftables": {"active": False, "installed": False},
                "iptables": {"active": False, "installed": False},
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert "inactive" in result.findings[0].title.lower() or "not active" in result.findings[0].title.lower()

    def test_has_mitre_and_cis_mapping(self):
        check = FirewallActiveCheck()
        result = check.evaluate({
            "firewall": {
                "ufw": {"active": False, "installed": False},
                "nftables": {"active": False, "installed": False},
                "iptables": {"active": False, "installed": False},
            }
        })
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert len(f.cis_benchmarks) > 0


class TestAppArmorStatusCheck:
    def test_passes_when_apparmor_enabled(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "Y")
        check = AppArmorStatusCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_apparmor_not_in_kernel(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = AppArmorStatusCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "not enabled" in f.title.lower() or "not enabled" in f.description.lower()
        assert f.severity == Severity.HIGH

    def test_fails_when_apparmor_not_enforcing(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "N")
        check = AppArmorStatusCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "not enforcing" in f.title.lower()

    def test_has_mitre_and_cis_mapping(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = AppArmorStatusCheck()
        result = check.evaluate({})
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert len(f.cis_benchmarks) > 0


class TestUSBGuardCheck:
    def test_passes_when_usb_storage_blacklisted(self, monkeypatch):
        monkeypatch.setattr(
            Path, "exists",
            lambda p: str(p).endswith("usb-storage-blacklist.conf"),
        )
        monkeypatch.setattr(
            Path, "read_text",
            lambda _: "blacklist usb-storage",
        )
        check = USBGuardCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_usbguard_active(self, monkeypatch):
        def fake_exists(p):
            s = str(p)
            return s.endswith("usbguard-daemon.conf") or s.endswith("rules.conf") or s.endswith("usbguard")

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(
            Path, "read_text",
            lambda _: "ImplicitPolicyTarget=block",
        )
        check = USBGuardCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_no_restriction(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = USBGuardCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "USB" in f.title
        assert f.severity == Severity.MEDIUM

    def test_handles_oserror_reading_blacklist(self, monkeypatch):
        monkeypatch.setattr(
            Path, "exists",
            lambda p: str(p).endswith("usb-storage-blacklist.conf"),
        )
        monkeypatch.setattr(
            Path, "read_text",
            lambda _: (_ for _ in ()).throw(OSError),
        )
        check = USBGuardCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_mapping(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        check = USBGuardCheck()
        result = check.evaluate({})
        assert len(result.findings[0].mitre_attack_ids) > 0
