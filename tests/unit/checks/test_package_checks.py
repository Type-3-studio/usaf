from __future__ import annotations

from usaf.checks.packages.unnecessary_packages import UnnecessaryPackagesCheck
from usaf.models.severity import Severity


class TestUnnecessaryPackagesCheck:
    def test_passes_when_no_risky_packages(self):
        check = UnnecessaryPackagesCheck()
        result = check.evaluate({
            "apt": {
                "packages": [
                    {"name": "openssh-server", "version": "1.0", "status": "installed"},
                    {"name": "ufw", "version": "1.0", "status": "installed"},
                ]
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_no_packages(self):
        check = UnnecessaryPackagesCheck()
        result = check.evaluate({"apt": {"packages": []}})
        assert result.passed

    def test_fails_when_risky_package_installed(self):
        check = UnnecessaryPackagesCheck()
        result = check.evaluate({
            "apt": {
                "packages": [
                    {"name": "telnetd", "version": "0.17", "status": "installed"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "telnetd" in f.title
        assert f.severity == Severity.MEDIUM

    def test_fails_with_multiple_risky_packages(self):
        check = UnnecessaryPackagesCheck()
        result = check.evaluate({
            "apt": {
                "packages": [
                    {"name": "telnetd", "version": "1.0", "status": "installed"},
                    {"name": "snmpd", "version": "2.0", "status": "installed"},
                    {"name": "cups", "version": "3.0", "status": "installed"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 3

    def test_skips_unknown_packages(self):
        check = UnnecessaryPackagesCheck()
        result = check.evaluate({
            "apt": {
                "packages": [
                    {"name": "telnetd", "version": "1.0", "status": "installed"},
                    {"name": "not-in-risky-list", "version": "1.0", "status": "installed"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_and_cis_mapping(self):
        check = UnnecessaryPackagesCheck()
        result = check.evaluate({
            "apt": {
                "packages": [
                    {"name": "telnetd", "version": "1.0", "status": "installed"},
                ]
            }
        })
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert len(f.cis_benchmarks) > 0
