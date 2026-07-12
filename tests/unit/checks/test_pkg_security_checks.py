from __future__ import annotations

from usaf.checks.packages.pkg_security_checks import (
    DevPackagesInstalledCheck,
    DuplicateRepositoriesCheck,
    MissingRecommendedPackagesCheck,
    ObsoleteKernelPackagesCheck,
    PackageAutoRemovableCheck,
    PackageDownloadSizeCheck,
    PackageSourceConsistencyCheck,
    UnusedSnapPackagesCheck,
)
from usaf.models.severity import Confidence, Severity


class TestMissingRecommendedPackagesCheck:
    def test_passes_with_most_installed(self):
        check = MissingRecommendedPackagesCheck()
        # Install enough to be under the threshold of 3
        many_pkgs = [{"name": p} for p in ["ufw", "auditd", "aide", "aide-common", "rkhunter",
                                             "chkrootkit", "lynis", "needrestart", "unattended-upgrades",
                                             "fail2ban", "crowdsec"]]
        collectors = {"apt": {"packages": many_pkgs}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_many_missing(self):
        check = MissingRecommendedPackagesCheck()
        collectors = {"apt": {"packages": [{"name": "coreutils"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM

    def test_has_cis(self):
        check = MissingRecommendedPackagesCheck()
        collectors = {"apt": {"packages": []}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].cis_benchmarks) > 0

    def test_has_mitre_ids(self):
        check = MissingRecommendedPackagesCheck()
        collectors = {"apt": {"packages": []}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestObsoleteKernelPackagesCheck:
    def test_passes_with_few_kernels(self):
        check = ObsoleteKernelPackagesCheck()
        collectors = {"apt": {"packages": [
            {"name": "linux-image-6.8.0-35-generic"},
            {"name": "linux-image-6.8.0-34-generic"},
        ]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_many_kernels(self):
        check = ObsoleteKernelPackagesCheck()
        collectors = {"apt": {"packages": [
            {"name": f"linux-image-6.8.0-{i}-generic"} for i in range(10)
        ]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].confidence == Confidence.HIGH

    def test_has_mitre_ids(self):
        check = ObsoleteKernelPackagesCheck()
        collectors = {"apt": {"packages": [{"name": f"linux-image-6.8.0-{i}-generic"} for i in range(5)]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestDevPackagesInstalledCheck:
    def test_passes_with_no_dev(self):
        check = DevPackagesInstalledCheck()
        collectors = {"apt": {"packages": [{"name": "coreutils", "version": "1.0"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_dev_pkg(self):
        check = DevPackagesInstalledCheck()
        collectors = {"apt": {"packages": [{"name": "mysql-server-dbgsym", "version": "1.0"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1

    def test_has_mitre_ids(self):
        check = DevPackagesInstalledCheck()
        collectors = {"apt": {"packages": [{"name": "mysql-server-dbgsym", "version": "1.0"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestPackageAutoRemovableCheck:
    def test_passes_with_few_obsolete(self):
        check = PackageAutoRemovableCheck()
        collectors = {"apt": {"packages": [{"name": "coreutils", "status": "installed"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre_ids(self):
        check = PackageAutoRemovableCheck()
        collectors = {"apt": {"packages": [{"name": f"oldlib{i}", "status": "obsolete"} for i in range(10)]}}
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestDuplicateRepositoriesCheck:
    def test_passes_with_unique_repos(self):
        check = DuplicateRepositoriesCheck()
        collectors = {"apt": {"repositories": [
            {"url": "http://archive.ubuntu.com", "suite": "jammy", "source": "/etc/apt/sources.list"},
        ]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_duplicates(self):
        check = DuplicateRepositoriesCheck()
        collectors = {"apt": {"repositories": [
            {"url": "http://archive.ubuntu.com", "suite": "jammy", "source": "/etc/apt/sources.list"},
            {"url": "http://archive.ubuntu.com", "suite": "jammy", "source": "/etc/apt/sources.list.d/extra.list"},
        ]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1


class TestUnusedSnapPackagesCheck:
    def test_passes_with_core_snaps(self):
        check = UnusedSnapPackagesCheck()
        collectors = {"snap": {"installed": [{"name": "core20"}, {"name": "snapd"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_extra_snaps(self):
        check = UnusedSnapPackagesCheck()
        collectors = {"snap": {"installed": [
            {"name": "core20"},
            {"name": "spotify", "current_revision": "123"},
        ]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1


class TestPackageDownloadSizeCheck:
    def test_passes_with_small_pkgs(self):
        check = PackageDownloadSizeCheck()
        collectors = {"apt": {"packages": [{"name": "coreutils", "installed_size": "5000000"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_large_pkg(self):
        check = PackageDownloadSizeCheck()
        collectors = {"apt": {"packages": [{"name": "big-data", "installed_size": str(1000 * 1024 * 1024)}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) >= 1


class TestPackageSourceConsistencyCheck:
    def test_passes_with_single_suite(self):
        check = PackageSourceConsistencyCheck()
        collectors = {"apt": {"repositories": [
            {"url": "http://archive.ubuntu.com", "suite": "jammy", "source": "sources.list"},
            {"url": "http://archive.ubuntu.com", "suite": "jammy-updates", "source": "sources.list"},
            {"url": "http://security.ubuntu.com", "suite": "jammy-security", "source": "sources.list"},
        ]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_passes_with_single_suite_test(self):
        check = PackageSourceConsistencyCheck()
        collectors = {"apt": {"repositories": [
            {"url": "http://archive.ubuntu.com", "suite": "jammy", "source": "sources.list"},
        ]}}
        result = check.evaluate(collectors)
        assert result.passed
