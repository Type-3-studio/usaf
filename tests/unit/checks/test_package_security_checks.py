from __future__ import annotations

from unittest.mock import patch

from usaf.checks.packages.package_security_checks import (
    AutoRemovablePackagesCheck,
    HeldPackagesCheck,
    InsecureRepoURLCheck,
    NonStandardReposCheck,
    OutdatedKernelCheck,
    PackageIntegritySummaryCheck,
    SourceReposEnabledCheck,
    ThirdPartyPackageCountCheck,
)
from usaf.models.severity import Severity


class TestInsecureRepoURLCheck:
    def test_passes_with_https(self):
        check = InsecureRepoURLCheck()
        result = check.evaluate({"apt": {"repositories": [{"url": "https://archive.ubuntu.com", "source": "/etc/apt/sources.list"}]}})
        assert result.passed

    def test_fails_with_http(self):
        check = InsecureRepoURLCheck()
        result = check.evaluate({"apt": {"repositories": [{"url": "http://archive.ubuntu.com", "source": "/etc/apt/sources.list"}]}})
        assert not result.passed
        assert len(result.findings) == 1

    def test_passes_when_no_repos(self):
        check = InsecureRepoURLCheck()
        result = check.evaluate({"apt": {"repositories": []}})
        assert result.passed


class TestSourceReposEnabledCheck:
    def test_passes_when_no_source_repos(self):
        check = SourceReposEnabledCheck()
        result = check.evaluate({"apt": {"repositories": [{"type": "deb", "url": "https://archive.ubuntu.com"}]}})
        assert result.passed

    def test_fails_with_source_repos(self):
        check = SourceReposEnabledCheck()
        result = check.evaluate({"apt": {"repositories": [{"type": "deb-src", "url": "https://archive.ubuntu.com"}]}})
        assert not result.passed
        assert len(result.findings) == 1


class TestNonStandardReposCheck:
    def test_passes_with_ubuntu_only(self):
        check = NonStandardReposCheck()
        result = check.evaluate({"apt": {"repositories": [{"url": "http://archive.ubuntu.com", "source": "/etc/apt/sources.list"}]}})
        assert result.passed

    def test_fails_with_third_party(self):
        check = NonStandardReposCheck()
        result = check.evaluate({"apt": {"repositories": [{"url": "https://ppa.launchpad.net/test", "source": "/etc/apt/sources.list.d/test.list"}]}})
        assert not result.passed
        assert len(result.findings) == 1


class TestHeldPackagesCheck:
    def test_passes_when_no_held(self):
        check = HeldPackagesCheck()
        with patch("usaf.checks.packages.package_security_checks.HeldPackagesCheck._get_held_packages", return_value=[]):
            result = check.evaluate({})
        assert result.passed

    def test_fails_with_held(self):
        check = HeldPackagesCheck()
        with patch("usaf.checks.packages.package_security_checks.HeldPackagesCheck._get_held_packages", return_value=["linux-image-generic"]):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1


class TestOutdatedKernelCheck:
    def test_passes_when_kernel_current(self):
        check = OutdatedKernelCheck()
        with patch.object(OutdatedKernelCheck, "_get_running_kernel", return_value="6.8.0-35-generic"):
            result = check.evaluate({"apt": {"packages": [
                {"name": "linux-image-6.8.0-35-generic", "version": "5.4.0-26.30"},
            ]}})
        assert result.passed

    def test_fails_when_kernel_outdated(self):
        check = OutdatedKernelCheck()
        with patch.object(OutdatedKernelCheck, "_get_running_kernel", return_value="6.5.0-15-generic"):
            result = check.evaluate({"apt": {"packages": [
                {"name": "linux-image-6.8.0-35-generic", "version": "6.8.0-35.36"},
            ]}})
        assert not result.passed
        assert len(result.findings) == 1


class TestAutoRemovablePackagesCheck:
    def test_passes_when_none(self):
        check = AutoRemovablePackagesCheck()
        with patch("usaf.checks.packages.package_security_checks.AutoRemovablePackagesCheck._get_auto_removable", return_value=[]):
            result = check.evaluate({})
        assert result.passed

    def test_fails_with_removable(self):
        check = AutoRemovablePackagesCheck()
        with patch("usaf.checks.packages.package_security_checks.AutoRemovablePackagesCheck._get_auto_removable", return_value=["libfoo", "libbar"]):
            result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1


class TestThirdPartyPackageCountCheck:
    def test_passes_with_few_repos(self):
        check = ThirdPartyPackageCountCheck()
        result = check.evaluate({"apt": {"repositories": [
            {"url": "http://archive.ubuntu.com"},
            {"url": "https://ppa.example.com"},
        ]}})
        assert result.passed

    def test_fails_with_many(self):
        check = ThirdPartyPackageCountCheck()
        result = check.evaluate({"apt": {"repositories": [
            {"url": "https://repo1.example.com"},
            {"url": "https://repo2.example.com"},
            {"url": "https://repo3.example.com"},
        ]}})
        assert not result.passed


class TestPackageIntegritySummaryCheck:
    def test_passes_when_clean(self):
        check = PackageIntegritySummaryCheck()
        result = check.evaluate({"apt": {
            "packages": [{"name": "bash", "version": "5.0"}],
            "updates": [],
            "repositories": [{"url": "https://archive.ubuntu.com"}],
        }})
        assert result.passed

    def test_fails_with_issues(self):
        check = PackageIntegritySummaryCheck()
        result = check.evaluate({"apt": {
            "packages": [],
            "updates": [],
            "repositories": [],
        }})
        assert not result.passed
        assert len(result.findings) == 1
