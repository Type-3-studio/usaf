from __future__ import annotations

from usaf.checks.compliance.ubuntu_version_check import UbuntuVersionCheck
from usaf.models.severity import Severity


class TestUbuntuVersionCheck:
    def test_passes_when_version_supported(self):
        check = UbuntuVersionCheck()
        result = check.evaluate({
            "kernel": {"os": {"version": "24.04"}},
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_22_04(self):
        check = UbuntuVersionCheck()
        result = check.evaluate({
            "kernel": {"os": {"version": "22.04"}},
        })
        assert result.passed

    def test_passes_with_20_04(self):
        check = UbuntuVersionCheck()
        result = check.evaluate({
            "kernel": {"os": {"version": "20.04"}},
        })
        assert result.passed

    def test_fails_when_version_unsupported(self):
        check = UbuntuVersionCheck()
        result = check.evaluate({
            "kernel": {"os": {"version": "18.04"}},
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "18.04" in f.title
        assert f.severity == Severity.MEDIUM

    def test_fails_with_unknown_version(self):
        check = UbuntuVersionCheck()
        result = check.evaluate({
            "kernel": {"os": {"version": "99.99"}},
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_version_empty(self):
        check = UbuntuVersionCheck()
        result = check.evaluate({
            "kernel": {"os": {"version": ""}},
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_no_os_data(self):
        check = UbuntuVersionCheck()
        result = check.evaluate({
            "kernel": {"os": {}},
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_cis_mapping(self):
        check = UbuntuVersionCheck()
        result = check.evaluate({
            "kernel": {"os": {"version": "18.04"}},
        })
        assert len(result.findings[0].cis_benchmarks) > 0
