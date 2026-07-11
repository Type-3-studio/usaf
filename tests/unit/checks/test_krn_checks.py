from __future__ import annotations

from pathlib import Path

from usaf.checks.kernel.module_loading_check import KernelModuleLoadingCheck
from usaf.models.severity import Severity


class TestKernelModuleLoadingCheck:
    def test_passes_when_modules_disabled(self, monkeypatch):
        monkeypatch.setattr(
            Path, "read_text", lambda _: "1",
        )
        monkeypatch.setattr(Path, "exists", lambda _: True)
        check = KernelModuleLoadingCheck()
        result = check.evaluate({})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_modules_enabled(self, monkeypatch):
        monkeypatch.setattr(
            Path, "read_text", lambda _: "0",
        )
        monkeypatch.setattr(Path, "exists", lambda _: True)
        check = KernelModuleLoadingCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "module loading" in f.title.lower()
        assert f.severity == Severity.MEDIUM

    def test_fails_when_sysctl_unreadable(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: (_ for _ in ()).throw(OSError))
        monkeypatch.setattr(Path, "exists", lambda _: True)
        check = KernelModuleLoadingCheck()
        result = check.evaluate({})
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_cis_and_mitre_mapping(self, monkeypatch):
        monkeypatch.setattr(
            Path, "read_text", lambda _: "0",
        )
        monkeypatch.setattr(Path, "exists", lambda _: True)
        check = KernelModuleLoadingCheck()
        result = check.evaluate({})
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert len(f.cis_benchmarks) > 0
