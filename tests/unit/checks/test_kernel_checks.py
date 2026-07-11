from __future__ import annotations

from usaf.checks.system.kernel_checks import (
    KernelASLRCheck,
    KernelCoreDumpCheck,
    KernelPtrRestrictCheck,
)
from usaf.models.severity import Severity


class TestKernelASLRCheck:
    def test_passes_when_aslr_2(self):
        check = KernelASLRCheck()
        result = check.evaluate(
            {
                "kernel_params": {"kernel.randomize_va_space": "2"},
            }
        )
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_aslr_0(self):
        check = KernelASLRCheck()
        result = check.evaluate(
            {
                "kernel_params": {"kernel.randomize_va_space": "0"},
            }
        )
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.severity == Severity.HIGH
        assert "0" in (f.detected_value or "")
        assert "ASLR" in f.title

    def test_fails_when_aslr_1(self):
        check = KernelASLRCheck()
        result = check.evaluate(
            {
                "kernel_params": {"kernel.randomize_va_space": "1"},
            }
        )
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_missing(self):
        check = KernelASLRCheck()
        result = check.evaluate(
            {
                "kernel_params": {},
            }
        )
        assert not result.passed
        assert len(result.findings) == 1
        assert "not found" in (result.findings[0].detected_value or "")

    def test_has_mitre_mapping(self):
        check = KernelASLRCheck()
        result = check.evaluate(
            {
                "kernel_params": {"kernel.randomize_va_space": "0"},
            }
        )
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestKernelPtrRestrictCheck:
    def test_passes_when_kptr_2(self):
        check = KernelPtrRestrictCheck()
        result = check.evaluate(
            {
                "kernel_params": {
                    "kernel.kptr_restrict": "2",
                    "kernel.dmesg_restrict": "1",
                },
            }
        )
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_kptr_0(self):
        check = KernelPtrRestrictCheck()
        result = check.evaluate(
            {
                "kernel_params": {
                    "kernel.kptr_restrict": "0",
                    "kernel.dmesg_restrict": "1",
                },
            }
        )
        assert not result.passed
        titles = [f.title for f in result.findings]
        assert any("kptr" in t.lower() or "pointer" in t.lower() for t in titles)
        assert len(result.findings) == 1

    def test_fails_when_dmesg_0(self):
        check = KernelPtrRestrictCheck()
        result = check.evaluate(
            {
                "kernel_params": {
                    "kernel.kptr_restrict": "2",
                    "kernel.dmesg_restrict": "0",
                },
            }
        )
        assert not result.passed
        titles = [f.title for f in result.findings]
        assert any("dmesg" in t.lower() for t in titles)


class TestKernelCoreDumpCheck:
    def test_passes_when_suid_dumpable_0(self):
        check = KernelCoreDumpCheck()
        result = check.evaluate(
            {
                "kernel_params": {"fs.suid_dumpable": "0"},
            }
        )
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_suid_dumpable_1(self):
        check = KernelCoreDumpCheck()
        result = check.evaluate(
            {
                "kernel_params": {"fs.suid_dumpable": "1"},
            }
        )
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM
