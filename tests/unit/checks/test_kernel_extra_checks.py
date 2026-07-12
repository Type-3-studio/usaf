from __future__ import annotations

from usaf.checks.kernel.kernel_extra_checks import (
    BootSecurityParamsCheck,
    CtrlAltDelCheck,
    IommuProtectionCheck,
    KexecDisabledCheck,
    ModuleSigningCheck,
    PerfEventParanoidCheck,
    PrintkLogLevelCheck,
    SysrqKeyCheck,
)


class TestPrintkLogLevelCheck:
    def test_passes_low(self):
        check = PrintkLogLevelCheck()
        result = check.evaluate({"kernel_params": {"kernel.printk": "3 3 3 1"}})
        assert result.passed

    def test_fails_high(self):
        check = PrintkLogLevelCheck()
        result = check.evaluate({"kernel_params": {"kernel.printk": "7 4 1 7"}})
        assert not result.passed


class TestCtrlAltDelCheck:
    def test_passes_0(self):
        check = CtrlAltDelCheck()
        result = check.evaluate({"kernel_params": {"kernel.ctrl-alt-del": "0"}})
        assert result.passed

    def test_fails_1(self):
        check = CtrlAltDelCheck()
        result = check.evaluate({"kernel_params": {"kernel.ctrl-alt-del": "1"}})
        assert not result.passed


class TestSysrqKeyCheck:
    def test_passes_0(self):
        check = SysrqKeyCheck()
        with patch_sysctl("kernel.sysrq", "0"):
            result = check.evaluate({})
        assert result.passed

    def test_fails_1(self):
        check = SysrqKeyCheck()
        with patch_sysctl("kernel.sysrq", "1"):
            result = check.evaluate({})
        assert not result.passed


class TestKexecDisabledCheck:
    def test_passes_disabled(self):
        check = KexecDisabledCheck()
        with patch_sysctl("kernel.kexec_load_disabled", "1"):
            result = check.evaluate({})
        assert result.passed

    def test_fails_enabled(self):
        check = KexecDisabledCheck()
        with patch_sysctl("kernel.kexec_load_disabled", "0"):
            result = check.evaluate({})
        assert not result.passed


class TestPerfEventParanoidCheck:
    def test_passes_2(self):
        check = PerfEventParanoidCheck()
        with patch_sysctl("kernel.perf_event_paranoid", "2"):
            result = check.evaluate({})
        assert result.passed

    def test_fails_0(self):
        check = PerfEventParanoidCheck()
        with patch_sysctl("kernel.perf_event_paranoid", "0"):
            result = check.evaluate({})
        assert not result.passed


class TestBootSecurityParamsCheck:
    def test_passes_default(self):
        check = BootSecurityParamsCheck()
        result = check.evaluate({"kernel": {"cmdline": {"full": "BOOT_IMAGE=/vmlinuz root=/dev/sda1"}}})
        assert result.passed

    def test_fails_mitigations_off(self):
        check = BootSecurityParamsCheck()
        result = check.evaluate({"kernel": {"cmdline": {"full": "mitigations=off root=/dev/sda1"}}})
        assert not result.passed


class TestModuleSigningCheck:
    def test_passes_with_lockdown(self):
        check = ModuleSigningCheck()
        result = check.evaluate({"kernel": {"cmdline": {"full": "lockdown=integrity root=/dev/sda1"}}})
        assert result.passed

    def test_fails_without(self):
        check = ModuleSigningCheck()
        with patch_sysctl("kernel.modules_disabled", "0"):
            result = check.evaluate({"kernel": {"cmdline": {"full": "root=/dev/sda1"}}})
        assert not result.passed


class TestIommuProtectionCheck:
    def test_passes_with_iommu(self):
        check = IommuProtectionCheck()
        result = check.evaluate({"kernel": {"cmdline": {"full": "iommu=on root=/dev/sda1"}}})
        assert result.passed

    def test_fails_without(self):
        check = IommuProtectionCheck()
        result = check.evaluate({"kernel": {"cmdline": {"full": "root=/dev/sda1"}}})
        assert not result.passed


import contextlib
from unittest.mock import patch


@contextlib.contextmanager
def patch_sysctl(key, value):
    target = "usaf.checks.kernel.kernel_extra_checks._read_sysctl"
    with patch(target, return_value=value):
        yield
