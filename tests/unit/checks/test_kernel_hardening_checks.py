from __future__ import annotations

from usaf.checks.kernel.kernel_hardening_checks import (
    CoreUsesPidCheck,
    LinkProtectionsCheck,
    MmapMinAddrCheck,
    SpecialFileProtectionsCheck,
    TTYLdiscAutoloadCheck,
    UnprivilegedBPFCheck,
    UserfaultfdCheck,
    YamaPtraceScopeCheck,
)
from usaf.models.severity import Severity


def _params(data: dict | None = None) -> dict:
    return {"kernel_params": data or {}}


class TestTTYLdiscAutoloadCheck:
    def test_passes_when_0(self):
        check = TTYLdiscAutoloadCheck()
        result = check.evaluate(_params({"dev.tty.ldisc_autoload": "0"}))
        assert result.passed

    def test_fails_when_1(self):
        check = TTYLdiscAutoloadCheck()
        result = check.evaluate(_params({"dev.tty.ldisc_autoload": "1"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_missing(self):
        check = TTYLdiscAutoloadCheck()
        result = check.evaluate(_params({}))
        assert not result.passed

    def test_severity_low(self):
        check = TTYLdiscAutoloadCheck()
        result = check.evaluate(_params({"dev.tty.ldisc_autoload": "1"}))
        assert result.findings[0].severity == Severity.LOW


class TestYamaPtraceScopeCheck:
    def test_passes_when_1(self):
        check = YamaPtraceScopeCheck()
        result = check.evaluate(_params({"kernel.yama.ptrace_scope": "1"}))
        assert result.passed

    def test_passes_when_2(self):
        check = YamaPtraceScopeCheck()
        result = check.evaluate(_params({"kernel.yama.ptrace_scope": "2"}))
        assert result.passed

    def test_fails_when_0(self):
        check = YamaPtraceScopeCheck()
        result = check.evaluate(_params({"kernel.yama.ptrace_scope": "0"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_missing(self):
        check = YamaPtraceScopeCheck()
        result = check.evaluate(_params({}))
        assert not result.passed

    def test_has_cis_mapping(self):
        check = YamaPtraceScopeCheck()
        result = check.evaluate(_params({"kernel.yama.ptrace_scope": "0"}))
        assert len(result.findings[0].cis_benchmarks) > 0


class TestCoreUsesPidCheck:
    def test_passes_when_1(self):
        check = CoreUsesPidCheck()
        result = check.evaluate(_params({"kernel.core_uses_pid": "1"}))
        assert result.passed

    def test_fails_when_0(self):
        check = CoreUsesPidCheck()
        result = check.evaluate(_params({"kernel.core_uses_pid": "0"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_missing(self):
        check = CoreUsesPidCheck()
        result = check.evaluate(_params({}))
        assert not result.passed


class TestUnprivilegedBPFCheck:
    def test_passes_when_1(self):
        check = UnprivilegedBPFCheck()
        result = check.evaluate(_params({"kernel.unprivileged_bpf_disabled": "1"}))
        assert result.passed

    def test_fails_when_0(self):
        check = UnprivilegedBPFCheck()
        result = check.evaluate(_params({"kernel.unprivileged_bpf_disabled": "0"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_missing(self):
        check = UnprivilegedBPFCheck()
        result = check.evaluate(_params({}))
        assert not result.passed

    def test_has_cis_mapping(self):
        check = UnprivilegedBPFCheck()
        result = check.evaluate(_params({"kernel.unprivileged_bpf_disabled": "0"}))
        assert len(result.findings[0].cis_benchmarks) > 0


class TestLinkProtectionsCheck:
    def test_passes_when_both_1(self):
        check = LinkProtectionsCheck()
        result = check.evaluate(_params({
            "fs.protected_hardlinks": "1",
            "fs.protected_symlinks": "1",
        }))
        assert result.passed

    def test_fails_when_hardlinks_0(self):
        check = LinkProtectionsCheck()
        result = check.evaluate(_params({
            "fs.protected_hardlinks": "0",
            "fs.protected_symlinks": "1",
        }))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_symlinks_0(self):
        check = LinkProtectionsCheck()
        result = check.evaluate(_params({
            "fs.protected_hardlinks": "1",
            "fs.protected_symlinks": "0",
        }))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_both_0(self):
        check = LinkProtectionsCheck()
        result = check.evaluate(_params({
            "fs.protected_hardlinks": "0",
            "fs.protected_symlinks": "0",
        }))
        assert not result.passed
        assert len(result.findings) == 2


class TestSpecialFileProtectionsCheck:
    def test_passes_when_both_1(self):
        check = SpecialFileProtectionsCheck()
        result = check.evaluate(_params({
            "fs.protected_regular": "1",
            "fs.protected_fifos": "1",
        }))
        assert result.passed

    def test_fails_when_regular_0(self):
        check = SpecialFileProtectionsCheck()
        result = check.evaluate(_params({
            "fs.protected_regular": "0",
            "fs.protected_fifos": "1",
        }))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_fifos_0(self):
        check = SpecialFileProtectionsCheck()
        result = check.evaluate(_params({
            "fs.protected_regular": "1",
            "fs.protected_fifos": "0",
        }))
        assert not result.passed
        assert len(result.findings) == 1


class TestUserfaultfdCheck:
    def test_passes_when_0(self):
        check = UserfaultfdCheck()
        result = check.evaluate(_params({"vm.unprivileged_userfaultfd": "0"}))
        assert result.passed

    def test_fails_when_1(self):
        check = UserfaultfdCheck()
        result = check.evaluate(_params({"vm.unprivileged_userfaultfd": "1"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_missing(self):
        check = UserfaultfdCheck()
        result = check.evaluate(_params({}))
        assert not result.passed

    def test_has_mitre_mapping(self):
        check = UserfaultfdCheck()
        result = check.evaluate(_params({"vm.unprivileged_userfaultfd": "1"}))
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestMmapMinAddrCheck:
    def test_passes_when_65536(self):
        check = MmapMinAddrCheck()
        result = check.evaluate(_params({"vm.mmap_min_addr": "65536"}))
        assert result.passed

    def test_passes_when_higher(self):
        check = MmapMinAddrCheck()
        result = check.evaluate(_params({"vm.mmap_min_addr": "131072"}))
        assert result.passed

    def test_fails_when_0(self):
        check = MmapMinAddrCheck()
        result = check.evaluate(_params({"vm.mmap_min_addr": "0"}))
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_when_4096(self):
        check = MmapMinAddrCheck()
        result = check.evaluate(_params({"vm.mmap_min_addr": "4096"}))
        assert not result.passed

    def test_fails_when_missing(self):
        check = MmapMinAddrCheck()
        result = check.evaluate(_params({}))
        assert not result.passed
