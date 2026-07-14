from __future__ import annotations

from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class KernelAslrCheck(AuditCheck):
    id = "KERN-901"
    name = "Kernel ASLR Effectiveness"
    category = CheckCategory.KERNEL
    severity = Severity.LOW
    description = "Checks that kernel ASLR entropy is sufficient"
    depends = ["kernel_params"]
    tags = ["kernel", "aslr", "memory", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        params = self._get_data(collectors, "kernel_params")

        aslr_value = params.get("kernel.randomize_va_space", "")
        if aslr_value == "2":
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="ASLR not at maximum (2)",
                description=f"kernel.randomize_va_space={aslr_value}. ASLR should be set to 2 for full entropy.",
                rationale="ASLR with full entropy (value 2) randomizes stack, heap, mmap, and shared memory regions. Value 1 only randomizes stack and library addresses.",
                remediation="Set 'kernel.randomize_va_space=2' in /etc/sysctl.d/ and run 'sysctl -w kernel.randomize_va_space=2'.",
                evidence=RegistryEvidence(key="kernel.randomize_va_space", value=aslr_value, expected="2", source="/proc/sys/kernel/randomize_va_space"),
                detected_value=f"ASLR={aslr_value}",
                expected_value="ASLR=2",
                affected_component="Kernel ASLR",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1562"],
                tags=["kernel", "aslr", "memory", "hardening"],
            )
        )
        return findings


@register_check
class DebugFsCheck(AuditCheck):
    id = "KERN-902"
    name = "Debug Filesystem Check"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that debugfs is not mounted (exposes kernel internals)"
    depends = ["mounts"]
    tags = ["kernel", "debugfs", "information-disclosure", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        mounts_data = self._get_data(collectors, "mounts")

        for m in mounts_data.get("mounts", []):
            if m.get("fstype") != "debugfs":
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title="debugfs is mounted",
                    description=f"debugfs is mounted at '{m.get('mount_point', '?')}'. Debugfs exposes kernel data structures to userspace.",
                    rationale="debugfs exposes kernel internal state, including process and memory information, that can aid privilege escalation. It should not be mounted on production systems.",
                    remediation="Add 'debugfs' to /etc/modprobe.d/blacklist.conf: 'blacklist debugfs'. Or unmount: 'umount /sys/kernel/debug'.",
                    evidence=RegistryEvidence(key="mounts.debugfs", value="mounted", expected="not mounted", source="/proc/mounts"),
                    detected_value="debugfs mounted",
                    expected_value="debugfs not mounted",
                    affected_component="debugfs",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1562"],
                    tags=["kernel", "debugfs", "information-disclosure", "hardening"],
                )
            )
        return findings


@register_check
class KernelModuleBlacklistCheck(AuditCheck):
    id = "KERN-903"
    name = "Kernel Module Blacklist"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that unnecessary kernel modules are blacklisted"
    depends = []
    tags = ["kernel", "modules", "blacklist", "hardening"]

    RECOMMENDED_BLACKLIST: list[str] = [
        "sctp", "dccp", "tipc", "rds",
        "bluetooth", "btusb",
        "firewire-core", "firewire-ohci",
        "uvcvideo", "snd-usb-audio",
    ]

    BLACKLIST_DIRS: list[str] = [
        "/etc/modprobe.d/blacklist.conf",
        "/etc/modprobe.d/",
    ]

    def _run_check(self, _collectors: dict[str, Any]) -> list:
        findings: list = []
        blacklisted: set[str] = set()

        for bl_dir in self.BLACKLIST_DIRS:
            p = Path(bl_dir)
            if not p.exists():
                continue
            try:
                if p.is_file():
                    self._parse_blacklist(p, blacklisted)
                elif p.is_dir():
                    for f in sorted(p.iterdir()):
                        if f.suffix == ".conf" and "blacklist" in f.name:
                            self._parse_blacklist(f, blacklisted)
            except OSError:
                continue

        not_blacklisted = [m for m in self.RECOMMENDED_BLACKLIST if m not in blacklisted]

        if not not_blacklisted:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Unnecessary kernel modules not blacklisted",
                description=f"Modules not blacklisted: {', '.join(not_blacklisted)}. These should be blacklisted to reduce attack surface.",
                rationale="Unnecessary kernel modules increase the attack surface. Modules like DCCP, SCTP, and Bluetooth are commonly exploited for privilege escalation.",
                remediation=f"Add to /etc/modprobe.d/blacklist.conf: 'blacklist <module>' for each: {', '.join(not_blacklisted)}.",
                evidence=RegistryEvidence(key="kernel.unblacklisted_modules", value=", ".join(not_blacklisted), expected="blacklisted", source="/etc/modprobe.d/"),
                detected_value=f"Not blacklisted: {', '.join(not_blacklisted)}",
                expected_value="All unnecessary modules blacklisted",
                affected_component="Kernel module loading",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.2,
                mitre_attack_ids=["T1562"],
                tags=["kernel", "modules", "blacklist", "hardening"],
            )
        )
        return findings

    def _parse_blacklist(self, path: Path, blacklisted: set[str]) -> None:
        for line in path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if stripped.startswith("blacklist "):
                module = stripped.split(None, 1)[1].strip()
                blacklisted.add(module)


@register_check
class SysRqKeyCheck(AuditCheck):
    id = "KERN-904"
    name = "SysRq Key Restriction"
    category = CheckCategory.KERNEL
    severity = Severity.LOW
    description = "Checks that the SysRq key is restricted"
    depends = ["kernel_params"]
    tags = ["kernel", "sysrq", "hardening"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        params = self._get_data(collectors, "kernel_params")

        sysrq = params.get("kernel.sysrq", "")
        if sysrq in ("0", "4"):
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title=f"SysRq key not restricted (value={sysrq})",
                description=f"kernel.sysrq={sysrq}. SysRq should be set to 0 (disabled) or 4 (only sync).",
                rationale="The SysRq (Magic SysRq) key allows direct low-level system commands even when the system is frozen. A value of 0 disables it entirely.",
                remediation="Set 'kernel.sysrq=0' in /etc/sysctl.d/ and run 'sysctl -w kernel.sysrq=0'.",
                evidence=RegistryEvidence(key="kernel.sysrq", value=sysrq, expected="0", source="/proc/sys/kernel/sysrq"),
                detected_value=f"SysRq={sysrq}",
                expected_value="SysRq=0",
                affected_component="Kernel SysRq",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.2,
                mitre_attack_ids=["T1562"],
                tags=["kernel", "sysrq", "hardening"],
            )
        )
        return findings
