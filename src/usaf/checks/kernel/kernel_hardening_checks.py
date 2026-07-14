from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class TTYLdiscAutoloadCheck(AuditCheck):
    id = "KERN-151"
    name = "TTY Line Discipline Autoload"
    category = CheckCategory.KERNEL
    severity = Severity.LOW
    description = "Checks that TTY line discipline autoloading is disabled"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "tty", "exploit-mitigation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        value = params.get("dev.tty.ldisc_autoload", "")
        if value != "0":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="TTY line discipline autoloading is enabled",
                    description=f"dev.tty.ldisc_autoload is set to {value!r}, expected '0'",
                    rationale=(
                        "TTY line discipline autoloading allows unprivileged users to load "
                        "line discipline modules, which can be used for kernel exploitation. "
                        "Disabling it reduces the kernel attack surface."
                    ),
                    remediation=(
                        "Set 'dev.tty.ldisc_autoload = 0' in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w dev.tty.ldisc_autoload=0'."
                    ),
                    evidence=RegistryEvidence(
                        key="dev.tty.ldisc_autoload",
                        value=value,
                        expected="0",
                        source="/proc/sys/dev/tty/ldisc_autoload",
                    ),
                    detected_value=value or "not found",
                    expected_value="0",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    tags=["kernel-hardening", "tty"],
                )
            )
        return findings


@register_check
class YamaPtraceScopeCheck(AuditCheck):
    id = "KERN-251"
    name = "Yama Ptrace Scope"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that ptrace scope is restricted to prevent process injection"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "ptrace", "exploit-mitigation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        value = params.get("kernel.yama.ptrace_scope", "")
        if value in {"", "0"}:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Ptrace scope is unrestricted",
                    description=(
                        f"kernel.yama.ptrace_scope is set to {value!r}, "
                        f"expected '1' or higher"
                    ),
                    rationale=(
                        "When ptrace_scope is 0, any process can ptrace any other process "
                        "owned by the same user. This allows easy process injection, "
                        "credential theft from memory, and debugging of protected processes. "
                        "Setting to 1 restricts ptrace to parent-child relationships only."
                    ),
                    remediation=(
                        "Set 'kernel.yama.ptrace_scope = 1' in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w kernel.yama.ptrace_scope=1'. "
                        "For high-security environments, use 2 or 3."
                    ),
                    evidence=RegistryEvidence(
                        key="kernel.yama.ptrace_scope",
                        value=value,
                        expected="1",
                        source="/proc/sys/kernel/yama/ptrace_scope",
                    ),
                    detected_value=value or "not found",
                    expected_value="1",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.6.2"],
                    mitre_attack_ids=["T1055"],
                    tags=["kernel-hardening", "process-injection"],
                )
            )
        return findings


@register_check
class CoreUsesPidCheck(AuditCheck):
    id = "KERN-351"
    name = "Core Dump PID Naming"
    category = CheckCategory.KERNEL
    severity = Severity.LOW
    description = "Checks that core dumps include PID in the filename for traceability"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "core-dump", "forensics"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        value = params.get("kernel.core_uses_pid", "")
        if value != "1":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Core dumps do not include PID in filename",
                    description=f"kernel.core_uses_pid is set to {value!r}, expected '1'",
                    rationale=(
                        "When core_uses_pid is 0, core dump filenames do not include the "
                        "PID, making it harder to associate core dumps with specific "
                        "process instances. Including the PID aids forensic analysis when "
                        "multiple processes crash."
                    ),
                    remediation=(
                        "Set 'kernel.core_uses_pid = 1' in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w kernel.core_uses_pid=1'."
                    ),
                    evidence=RegistryEvidence(
                        key="kernel.core_uses_pid",
                        value=value,
                        expected="1",
                        source="/proc/sys/kernel/core_uses_pid",
                    ),
                    detected_value=value or "not found",
                    expected_value="1",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    tags=["kernel-hardening", "forensics"],
                )
            )
        return findings


@register_check
class UnprivilegedBPFCheck(AuditCheck):
    id = "KERN-451"
    name = "Unprivileged BPF"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that unprivileged BPF is disabled"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "bpf", "exploit-mitigation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        value = params.get("kernel.unprivileged_bpf_disabled", "")
        if value != "1":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Unprivileged BPF is enabled",
                    description=(
                        f"kernel.unprivileged_bpf_disabled is set to {value!r}, "
                        f"expected '1'"
                    ),
                    rationale=(
                        "Unprivileged BPF allows non-root users to load Berkeley Packet "
                        "Filter programs into the kernel. BPF has a history of "
                        "vulnerabilities (CVE-2017-16994, CVE-2020-8835, etc.) that allow "
                        "privilege escalation. Disabling unprivileged BPF eliminates "
                        "a major attack surface."
                    ),
                    remediation=(
                        "Set 'kernel.unprivileged_bpf_disabled = 1' "
                        "in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w kernel.unprivileged_bpf_disabled=1'."
                    ),
                    evidence=RegistryEvidence(
                        key="kernel.unprivileged_bpf_disabled",
                        value=value,
                        expected="1",
                        source="/proc/sys/kernel/unprivileged_bpf_disabled",
                    ),
                    detected_value=value or "not found",
                    expected_value="1",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1204.002"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.6.3"],
                    tags=["kernel-hardening", "bpf", "privilege-escalation"],
                )
            )
        return findings


@register_check
class LinkProtectionsCheck(AuditCheck):
    id = "KERN-511"
    name = "Filesystem Link Protections"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that hardlink and symlink protections are enabled"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "filesystem", "privilege-escalation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        hardlinks = params.get("fs.protected_hardlinks", "")
        if hardlinks != "1":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Hardlink protection is disabled",
                    description=f"fs.protected_hardlinks is set to {hardlinks!r}, expected '1'",
                    rationale=(
                        "Without protected_hardlinks, unprivileged users can create hardlinks "
                        "to files they do not own, potentially accessing sensitive data or "
                        "enabling privilege escalation via file descriptor attacks."
                    ),
                    remediation=(
                        "Set 'fs.protected_hardlinks = 1' in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w fs.protected_hardlinks=1'."
                    ),
                    evidence=RegistryEvidence(
                        key="fs.protected_hardlinks",
                        value=hardlinks,
                        expected="1",
                        source="/proc/sys/fs/protected_hardlinks",
                    ),
                    detected_value=hardlinks or "not found",
                    expected_value="1",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.5.3"],
                    mitre_attack_ids=["T1574.001"],
                    tags=["kernel-hardening", "filesystem"],
                )
            )
        symlinks = params.get("fs.protected_symlinks", "")
        if symlinks != "1":
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Symlink protection is disabled",
                    description=f"fs.protected_symlinks is set to {symlinks!r}, expected '1'",
                    rationale=(
                        "Without protected_symlinks, unprivileged users can create symlinks "
                        "in world-writable directories pointing to files they do not own. "
                        "This enables TOCTOU attacks where a privileged process follows "
                        "a malicious symlink to overwrite or read protected files."
                    ),
                    remediation=(
                        "Set 'fs.protected_symlinks = 1' in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w fs.protected_symlinks=1'."
                    ),
                    evidence=RegistryEvidence(
                        key="fs.protected_symlinks",
                        value=symlinks,
                        expected="1",
                        source="/proc/sys/fs/protected_symlinks",
                    ),
                    detected_value=symlinks or "not found",
                    expected_value="1",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.5.4"],
                    mitre_attack_ids=["T1574.002"],
                    tags=["kernel-hardening", "filesystem"],
                )
            )
        return findings


@register_check
class SpecialFileProtectionsCheck(AuditCheck):
    id = "KERN-512"
    name = "Special File Open Protections"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that protected_regular and protected_fifos are enabled"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "filesystem", "privilege-escalation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        regular = params.get("fs.protected_regular", "")
        if regular != "1":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Protected regular file creation is disabled",
                    description=f"fs.protected_regular is set to {regular!r}, expected '1'",
                    rationale=(
                        "When protected_regular is 0, unprivileged users can create "
                        "regular files in sticky-bit world-writable directories owned "
                        "by other users. This can be used for privilege escalation "
                        "via data corruption or file replacement attacks."
                    ),
                    remediation=(
                        "Set 'fs.protected_regular = 1' in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w fs.protected_regular=1'."
                    ),
                    evidence=RegistryEvidence(
                        key="fs.protected_regular",
                        value=regular,
                        expected="1",
                        source="/proc/sys/fs/protected_regular",
                    ),
                    detected_value=regular or "not found",
                    expected_value="1",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    tags=["kernel-hardening", "filesystem", "privilege-escalation"],
                )
            )
        fifos = params.get("fs.protected_fifos", "")
        if fifos != "1":
            findings.append(
                self.finding(
                    finding_id="002",
                    title="Protected FIFO creation is disabled",
                    description=f"fs.protected_fifos is set to {fifos!r}, expected '1'",
                    rationale=(
                        "When protected_fifos is 0, unprivileged users can create "
                        "named pipes (FIFOs) in sticky-bit world-writable directories "
                        "owned by other users. Attackers can use this to intercept "
                        "data or cause denial of service."
                    ),
                    remediation=(
                        "Set 'fs.protected_fifos = 1' in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w fs.protected_fifos=1'."
                    ),
                    evidence=RegistryEvidence(
                        key="fs.protected_fifos",
                        value=fifos,
                        expected="1",
                        source="/proc/sys/fs/protected_fifos",
                    ),
                    detected_value=fifos or "not found",
                    expected_value="1",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    tags=["kernel-hardening", "filesystem", "privilege-escalation"],
                )
            )
        return findings


@register_check
class UserfaultfdCheck(AuditCheck):
    id = "KERN-513"
    name = "Unprivileged Userfaultfd"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that unprivileged userfaultfd is disabled"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "userfaultfd", "exploit-mitigation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        value = params.get("vm.unprivileged_userfaultfd", "")
        if value != "0":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Unprivileged userfaultfd is enabled",
                    description=(
                        f"vm.unprivileged_userfaultfd is set to {value!r}, "
                        f"expected '0'"
                    ),
                    rationale=(
                        "Userfaultfd allows userspace page fault handling. When available "
                        "to unprivileged users, it has been exploited in privilege escalation "
                        "attacks (CVE-2022-2588, CVE-2021-20201) by corrupting memory "
                        "during copy-on-write operations."
                    ),
                    remediation=(
                        "Set 'vm.unprivileged_userfaultfd = 0' "
                        "in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w vm.unprivileged_userfaultfd=0'."
                    ),
                    evidence=RegistryEvidence(
                        key="vm.unprivileged_userfaultfd",
                        value=value,
                        expected="0",
                        source="/proc/sys/vm/unprivileged_userfaultfd",
                    ),
                    detected_value=value or "not found",
                    expected_value="0",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1204.002"],
                    tags=["kernel-hardening", "privilege-escalation"],
                )
            )
        return findings


@register_check
class MmapMinAddrCheck(AuditCheck):
    id = "KERN-514"
    name = "Minimum mmap Address"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that the minimum mmap address is at least 65536 to prevent low-memory area exploits"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "mmap", "exploit-mitigation"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        value = params.get("vm.mmap_min_addr", "")
        try:
            addr = int(value)
        except (ValueError, TypeError):
            addr = 0
        if addr < 65536:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Minimum mmap address is too low",
                    description=(
                        f"vm.mmap_min_addr is set to {value!r} ({addr}), "
                        f"expected at least 65536"
                    ),
                    rationale=(
                        "mmap_min_addr sets the lowest virtual address that user-space "
                        "processes can mmap. A low value allows mmap'ing NULL-page "
                        "memory, which can be exploited for privilege escalation via "
                        "NULL pointer dereference vulnerabilities."
                    ),
                    remediation=(
                        "Set 'vm.mmap_min_addr = 65536' "
                        "in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w vm.mmap_min_addr=65536'."
                    ),
                    evidence=RegistryEvidence(
                        key="vm.mmap_min_addr",
                        value=value,
                        expected="65536",
                        source="/proc/sys/vm/mmap_min_addr",
                    ),
                    detected_value=value or "not found",
                    expected_value="65536",
                    affected_component="kernel",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    tags=["kernel-hardening", "exploit-mitigation"],
                )
            )
        return findings
