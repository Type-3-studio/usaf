from __future__ import annotations

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class KernelASLRCheck(AuditCheck):
    """Check that kernel ASLR is enabled (randomize_va_space = 2)."""

    id = "KERN-101"
    name = "Kernel ASLR Status"
    category = CheckCategory.KERNEL
    severity = Severity.HIGH
    description = "Checks that kernel ASLR (Address Space Layout Randomization) is fully enabled"
    depends = ["kernel_params"]
    tags = ["aslr", "kernel-hardening", "exploit-mitigation"]

    def _run_check(self, collectors: dict) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings = []

        aslr_value = params.get("kernel.randomize_va_space", "")
        if aslr_value != "2":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Kernel ASLR is not fully enabled",
                    description=f"kernel.randomize_va_space is set to {aslr_value!r}, expected '2'",
                    rationale=(
                        "ASLR randomizes memory addresses to make exploitation of memory corruption "
                        "vulnerabilities significantly harder. Without full ASLR (value 2), attackers "
                        "can more reliably predict memory layouts for return-oriented programming (ROP) "
                        "and other code-reuse attacks. Value 0 disables ASLR entirely. Value 1 randomizes "
                        "stack, shared libraries, and mmap but not the main executable text."
                    ),
                    remediation=(
                        "Set 'kernel.randomize_va_space = 2' in /etc/sysctl.d/99-security.conf "
                        "and run 'sysctl -w kernel.randomize_va_space=2'."
                    ),
                    evidence=RegistryEvidence(
                        key="kernel.randomize_va_space",
                        value=aslr_value,
                        expected="2",
                        source="/proc/sys/kernel/randomize_va_space",
                    ),
                    detected_value=aslr_value or "not found",
                    expected_value="2",
                    affected_component="kernel",
                    reference="https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#randomize-va-space",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1204.002", "T1574"],
                    tags=["aslr", "exploit-mitigation"],
                )
            )

        return findings


@register_check
class KernelPtrRestrictCheck(AuditCheck):
    """Check that kernel pointer restriction is enabled."""

    id = "KERN-201"
    name = "Kernel Pointer Restriction"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that kptr_restrict prevents kernel address leaks"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "information-disclosure"]

    def _run_check(self, collectors: dict) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings = []

        kptr = params.get("kernel.kptr_restrict", "")
        dmesg = params.get("kernel.dmesg_restrict", "")

        if kptr != "2" and kptr != "1":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Kernel pointer restriction is insufficient",
                    description=f"kernel.kptr_restrict is set to {kptr!r}, expected '2' (or at least '1')",
                    rationale=(
                        "When kptr_restrict is 0, kernel addresses are visible to all users in /proc files "
                        "like /proc/kallsyms. This leaks information that aids ASLR bypass during exploitation. "
                        "Setting to 1 prevents non-root users from seeing kernel addresses. Setting to 2 "
                        "prevents all users (including root) from seeing kernel addresses unless explicitly "
                        "needed (e.g., by profiling tools with CAP_SYSLOG)."
                    ),
                    remediation=(
                        "Set 'kernel.kptr_restrict = 2' in /etc/sysctl.d/99-security.conf. "
                        "Also set 'kernel.dmesg_restrict = 1' to restrict dmesg access."
                    ),
                    evidence=RegistryEvidence(
                        key="kernel.kptr_restrict",
                        value=kptr,
                        expected="2",
                        source="/proc/sys/kernel/kptr_restrict",
                    ),
                    detected_value=kptr or "not found",
                    expected_value="2",
                    affected_component="kernel",
                    reference="https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#kptr-restrict",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    mitre_attack_ids=["T1592"],
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.6.1"],
                    tags=["information-disclosure", "aslr"],
                )
            )

        if dmesg != "1":
            findings.append(
                self.finding(
                    finding_id="002",
                    title="dmesg restriction is not enabled",
                    description=f"kernel.dmesg_restrict is set to {dmesg!r}, expected '1'",
                    rationale=(
                        "Without dmesg_restrict, non-privileged users can read kernel log messages via dmesg. "
                        "These logs may contain sensitive information including kernel addresses, hardware "
                        "details, and potential vulnerability indicators."
                    ),
                    remediation=(
                        "Set 'kernel.dmesg_restrict = 1' in /etc/sysctl.d/99-security.conf."
                    ),
                    evidence=RegistryEvidence(
                        key="kernel.dmesg_restrict",
                        value=dmesg,
                        expected="1",
                        source="/proc/sys/kernel/dmesg_restrict",
                    ),
                    detected_value=dmesg or "not found",
                    expected_value="1",
                    affected_component="kernel",
                    reference="https://www.kernel.org/doc/html/latest/admin-guide/sysctl/kernel.html#dmesg-restrict",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    tags=["information-disclosure"],
                )
            )

        return findings


@register_check
class KernelCoreDumpCheck(AuditCheck):
    """Check that core dumps are restricted."""

    id = "KERN-301"
    name = "Core Dump Restriction"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that core dumps are disabled or restricted to prevent data leakage"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "information-disclosure"]

    def _run_check(self, collectors: dict) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings = []

        suid_dumpable = params.get("fs.suid_dumpable", "")
        if suid_dumpable != "0":
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Core dumps are not fully restricted",
                    description=f"fs.suid_dumpable is set to {suid_dumpable!r}, expected '0'",
                    rationale=(
                        "When fs.suid_dumpable is non-zero, setuid programs can produce core dumps "
                        "that contain sensitive data including passwords, keys, and memory content. "
                        "Value 1 allows core dumps. Value 2 allows core dumps but only readable by "
                        "root. Both values represent a risk for sensitive data leakage."
                    ),
                    remediation=(
                        "Set 'fs.suid_dumpable = 0' in /etc/sysctl.d/99-security.conf. "
                        "Additionally, set '* hard core 0' and '* soft core 0' in /etc/security/limits.conf "
                        "to disable core dumps for all users."
                    ),
                    evidence=RegistryEvidence(
                        key="fs.suid_dumpable",
                        value=suid_dumpable,
                        expected="0",
                        source="/proc/sys/fs/suid_dumpable",
                    ),
                    detected_value=suid_dumpable or "not found",
                    expected_value="0",
                    affected_component="kernel",
                    reference="https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#suid-dumpable",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.0,
                    cis_benchmarks=["CIS Ubuntu 20.04: 1.5.1"],
                    tags=["core-dump", "data-leakage"],
                )
            )

        return findings
