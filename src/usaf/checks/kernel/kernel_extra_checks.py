from __future__ import annotations

from pathlib import Path
from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


def _read_sysctl(key: str) -> str | None:
    try:
        p = Path("/proc/sys") / key.replace(".", "/")
        return p.read_text().strip()
    except OSError:
        return None


@register_check
class PrintkLogLevelCheck(AuditCheck):
    id = "KERN-152"
    name = "Console Log Level"
    category = CheckCategory.KERNEL
    severity = Severity.LOW
    description = "Checks that kernel console log level restricts kernel message output"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "logging"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        value = params.get("kernel.printk", "")
        if value:
            levels = value.split()
            if len(levels) >= 1 and levels[0] not in ("0", "1", "2", "3"):
                findings.append(self.finding(
                    finding_id="001", title="Kernel console log level may expose sensitive info",
                    description=f"kernel.printk is '{value}' — console log level {levels[0]} allows kernel messages on console",
                    rationale="High console log levels print kernel messages to the console, potentially exposing kernel addresses and memory layout to users with console access.",
                    remediation="Set 'kernel.printk = 3 3 3 1' or lower in /etc/sysctl.d/",
                    evidence=RegistryEvidence(key="kernel.printk", value=value, expected="3 or lower first value", source="/proc/sys/kernel/printk"),
                    detected_value=value, expected_value="3 3 3 1 or similar",
                    affected_component="kernel", confidence=Confidence.LOW,
                    false_positive_probability=0.1,
                    tags=["kernel-hardening", "logging"],
                ))
        return findings


@register_check
class CtrlAltDelCheck(AuditCheck):
    id = "KERN-252"
    name = "Ctrl-Alt-Del Behavior"
    category = CheckCategory.KERNEL
    severity = Severity.LOW
    description = "Checks that Ctrl+Alt+Del shuts down the system rather than rebooting"
    depends = ["kernel_params"]
    tags = ["kernel-hardening", "access-control"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        params = self._get_data(collectors, "kernel_params")
        findings: list = []
        value = params.get("kernel.ctrl-alt-del", "")
        if value == "1":
            findings.append(self.finding(
                finding_id="001", title="Ctrl+Alt+Del triggers immediate reboot",
                description="kernel.ctrl-alt-del is 1 — Ctrl+Alt+Del will reboot without proper shutdown",
                rationale="When set to 1, pressing Ctrl+Alt+Del immediately reboots the system, bypassing proper shutdown procedures and potentially losing data.",
                remediation="Set 'kernel.ctrl-alt-del = 0' in /etc/sysctl.d/",
                evidence=RegistryEvidence(key="kernel.ctrl-alt-del", value=value, expected="0", source="/proc/sys/kernel/ctrl-alt-del"),
                detected_value=value, expected_value="0",
                affected_component="kernel", confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                tags=["kernel-hardening", "access-control"],
            ))
        return findings


@register_check
class SysrqKeyCheck(AuditCheck):
    id = "KERN-352"
    name = "SysRq Key Restrictions"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that the SysRq key is restricted to prevent unauthorized system operations"
    depends = []
    tags = ["kernel-hardening", "access-control"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        value = _read_sysctl("kernel.sysrq")
        if value is not None and value not in ("0", "4"):
            findings.append(self.finding(
                finding_id="001", title=f"SysRq key enabled: value={value}",
                description=f"kernel.sysrq is {value!r}, expected 0 (disabled) or 4 (enable only sync)",
                rationale="The SysRq key allows performing system operations (reboot, crash, kill processes) from the keyboard. Should be disabled on production systems.",
                remediation="Set 'kernel.sysrq = 0' in /etc/sysctl.d/",
                evidence=RegistryEvidence(key="kernel.sysrq", value=value, expected="0", source="/proc/sys/kernel/sysrq"),
                detected_value=value, expected_value="0",
                affected_component="kernel", confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1496"],
                tags=["kernel-hardening", "access-control"],
            ))
        return findings


@register_check
class KexecDisabledCheck(AuditCheck):
    id = "KERN-452"
    name = "Kexec Load Disabled"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that kexec loading is disabled"
    depends = []
    tags = ["kernel-hardening", "boot"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        value = _read_sysctl("kernel.kexec_load_disabled")
        if value is not None and value != "1":
            findings.append(self.finding(
                finding_id="001", title="Kexec loading is enabled",
                description=f"kernel.kexec_load_disabled is {value!r}, expected '1'",
                rationale="Kexec allows loading and executing a new kernel without going through firmware. If enabled, an attacker with root can replace the running kernel with a malicious one.",
                remediation="Set 'kernel.kexec_load_disabled = 1' in /etc/sysctl.d/",
                evidence=RegistryEvidence(key="kernel.kexec_load_disabled", value=value, expected="1", source="/proc/sys/kernel/kexec_load_disabled"),
                detected_value=value, expected_value="1",
                affected_component="kernel", confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1542.001"],
                tags=["kernel-hardening", "boot"],
            ))
        return findings


@register_check
class PerfEventParanoidCheck(AuditCheck):
    id = "KERN-552"
    name = "Perf Event Restrictions"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that perf events are restricted to prevent kernel information leaks"
    depends = []
    tags = ["kernel-hardening", "information-disclosure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        value = _read_sysctl("kernel.perf_event_paranoid")
        if value is not None and value not in ("2", "3"):
            findings.append(self.finding(
                finding_id="001", title=f"Perf event restrictions insufficient: level={value}",
                description=f"kernel.perf_event_paranoid is {value!r}, expected 2 or 3",
                rationale="perf_event_paranoid controls access to performance monitoring. Level 0 allows anyone to monitor the system. Level 2 or 3 restricts to CAP_PERFMON/CAP_SYS_ADMIN.",
                remediation="Set 'kernel.perf_event_paranoid = 3' in /etc/sysctl.d/",
                evidence=RegistryEvidence(key="kernel.perf_event_paranoid", value=value, expected="2 or 3", source="/proc/sys/kernel/perf_event_paranoid"),
                detected_value=value, expected_value="2 or 3",
                affected_component="kernel", confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1592"],
                tags=["kernel-hardening", "information-disclosure"],
            ))
        return findings


@register_check
class BootSecurityParamsCheck(AuditCheck):
    id = "KERN-652"
    name = "Boot Security Parameters"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks kernel boot parameters for security mitigations"
    depends = ["kernel"]
    tags = ["kernel-hardening", "boot", "mitigations"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        kernel_data = self._get_data(collectors, "kernel")
        findings: list = []
        cmdline: str = (kernel_data.get("cmdline") or {}).get("full", "")
        if not cmdline:
            return findings

        if "mitigations=off" in cmdline:
            findings.append(self.finding(
                finding_id="001", title="Kernel mitigations disabled: mitigations=off",
                description="Boot cmdline contains 'mitigations=off' which disables CPU vulnerability mitigations",
                rationale="Disabling CPU mitigations (Spectre, Meltdown, L1TF, MDS) exposes the system to side-channel attacks.",
                remediation="Remove 'mitigations=off' from kernel cmdline in /etc/default/grub and run update-grub.",
                evidence=RegistryEvidence(key="cmdline.mitigations", value="off", expected="on or default", source="/proc/cmdline"),
                detected_value="mitigations=off", expected_value="mitigations on or default",
                affected_component="kernel cmdline", confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1204.002"],
                tags=["kernel-hardening", "boot", "mitigations"],
            ))

        return findings


@register_check
class ModuleSigningCheck(AuditCheck):
    id = "KERN-752"
    name = "Kernel Module Signing"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that kernel module signing enforcement is active"
    depends = ["kernel"]
    tags = ["kernel-hardening", "modules", "integrity"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        kernel_data = self._get_data(collectors, "kernel")
        findings: list = []
        cmdline: str = (kernel_data.get("cmdline") or {}).get("full", "")
        if not cmdline:
            return findings

        has_lockdown = "lockdown=" in cmdline
        has_module_sig = "module.sig_enforce" in cmdline

        modules_disabled = _read_sysctl("kernel.modules_disabled")
        modules_off = modules_disabled == "1"

        if not has_lockdown and not has_module_sig and not modules_off:
            findings.append(self.finding(
                finding_id="001", title="Kernel module signing not enforced",
                description="No module signing enforcement detected in boot params or sysctl",
                rationale="Without module signing enforcement, arbitrary kernel modules can be loaded, allowing rootkits and kernel backdoors.",
                remediation="Add 'module.sig_enforce=1' to GRUB_CMDLINE_LINUX in /etc/default/grub and run update-grub.",
                evidence=RegistryEvidence(key="cmdline.module_sig", value="not enforced", expected="module.sig_enforce=1 or lockdown", source="/proc/cmdline"),
                detected_value="Module signing not enforced",
                expected_value="module.sig_enforce=1 or lockdown=integrity/confidentiality",
                affected_component="kernel module loading",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.15,
                mitre_attack_ids=["T1542.001"],
                tags=["kernel-hardening", "modules"],
            ))

        return findings


@register_check
class IommuProtectionCheck(AuditCheck):
    id = "KERN-852"
    name = "IOMMU Protection"
    category = CheckCategory.KERNEL
    severity = Severity.LOW
    description = "Checks that IOMMU is enabled for DMA protection"
    depends = ["kernel"]
    tags = ["kernel-hardening", "iommu", "dma"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        kernel_data = self._get_data(collectors, "kernel")
        findings: list = []
        cmdline: str = (kernel_data.get("cmdline") or {}).get("full", "")
        if not cmdline:
            return findings

        has_iommu = "iommu=on" in cmdline or "iommu=pt" in cmdline
        has_intel_iommu = "intel_iommu=on" in cmdline
        has_amd_iommu = "amd_iommu=on" in cmdline

        if not has_iommu and not has_intel_iommu and not has_amd_iommu:
            findings.append(self.finding(
                finding_id="001", title="IOMMU not enabled in boot parameters",
                description="No IOMMU enablement found in kernel cmdline",
                rationale="IOMMU protects against DMA attacks by isolating device memory access. Without IOMMU, a malicious PCI device can read arbitrary system memory.",
                remediation="Add 'intel_iommu=on' (Intel) or 'amd_iommu=on' (AMD) to GRUB_CMDLINE_LINUX.",
                evidence=RegistryEvidence(key="cmdline.iommu", value="not enabled", expected="iommu=on", source="/proc/cmdline"),
                detected_value="IOMMU not enabled",
                expected_value="iommu=on (or vendor-specific variant)",
                affected_component="IOMMU",
                confidence=Confidence.LOW,
                false_positive_probability=0.3,
                tags=["kernel-hardening", "iommu"],
            ))

        return findings
