from __future__ import annotations

from pathlib import Path

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class KernelModuleLoadingCheck(AuditCheck):
    id = "KERN-401"
    name = "Kernel Module Loading Restrictions"
    category = CheckCategory.KERNEL
    severity = Severity.MEDIUM
    description = "Checks that kernel module loading is restricted to prevent unauthorized kernel code execution"
    depends = []
    tags = ["kernel", "hardening", "module-loading"]

    def _run_check(self, collectors: dict) -> list:
        findings: list = []
        value = self._read_sysctl("kernel.modules_disabled")
        if value == "1":
            return findings
        findings.append(
            self.finding(
                finding_id="001",
                title="Kernel module loading is not disabled",
                description=f"kernel.modules_disabled={value or 'unreadable'} (expected 1)",
                rationale=(
                    "When modules_disabled=1, no kernel modules can be loaded or unloaded after "
                    "boot. This prevents attackers from loading rootkits or malicious kernel "
                    "modules. For most production systems, this is a strong hardening measure. "
                    "This should only be set after verifying all required modules are loaded."
                ),
                remediation=(
                    "Add 'kernel.modules_disabled=1' to /etc/sysctl.d/99-hardening.conf. "
                    "Apply: 'sysctl -w kernel.modules_disabled=1'. "
                    "Ensure all required hardware drivers are loaded before enabling."
                ),
                evidence=RegistryEvidence(
                    key="kernel.modules_disabled",
                    value=value or "unreadable",
                    expected="1",
                    source="/proc/sys/kernel/modules_disabled",
                ),
                detected_value=value or "unreadable",
                expected_value="1",
                affected_component="kernel",
                reference="https://ubuntu.com/security/cis",
                confidence=Confidence.LOW,
                false_positive_probability=0.4,
                mitre_attack_ids=["T1214"],
                cis_benchmarks=["CIS Ubuntu 20.04: 3.5"],
                tags=["kernel-hardening", "rootkit-prevention"],
            )
        )
        return findings

    def _read_sysctl(self, key: str) -> str | None:
        path = Path("/proc/sys") / key.replace(".", "/")
        try:
            return path.read_text().strip()
        except OSError:
            return None
