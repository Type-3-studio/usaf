from __future__ import annotations

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class UbuntuVersionCheck(AuditCheck):
    id = "CMP-001"
    name = "Ubuntu Version Support Status"
    category = CheckCategory.COMPLIANCE
    severity = Severity.MEDIUM
    description = "Checks that the installed Ubuntu release is still within its support window"
    depends = ["kernel"]
    tags = ["compliance", "support", "lifecycle"]

    SUPPORTED_VERSIONS = {
        "20.04": "Standard support ended April 2025; ESM available",
        "22.04": "Supported until April 2027",
        "24.04": "Supported until April 2029",
        "26.04": "Supported until April 2029",
    }

    def _run_check(self, collectors: dict) -> list:
        kernel_data = self._get_data(collectors, "kernel")
        os_info = kernel_data.get("os", {})
        version = os_info.get("version", "")
        findings: list = []

        if version in self.SUPPORTED_VERSIONS:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title=f"Ubuntu version {version} may be out of support",
                description=f"Ubuntu version {version} is not in the known supported list",
                rationale=(
                    "Running an unsupported Ubuntu release means no security patches for "
                    "kernel vulnerabilities, critical libraries, or userspace tools. Attackers "
                    "can target known CVEs that will never be patched. Even ESM (Expanded Security "
                    "Maintenance) requires an active Ubuntu Pro subscription."
                ),
                remediation=(
                    "Upgrade to a supported LTS release: 'do-release-upgrade'. "
                    "Check https://ubuntu.com/about/release-cycle for current support status. "
                    "If ESM is available, attach an Ubuntu Pro subscription: 'ua attach <token>'."
                ),
                evidence=RegistryEvidence(
                    key="VERSION_ID",
                    value=version,
                    expected="20.04, 22.04, 24.04, or 26.04",
                    source="/etc/os-release",
                ),
                detected_value=version,
                expected_value="A supported Ubuntu LTS version",
                affected_component="Operating System",
                reference="https://ubuntu.com/about/release-cycle",
                confidence=Confidence.HIGH,
                false_positive_probability=0.05,
                mitre_attack_ids=["T1562"],
                cis_benchmarks=["CIS Ubuntu 20.04: 1.1"],
                tags=["compliance", "support-lifecycle", "patch-management"],
            )
        )
        return findings
