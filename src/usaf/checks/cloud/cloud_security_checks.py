from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class CloudEnvCredentialsCheck(AuditCheck):
    id = "CLD-502"
    name = "Cloud Credentials in Environment"
    category = CheckCategory.CLOUD
    severity = Severity.HIGH
    description = "Detects cloud credentials in environment variables"
    depends = ["cloud"]
    tags = ["cloud", "credentials", "secrets"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []
        env: dict[str, Any] = cloud_data.get("environment", {})

        cred_vars = {k: v for k, v in env.items() if v}
        if cred_vars:
            details = "; ".join(f"{k}={v}" for k, v in cred_vars.items())
            findings.append(self.finding(
                finding_id="001", title="Cloud credentials found in environment variables",
                description=f"Cloud credential environment variables detected: {details}",
                rationale="Cloud credentials in environment variables can be leaked via process listings, debug endpoints, and container orchestration platforms.",
                remediation="Use instance profiles (AWS), service accounts (GCP), or managed identities (Azure) instead of environment variables.",
                evidence=RegistryEvidence(
                    key="cloud.environment",
                    value=details,
                    expected="No cloud credential env vars",
                    source="process environment",
                ),
                detected_value=details,
                expected_value="No cloud credential env vars",
                affected_component="environment variables",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.15,
                mitre_attack_ids=["T1552.004"],
                tags=["cloud", "credentials"],
            ))

        return findings


@register_check
class KubeletAnonymousAuthCheck(AuditCheck):
    id = "CLD-503"
    name = "Kubelet Anonymous Authentication"
    category = CheckCategory.CLOUD
    severity = Severity.HIGH
    description = "Checks that kubelet anonymous authentication is disabled"
    depends = ["cloud"]
    tags = ["cloud", "kubernetes", "kubelet"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []
        kc: Any = cloud_data.get("kubelet_config_raw")
        if kc is None:
            return findings

        auth: Any = kc.get("authentication", {})
        anon: Any = auth.get("anonymous", {}) if isinstance(auth, dict) else {}
        anon_enabled = anon.get("enabled", True) if isinstance(anon, dict) else True

        if anon_enabled:
            findings.append(self.finding(
                finding_id="001", title="Kubelet anonymous authentication is enabled",
                description="Kubelet allows unauthenticated requests (anonymous auth enabled).",
                rationale="Anonymous authentication allows anyone who can reach the kubelet port to query node state and execute commands without credentials.",
                remediation="Set 'authentication: anonymous: enabled: false' in kubelet config.",
                evidence=RegistryEvidence(
                    key="kubelet.authentication.anonymous.enabled",
                    value="true",
                    expected="false",
                    source="kubelet config",
                ),
                detected_value="Anonymous auth enabled",
                expected_value="Anonymous auth disabled",
                affected_component="kubelet",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                mitre_attack_ids=["T1078"],
                tags=["cloud", "kubernetes", "kubelet"],
            ))

        return findings


@register_check
class KubeletReadOnlyPortCheck(AuditCheck):
    id = "CLD-504"
    name = "Kubelet Read-Only Port"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Checks that kubelet read-only port is disabled"
    depends = ["cloud"]
    tags = ["cloud", "kubernetes", "kubelet"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []
        kc: Any = cloud_data.get("kubelet_config_raw")
        if kc is None:
            return findings

        ro_port = kc.get("read_only_port", 0)
        if ro_port and ro_port != 0:
            findings.append(self.finding(
                finding_id="001", title=f"Kubelet read-only port enabled: {ro_port}",
                description=f"Kubelet read-only port is set to {ro_port} (should be 0).",
                rationale="The kubelet read-only port (10255) exposes node state without authentication. It should be disabled.",
                remediation="Set 'readOnlyPort: 0' in kubelet config and restart kubelet.",
                evidence=RegistryEvidence(
                    key="kubelet.read_only_port",
                    value=str(ro_port),
                    expected="0",
                    source="kubelet config",
                ),
                detected_value=f"readOnlyPort: {ro_port}",
                expected_value="readOnlyPort: 0",
                affected_component="kubelet",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                tags=["cloud", "kubernetes", "kubelet"],
            ))

        return findings


@register_check
class KubeletSeccompCheck(AuditCheck):
    id = "CLD-505"
    name = "Kubelet Seccomp Default"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Checks that kubelet seccomp default is configured"
    depends = ["cloud"]
    tags = ["cloud", "kubernetes", "seccomp"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []
        kc: Any = cloud_data.get("kubelet_config_raw")
        if kc is None:
            return findings

        seccomp = kc.get("seccomp_default")
        if not seccomp:
            findings.append(self.finding(
                finding_id="001", title="Kubelet seccomp default not configured",
                description="Kubelet seccompDefault is not set to true.",
                rationale="Seccomp default restricts system calls available to containers, reducing kernel attack surface.",
                remediation="Set 'seccompDefault: true' in kubelet config.",
                evidence=RegistryEvidence(
                    key="kubelet.seccompDefault",
                    value=str(seccomp),
                    expected="true",
                    source="kubelet config",
                ),
                detected_value=f"seccompDefault: {seccomp}",
                expected_value="seccompDefault: true",
                affected_component="kubelet",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.1,
                tags=["cloud", "kubernetes", "seccomp"],
            ))

        return findings


@register_check
class KubeletProtectKernelCheck(AuditCheck):
    id = "CLD-506"
    name = "Kubelet Protect Kernel Defaults"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Checks that kubelet protectKernelDefaults is enabled"
    depends = ["cloud"]
    tags = ["cloud", "kubernetes", "kernel"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []
        kc: Any = cloud_data.get("kubelet_config_raw")
        if kc is None:
            return findings

        pkd = kc.get("protect_kernel_defaults", False)
        if not pkd:
            findings.append(self.finding(
                finding_id="001", title="Kubelet protectKernelDefaults is not enabled",
                description="protectKernelDefaults is not set to true in kubelet config.",
                rationale="protectKernelDefaults ensures kernel parameters are set to safe values for container isolation.",
                remediation="Set 'protectKernelDefaults: true' in kubelet config.",
                evidence=RegistryEvidence(
                    key="kubelet.protectKernelDefaults",
                    value=str(pkd),
                    expected="true",
                    source="kubelet config",
                ),
                detected_value=f"protectKernelDefaults: {pkd}",
                expected_value="protectKernelDefaults: true",
                affected_component="kubelet",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.05,
                tags=["cloud", "kubernetes", "kernel"],
            ))

        return findings


@register_check
class CloudProviderInfoCheck(AuditCheck):
    id = "CLD-507"
    name = "Cloud Provider Information"
    category = CheckCategory.CLOUD
    severity = Severity.LOW
    description = "Reports detected cloud provider information"
    depends = ["cloud"]
    tags = ["cloud", "provider", "info"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []
        provider: str = cloud_data.get("provider", "none") or "none"
        k8s: dict[str, Any] = cloud_data.get("kubernetes", {})

        if provider != "none" or k8s.get("detected", False):
            info_parts = []
            if provider != "none":
                info_parts.append(f"Provider: {provider}")
            if k8s.get("detected", False):
                info_parts.append("Kubernetes detected")
                if k8s.get("kubelet_running", False):
                    info_parts.append("kubelet running")
                pods = k8s.get("pods_running", 0)
                if pods:
                    info_parts.append(f"{pods} pods")
            info = " | ".join(info_parts)

            findings.append(self.finding(
                finding_id="001", title=f"Cloud environment: {info}",
                description=f"System is running on cloud provider '{provider}' with: {info}",
                rationale="Cloud environment information aids in understanding the security context and applicable controls.",
                remediation="No action needed. This is informational.",
                evidence=RegistryEvidence(
                    key="cloud.provider",
                    value=provider,
                    expected="N/A (informational)",
                    source="cloud metadata",
                ),
                detected_value=info,
                expected_value="N/A",
                affected_component="cloud environment",
                confidence=Confidence.HIGH,
                false_positive_probability=0.0,
                tags=["cloud", "provider"],
            ))

        return findings


@register_check
class KubeletSecretsCheck(AuditCheck):
    id = "CLD-508"
    name = "Kubernetes Secrets on Node"
    category = CheckCategory.CLOUD
    severity = Severity.HIGH
    description = "Detects Kubernetes secrets stored on the node filesystem"
    depends = ["cloud"]
    tags = ["cloud", "kubernetes", "secrets"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []
        k8s: dict[str, Any] = cloud_data.get("kubernetes", {})

        if k8s.get("detected", False) and k8s.get("secrets_present", False):
            findings.append(self.finding(
                finding_id="001", title="Kubernetes secrets found on node filesystem",
                description="Kubernetes secret files detected at /var/lib/kubelet/secrets/.",
                rationale="Kubernetes secrets stored on the node filesystem can be accessed by any process with node-level access. Secrets should be managed externally or encrypted.",
                remediation="Review stored secrets at /var/lib/kubelet/secrets/. Use external secrets management or enable KMS encryption.",
                evidence=RegistryEvidence(
                    key="kubernetes.secrets_present",
                    value="true",
                    expected="false (secrets managed externally)",
                    source="filesystem",
                ),
                detected_value="K8s secrets on node",
                expected_value="No secrets stored on node",
                affected_component="kubernetes node",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1552.007"],
                tags=["cloud", "kubernetes", "secrets"],
            ))

        return findings


@register_check
class MultiCloudCredentialsCheck(AuditCheck):
    id = "CLD-509"
    name = "Multiple Cloud Provider Credentials"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Detects credentials for multiple cloud providers on the same system"
    depends = ["cloud"]
    tags = ["cloud", "credentials", "secrets"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []
        creds: dict[str, Any] = cloud_data.get("credentials", {})

        found_providers: list[str] = []
        if creds.get("aws_credentials_exist", False):
            found_providers.append(f"AWS ({creds.get('aws_credential_count', 0)} profiles)")
        if creds.get("gcp_credentials_exist", False):
            found_providers.append(f"GCP ({creds.get('gcp_credential_count', 0)} keys)")
        if creds.get("azure_credentials_exist", False):
            found_providers.append(f"Azure ({creds.get('azure_credential_count', 0)} profiles)")

        if len(found_providers) > 1:
            findings.append(self.finding(
                finding_id="001", title=f"Multiple cloud provider credentials: {len(found_providers)}",
                description=f"Credentials for multiple cloud providers detected: {', '.join(found_providers)}",
                rationale="Multiple cloud credential sets increase the blast radius of a compromise. An attacker gaining access to the system can pivot to multiple cloud environments.",
                remediation="Remove unused cloud credential files from ~/.aws/, ~/.config/gcloud/, and ~/.azure/.",
                evidence=RegistryEvidence(
                    key="cloud.credentials",
                    value=", ".join(found_providers),
                    expected="Credentials for at most one cloud provider",
                    source="filesystem",
                ),
                detected_value=", ".join(found_providers),
                expected_value="Single cloud provider credentials",
                affected_component="cloud credentials",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.15,
                mitre_attack_ids=["T1552.004"],
                tags=["cloud", "credentials"],
            ))

        return findings
