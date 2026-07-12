from __future__ import annotations

from typing import Any

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class CloudCliToolsCheck(AuditCheck):
    id = "CLD-601"
    name = "Cloud CLI Tools Installed"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Checks for installed cloud provider CLI tools"
    depends = ["apt"]
    tags = ["cloud", "cli", "credentials", "exposure"]

    CLOUD_CLI_PACKAGES: list[str] = [
        "awscli", "aws-cli", "google-cloud-sdk", "gcloud",
        "azure-cli", "az", "ibmcloud-cli", "oci-cli",
        "doctl", "s3cmd", "mc",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")
        installed = {p.get("name", "") for p in apt_data.get("packages", [])}

        found = [pkg for pkg in self.CLOUD_CLI_PACKAGES if pkg in installed]

        if not found:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Cloud CLI tools installed",
                description=f"Cloud CLI tools found: {', '.join(found)}. These tools may provide access to cloud credentials.",
                rationale="CLI tools may contain cached credentials and API keys. On shared or CI systems, these can be harvested by malicious processes.",
                remediation=f"Review installed CLI tools. Ensure credentials are not cached: 'aws configure list', 'gcloud auth list'. Use IAM roles instead of keys where possible.",
                evidence=RegistryEvidence(key="packages.cloud_cli", value=", ".join(found), expected="not installed on shared systems", source="dpkg"),
                detected_value=f"CLI tools: {', '.join(found)}",
                expected_value="No cloud CLI tools on shared systems",
                affected_component="Cloud CLI",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.3,
                mitre_attack_ids=["T1525"],
                tags=["cloud", "cli", "credentials", "exposure"],
            )
        )
        return findings


@register_check
class CloudEnvCredentialsCheck(AuditCheck):
    id = "CLD-602"
    name = "Cloud Credentials in Environment"
    category = CheckCategory.CLOUD
    severity = Severity.CRITICAL
    description = "Checks for cloud credentials in process environments"
    depends = ["processes"]
    tags = ["cloud", "credentials", "exposure", "secrets"]
    max_findings = 100

    SENSITIVE_ENV_KEYS: list[str] = [
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_KEY",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET", "AZURE_TENANT_ID",
        "ARM_CLIENT_ID", "ARM_CLIENT_SECRET",
        "TF_VAR_", "PACKER_KEY",
    ]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        proc_data = self._get_data(collectors, "processes")

        for proc in proc_data.get("processes", []):
            env = proc.get("environment")
            if not env or not isinstance(env, str):
                continue

            env_upper = env.upper()
            found = [k for k in self.SENSITIVE_ENV_KEYS if k in env_upper]

            if not found:
                continue

            findings.append(
                self.finding(
                    finding_id="001",
                    title=f"Cloud credentials in environment: PID {proc.get('pid', 0)}",
                    description=f"Process '{proc.get('name', '?')}' (PID {proc.get('pid')}) has cloud credentials in environment variables: {', '.join(found)}.",
                    rationale="Cloud credentials in process environments can be read by any user on the system via /proc/PID/environ. This exposes cloud access to all local users.",
                    remediation=f"Review process '{proc.get('name')}'. Use instance profiles (AWS) or managed identities (Azure) instead of environment variables.",
                    evidence=RegistryEvidence(key=f"process.{proc.get('pid')}.env", value=", ".join(found), expected="no cloud credentials", source="/proc/PID/environ"),
                    detected_value=f"Cloud creds in PID {proc.get('pid')}",
                    expected_value="No cloud credentials in environment",
                    affected_component=f"PID {proc.get('pid')}: {proc.get('name', '')}",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1552.004"],
                    tags=["cloud", "credentials", "exposure", "secrets"],
                )
            )
        return findings


@register_check
class CloudMetadataCheck(AuditCheck):
    id = "CLD-603"
    name = "Cloud Metadata Service"
    category = CheckCategory.CLOUD
    severity = Severity.HIGH
    description = "Checks reachability of cloud metadata service"
    depends = ["cloud"]
    tags = ["cloud", "metadata", "imds", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        cloud_data = self._get_data(collectors, "cloud")

        metadata = cloud_data.get("metadata_service", {})
        provider = cloud_data.get("provider")

        if not cloud_data.get("on_cloud", False):
            return findings

        imds_reachable = metadata.get("imds_reachable", False)
        imds_v1 = metadata.get("imds_v1_accessible", False)

        if imds_v1:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="IMDSv1 is accessible",
                    description=f"Cloud ({provider}): IMDSv1 is accessible. IMDSv1 is vulnerable to SSRF attacks.",
                    rationale="IMDSv1 allows token-less access to the metadata service. SSRF vulnerabilities can read cloud credentials via IMDSv1. IMDSv2 requires a session token and is more secure.",
                    remediation="Enable IMDSv2 and disable IMDSv1. For AWS: set 'MetadataOptions' with 'HttpTokens: required'.",
                    evidence=RegistryEvidence(key="cloud.imds_v1", value="accessible", expected="disabled", source=f"metadata service ({provider})"),
                    detected_value="IMDSv1 accessible",
                    expected_value="IMDSv2 required, IMDSv1 disabled",
                    affected_component=f"Cloud metadata service ({provider})",
                    confidence=Confidence.HIGH,
                    false_positive_probability=0.05,
                    mitre_attack_ids=["T1552.005"],
                    tags=["cloud", "metadata", "imds", "exposure"],
                )
            )

        return findings


@register_check
class CloudStorageToolsCheck(AuditCheck):
    id = "CLD-604"
    name = "Cloud Storage Tools"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Checks for cloud storage management tools"
    depends = ["apt", "cloud"]
    tags = ["cloud", "storage", "tools", "exposure"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        apt_data = self._get_data(collectors, "apt")
        cloud_data = self._get_data(collectors, "cloud")
        installed = {p.get("name", "") for p in apt_data.get("packages", [])}

        if not cloud_data.get("on_cloud", False):
            return findings

        storage_tools = cloud_data.get("storage_tools", {})
        active_tools = [tool for tool, present in storage_tools.items() if present]

        if not active_tools:
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title="Cloud storage tools present",
                description=f"Storage tools: {', '.join(active_tools)}. These tools can access cloud storage buckets.",
                rationale="Cloud storage tools (s3cmd, mc, gsutil) can list, read, and write to cloud storage. If configured with credentials, they provide broad data access.",
                remediation="Review storage tool configurations. Ensure credentials are not stored in config files. Use IAM roles where possible.",
                evidence=RegistryEvidence(key="cloud.storage_tools", value=", ".join(active_tools), expected="none", source="cloud collector"),
                detected_value=f"Tools: {', '.join(active_tools)}",
                expected_value="No storage management tools",
                affected_component="Cloud storage",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.3,
                mitre_attack_ids=["T1525"],
                tags=["cloud", "storage", "tools", "exposure"],
            )
        )
        return findings


@register_check
class CloudAgentCheck(AuditCheck):
    id = "CLD-605"
    name = "Cloud Agent Health"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Checks that cloud provider agents are running"
    depends = ["cloud"]
    tags = ["cloud", "agents", "monitoring"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        cloud_data = self._get_data(collectors, "cloud")

        agents = cloud_data.get("agents", {})
        provider = cloud_data.get("provider", "unknown")

        running_agents = [name for name, running in agents.items() if running]

        if running_agents:
            return findings

        if not cloud_data.get("on_cloud", False):
            return findings

        findings.append(
            self.finding(
                finding_id="001",
                title=f"No cloud agents running ({provider})",
                description=f"No cloud provider agents are running on this {provider} instance.",
                rationale="Cloud agents (SSM, Guest Agent, WaAgent) provide security patching, inventory, and monitoring. Missing agents may indicate misconfiguration or compromise.",
                remediation=f"Install and start the {provider} agent. For AWS: 'systemctl start amazon-ssm-agent'. For GCP: 'systemctl start google-guest-agent'.",
                evidence=RegistryEvidence(key="cloud.agents", value="none running", expected=f"{provider} agent running", source="cloud collector"),
                detected_value=f"No agents on {provider}",
                expected_value=f"{provider} agent running",
                affected_component=f"Cloud agent ({provider})",
                confidence=Confidence.MEDIUM,
                false_positive_probability=0.3,
                mitre_attack_ids=["T1562"],
                tags=["cloud", "agents", "monitoring"],
            )
        )
        return findings


@register_check
class KubeletSecurityCheck(AuditCheck):
    id = "CLD-606"
    name = "Kubelet Security Configuration"
    category = CheckCategory.CLOUD
    severity = Severity.HIGH
    description = "Checks for insecure kubelet configuration"
    depends = ["cloud"]
    tags = ["cloud", "kubernetes", "kubelet", "security"]

    def _run_check(self, collectors: dict[str, Any]) -> list:
        findings: list = []
        cloud_data = self._get_data(collectors, "cloud")
        k8s = cloud_data.get("kubernetes", {})

        if not k8s.get("detected", False):
            return findings

        kubelet_config = k8s.get("kubelet_config_raw", {}) or {}

        anon_auth = kubelet_config.get("authentication", {}).get("anonymous", {}).get("enabled", True)
        read_only_port = kubelet_config.get("readOnlyPort", 0)

        if not anon_auth and not read_only_port:
            return findings

        issues: list[str] = []
        if anon_auth:
            issues.append("anonymous authentication enabled")
        if read_only_port:
            issues.append(f"read-only port {read_only_port} open")

        findings.append(
            self.finding(
                finding_id="001",
                title="Insecure kubelet configuration",
                description=f"Issues found: {'; '.join(issues)}.",
                rationale="Anonymous authentication on the kubelet allows unauthenticated access to node APIs. The read-only port exposes system metrics and pod information without authentication.",
                remediation="In kubelet config: set 'authentication.anonymous.enabled: false' and 'readOnlyPort: 0'. Restart kubelet.",
                evidence=RegistryEvidence(key="kubelet.security", value="; ".join(issues), expected="anonymous auth disabled, read-only port closed", source="kubelet config"),
                detected_value="; ".join(issues),
                expected_value="Secure kubelet configuration",
                affected_component="Kubelet",
                confidence=Confidence.HIGH,
                false_positive_probability=0.1,
                mitre_attack_ids=["T1525"],
                tags=["cloud", "kubernetes", "kubelet", "security"],
            )
        )
        return findings
