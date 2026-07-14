from __future__ import annotations

from usaf.core.plugin import AuditCheck
from usaf.core.registry import register_check
from usaf.models.evidence import RegistryEvidence
from usaf.models.severity import CheckCategory, Confidence, Severity


@register_check
class CloudMetadataExposureCheck(AuditCheck):
    id = "CLD-101"
    name = "Cloud Metadata Service Exposure"
    category = CheckCategory.CLOUD
    severity = Severity.HIGH
    description = "Checks if the cloud instance metadata service (IMDS) is accessible, which could enable SSRF-based credential theft"
    depends = ["cloud"]
    tags = ["cloud", "metadata", "imds", "ssrf"]

    def _run_check(self, collectors: dict) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []

        metadata = cloud_data.get("metadata_service", {})
        provider = cloud_data.get("provider")

        if provider is None:
            return findings

        imds_reachable = metadata.get("imds_reachable", False)
        imds_v1 = metadata.get("imds_v1_accessible", False)
        imds_v2_required = metadata.get("imds_v2_required")

        if imds_reachable and imds_v1:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="IMDSv1 Accessible — SSRF Risk",
                    description=(
                        f"The cloud metadata service ({provider}) is reachable via IMDSv1 "
                        "(unauthenticated request/response mode). This allows any process "
                        "with HTTP access to 169.254.169.254 to retrieve instance credentials."
                    ),
                    rationale=(
                        "IMDSv1 is a request/response model that does not require session tokens. "
                        "Any SSRF vulnerability or compromised container with host networking can "
                        "access the metadata service and steal IAM credentials."
                    ),
                    remediation=(
                        f"For {provider}: disable IMDSv1 and enforce IMDSv2. On AWS: "
                        "aws ec2 modify-instance-metadata-options --instance-id <id> "
                        "--http-endpoint enabled --http-tokens required --http-put-response-hop-limit 2"
                    ),
                    evidence=RegistryEvidence(
                        key="metadata_service.imds_v1_accessible",
                        value=str(imds_v1),
                        expected="False",
                        source=f"{provider} IMDS",
                    ),
                    detected_value=str(imds_v1),
                    expected_value="False",
                    affected_component=f"{provider} metadata service",
                    confidence=Confidence.HIGH,
                    mitre_attack_ids=["T1552.005", "T1613"],
                    cis_benchmarks=["CIS Ubuntu 22.04: 1.5"],
                    tags=["cloud", "metadata", "imds", "ssrf", "credential-theft"],
                )
            )

        if provider == "aws" and imds_v2_required is False:
            findings.append(
                self.finding(
                    finding_id="002",
                    title="IMDSv2 Not Enforced",
                    description=(
                        "IMDSv2 (session-oriented metadata service) is not enforced. "
                        "The instance allows both IMDSv1 and IMDSv2 requests."
                    ),
                    rationale=(
                        "Without IMDSv2 enforcement, the metadata service remains vulnerable "
                        "to SSRF-based attacks that can bypass the session token requirement."
                    ),
                    remediation=(
                        "aws ec2 modify-instance-metadata-options --instance-id <id> "
                        "--http-tokens required"
                    ),
                    evidence=RegistryEvidence(
                        key="metadata_service.imds_v2_required",
                        value=str(imds_v2_required),
                        expected="True",
                        source="AWS IMDS",
                    ),
                    detected_value=str(imds_v2_required),
                    expected_value="True",
                    affected_component="AWS EC2 metadata service",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.1,
                    mitre_attack_ids=["T1552.005", "T1613"],
                    cis_benchmarks=["CIS Ubuntu 22.04: 1.5"],
                    tags=["cloud", "aws", "imdsv2", "hardening"],
                )
            )

        return findings


@register_check
class IMDSv2Check(AuditCheck):
    id = "CLD-102"
    name = "IMDSv1 vs IMDSv2 Enforcement"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Verifies that IMDSv2 (session-oriented) is enforced to protect against SSRF-based credential theft"
    depends = ["cloud"]
    tags = ["cloud", "imds", "imdsv2", "aws"]

    def _run_check(self, collectors: dict) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []

        provider = cloud_data.get("provider")
        if provider != "aws":
            return findings

        metadata = cloud_data.get("metadata_service", {})
        imds_v2_required = metadata.get("imds_v2_required")

        if imds_v2_required is None:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="IMDSv2 Enforceability Unknown",
                    description=(
                        "Unable to determine if IMDSv2 is enforced. "
                        "The metadata service may not be accessible from this context."
                    ),
                    rationale=(
                        "Without confirmation of IMDSv2 enforcement, the instance may be "
                        "vulnerable to SSRF-based credential theft through IMDSv1."
                    ),
                    remediation=(
                        "Verify IMDS configuration: "
                        "aws ec2 describe-instances --instance-id <id> --query "
                        "'Reservations[0].Instances[0].MetadataOptions'"
                    ),
                    evidence=RegistryEvidence(
                        key="metadata_service.imds_v2_required",
                        value="unknown",
                        expected="True",
                        source="AWS IMDS",
                    ),
                    detected_value="unknown",
                    expected_value="True",
                    affected_component="AWS metadata service configuration",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.2,
                    mitre_attack_ids=["T1552.005"],
                    tags=["cloud", "aws", "imdsv2"],
                )
            )

        return findings


@register_check
class PublicCloudStorageExposureCheck(AuditCheck):
    id = "CLD-201"
    name = "Public Cloud Storage Exposure"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Detects cloud storage CLI tools that could be used to access or expose cloud storage buckets"
    depends = ["cloud"]
    tags = ["cloud", "storage", "exposure", "s3", "gcs", "blob"]

    def _run_check(self, collectors: dict) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings = []

        storage_tools = cloud_data.get("storage_tools", {})
        present_tools = [name for name, present in storage_tools.items() if present]

        if present_tools:
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Cloud Storage CLI Tools Present",
                    description=(
                        f"Cloud storage CLI tools detected: {', '.join(present_tools)}. "
                        "These tools can access and modify cloud storage resources."
                    ),
                    rationale=(
                        "Cloud storage CLI tools (aws s3, gcloud storage, az storage) provide "
                        "programmatic access to cloud storage buckets. If credentials are "
                        "misconfigured or overly permissive, these tools can be used to exfiltrate "
                        "data or expose storage resources to the public internet."
                    ),
                    remediation=(
                        "1. Audit IAM permissions for all cloud storage access\n"
                        "2. Ensure storage buckets are not publicly accessible\n"
                        "3. Remove unnecessary CLI tools from production systems\n"
                        "4. Use 'aws s3api put-public-access-block' for S3 buckets"
                    ),
                    evidence=RegistryEvidence(
                        key="cloud.storage_tools",
                        value=", ".join(present_tools),
                        expected="no storage CLI tools",
                        source="filesystem",
                    ),
                    detected_value=", ".join(present_tools),
                    expected_value="no storage CLI tools",
                    affected_component="cloud storage access",
                    confidence=Confidence.MEDIUM,
                    false_positive_probability=0.3,
                    mitre_attack_ids=["T1530", "T1525"],
                    tags=["cloud", "storage", "s3", "gcs", "blob-storage"],
                )
            )

        return findings


@register_check
class CloudIAMCredentialAuditCheck(AuditCheck):
    id = "CLD-301"
    name = "Cloud IAM Credential Audit"
    category = CheckCategory.CLOUD
    severity = Severity.HIGH
    description = "Audits the presence and age of cloud IAM credentials stored on the filesystem"
    depends = ["cloud"]
    tags = ["cloud", "iam", "credentials", "audit"]

    def _run_check(self, collectors: dict) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings = []

        creds = cloud_data.get("credentials", {})

        if creds.get("aws_credentials_exist"):
            aws_count = creds.get("aws_credential_count", 0)
            findings.append(
                self.finding(
                    finding_id="001",
                    title="AWS Credentials Found on Filesystem",
                    description=(
                        f"AWS IAM credentials found on the filesystem ({aws_count} profile(s) detected "
                        f"in ~/.aws/credentials). Long-lived credentials increase the risk of compromise."
                    ),
                    rationale=(
                        "Long-lived AWS access keys stored on disk can be stolen and used to maintain "
                        "persistent cloud access. Prefer IAM roles with short-term credentials via "
                        "metadata service (IMDSv2)."
                    ),
                    remediation=(
                        "1. Remove long-lived credentials: 'rm ~/.aws/credentials'\n"
                        "2. Use IAM roles for EC2/containers\n"
                        "3. Use 'aws configure set aws_access_key_id <key> --profile <name>' only when necessary\n"
                        "4. Rotate any exposed credentials immediately"
                    ),
                    evidence=RegistryEvidence(
                        key="cloud.credentials.aws_credential_count",
                        value=str(aws_count),
                        expected="0",
                        source="~/.aws/credentials",
                    ),
                    detected_value=str(aws_count),
                    expected_value="0",
                    affected_component="AWS IAM credentials",
                    confidence=Confidence.HIGH,
                    mitre_attack_ids=["T1552.005", "T1525"],
                    cis_benchmarks=["CIS Ubuntu 22.04: 6.2"],
                    tags=["cloud", "aws", "iam", "credentials"],
                )
            )

        if creds.get("gcp_credentials_exist"):
            gcp_count = creds.get("gcp_credential_count", 0)
            findings.append(
                self.finding(
                    finding_id="002",
                    title="GCP Service Account Keys Found on Filesystem",
                    description=(
                        f"GCP service account key files found on the filesystem "
                        f"({gcp_count} JSON key file(s) detected in ~/.config/gcloud/)."
                    ),
                    rationale=(
                        "GCP service account keys stored as JSON files are long-lived credentials. "
                        "If stolen, they provide persistent access to GCP resources. "
                        "Prefer workload identity federation or GCE default service accounts."
                    ),
                    remediation=(
                        "1. Delete downloaded service account key files\n"
                        "2. Use workload identity federation for GKE\n"
                        "3. Use GCE default service account with scoped access\n"
                        "4. Rotate any exposed keys immediately"
                    ),
                    evidence=RegistryEvidence(
                        key="cloud.credentials.gcp_credential_count",
                        value=str(gcp_count),
                        expected="0",
                        source="~/.config/gcloud/",
                    ),
                    detected_value=str(gcp_count),
                    expected_value="0",
                    affected_component="GCP service account keys",
                    confidence=Confidence.HIGH,
                    mitre_attack_ids=["T1552.005", "T1525"],
                    tags=["cloud", "gcp", "iam", "service-account"],
                )
            )

        if creds.get("azure_credentials_exist"):
            azure_count = creds.get("azure_credential_count", 0)
            findings.append(
                self.finding(
                    finding_id="003",
                    title="Azure Credentials Found on Filesystem",
                    description=(
                        f"Azure credentials found on the filesystem ({azure_count} Azure profile(s) "
                        f"detected in ~/.azure/)."
                    ),
                    rationale=(
                        "Azure CLI credentials stored on disk can be used to authenticate to Azure "
                        "resources. Use managed identities for Azure resources instead."
                    ),
                    remediation=(
                        "1. Remove Azure CLI credentials: 'az logout'\n"
                        "2. Use managed identities for Azure VMs\n"
                        "3. Rotate any exposed credentials"
                    ),
                    evidence=RegistryEvidence(
                        key="cloud.credentials.azure_credential_count",
                        value=str(azure_count),
                        expected="0",
                        source="~/.azure/azureProfile.json",
                    ),
                    detected_value=str(azure_count),
                    expected_value="0",
                    affected_component="Azure credentials",
                    confidence=Confidence.HIGH,
                    mitre_attack_ids=["T1552.005", "T1525"],
                    tags=["cloud", "azure", "credentials"],
                )
            )

        return findings


@register_check
class CloudAgentHealthCheck(AuditCheck):
    id = "CLD-401"
    name = "Cloud Agent Health"
    category = CheckCategory.CLOUD
    severity = Severity.MEDIUM
    description = "Checks that cloud management agents (SSM Agent, GCP Guest Agent, Azure waagent) are running"
    depends = ["cloud"]
    tags = ["cloud", "agent", "ssm", "monitoring"]

    def _run_check(self, collectors: dict) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []

        provider = cloud_data.get("provider")
        if not provider:
            return findings

        agents = cloud_data.get("agents", {})

        if provider == "aws" and not agents.get("aws_ssm_agent", False):
            findings.append(
                self.finding(
                    finding_id="001",
                    title="AWS SSM Agent Not Running",
                    description=(
                        "The Amazon SSM Agent (amazon-ssm-agent) is not currently running. "
                        "This agent enables Systems Manager capabilities including patch management, "
                        "session manager, and inventory collection."
                    ),
                    rationale=(
                        "The SSM Agent is required for AWS Systems Manager to manage the instance. "
                        "Without it, automated patching, compliance scanning, and operational "
                        "automation are unavailable."
                    ),
                    remediation=(
                        "sudo systemctl enable --now amazon-ssm-agent\n"
                        "or: sudo snap start amazon-ssm-agent"
                    ),
                    evidence=RegistryEvidence(
                        key="cloud.agents.aws_ssm_agent",
                        value="not running",
                        expected="running",
                        source="/proc",
                    ),
                    detected_value="not running",
                    expected_value="running",
                    affected_component="amazon-ssm-agent",
                    confidence=Confidence.HIGH,
                    mitre_attack_ids=["T1562.001"],
                    tags=["cloud", "aws", "ssm-agent", "monitoring"],
                )
            )

        if provider == "gcp" and not agents.get("gcp_guest_agent", False):
            findings.append(
                self.finding(
                    finding_id="002",
                    title="GCP Guest Agent Not Running",
                    description=(
                        "The Google Guest Agent (google-guest-agent) is not currently running. "
                        "This agent manages OS configuration, account management, and metadata syncing."
                    ),
                    rationale=(
                        "The Guest Agent is required for proper GCP integration. Without it, "
                        "SSH key management, OS login, and metadata updates may not work correctly."
                    ),
                    remediation=(
                        "sudo systemctl enable --now google-guest-agent"
                    ),
                    evidence=RegistryEvidence(
                        key="cloud.agents.gcp_guest_agent",
                        value="not running",
                        expected="running",
                        source="/proc",
                    ),
                    detected_value="not running",
                    expected_value="running",
                    affected_component="google-guest-agent",
                    confidence=Confidence.HIGH,
                    mitre_attack_ids=["T1562.001"],
                    tags=["cloud", "gcp", "guest-agent", "monitoring"],
                )
            )

        if provider == "azure" and not agents.get("azure_waagent", False):
            findings.append(
                self.finding(
                    finding_id="003",
                    title="Azure waagent Not Running",
                    description=(
                        "The Azure Linux Agent (waagent) is not currently running. "
                        "This agent manages VM provisioning, extension installation, and diagnostics."
                    ),
                    rationale=(
                        "The Azure Linux Agent is required for VM management. Without it, "
                        "VM extensions, backup, and monitoring may not function."
                    ),
                    remediation=(
                        "sudo systemctl enable --now waagent"
                    ),
                    evidence=RegistryEvidence(
                        key="cloud.agents.azure_waagent",
                        value="not running",
                        expected="running",
                        source="/proc",
                    ),
                    detected_value="not running",
                    expected_value="running",
                    affected_component="waagent",
                    confidence=Confidence.HIGH,
                    mitre_attack_ids=["T1562.001"],
                    tags=["cloud", "azure", "waagent", "monitoring"],
                )
            )

        return findings


@register_check
class KubernetesNodeSecurityCheck(AuditCheck):
    id = "CLD-501"
    name = "Kubernetes Node Security Assessment"
    category = CheckCategory.CLOUD
    severity = Severity.HIGH
    description = "Assesses Kubernetes node security configuration including kubelet, RBAC, and pod security"
    depends = ["cloud", "processes"]
    tags = ["cloud", "kubernetes", "kubelet", "node-security"]

    def _run_check(self, collectors: dict) -> list:
        cloud_data = self._get_data(collectors, "cloud")
        findings: list = []

        k8s = cloud_data.get("kubernetes", {})
        if not k8s.get("detected", False):
            return findings

        processes = self._get_optional_data(collectors, "processes")
        running_k8s_processes = []
        if processes:
            procs = processes.get("processes", [])
            for proc in procs:
                cmdline = (proc.get("cmdline") or proc.get("name", "")).lower()
                if any(k in cmdline for k in ["kubelet", "kube-apiserver", "kube-controller", "kube-proxy", "kube-scheduler"]):
                    running_k8s_processes.append(proc.get("name", "unknown"))

        if not k8s.get("kubelet_running", False):
            findings.append(
                self.finding(
                    finding_id="001",
                    title="Kubelet Not Running",
                    description=(
                        "Kubernetes environment detected but kubelet process is not running. "
                        "This may indicate a node failure or compromise."
                    ),
                    rationale=(
                        "The kubelet is the primary node agent that runs on each Kubernetes node. "
                        "If it is not running, the node is unhealthy and workloads cannot be scheduled."
                    ),
                    remediation=(
                        "sudo systemctl enable --now kubelet\n"
                        "Check kubelet logs: journalctl -u kubelet -n 50 --no-pager"
                    ),
                    evidence=RegistryEvidence(
                        key="cloud.kubernetes.kubelet_running",
                        value="false",
                        expected="true",
                        source="/proc",
                    ),
                    detected_value="false",
                    expected_value="true",
                    affected_component="kubelet",
                    confidence=Confidence.HIGH,
                    mitre_attack_ids=["T1578.002", "T1610"],
                    tags=["cloud", "kubernetes", "kubelet"],
                )
            )

        if running_k8s_processes:
            found_sensitive = [p for p in running_k8s_processes
                               if any(k in p.lower() for k in ["apiserver", "scheduler", "controller"])]
            if found_sensitive:
                findings.append(
                    self.finding(
                        finding_id="002",
                        title="Kubernetes Control Plane Components on Node",
                        description=(
                            f"Kubernetes control plane components detected on this node: "
                            f"{', '.join(found_sensitive)}. "
                            "This is expected for control plane nodes but concerning for worker nodes."
                        ),
                        rationale=(
                            "Control plane components (apiserver, scheduler, controller-manager) "
                            "on worker nodes could indicate a security boundary violation or "
                            "misconfiguration. Control plane nodes should be restricted."
                        ),
                        remediation=(
                            "Verify node role classification:\n"
                            "kubectl get nodes -o json | jq '.items[].metadata.labels'"
                        ),
                        evidence=RegistryEvidence(
                            key="cloud.kubernetes.control_plane_processes",
                            value=", ".join(found_sensitive),
                            expected="no control plane components on worker node",
                            source="/proc",
                        ),
                        detected_value=", ".join(found_sensitive),
                        expected_value="no control plane components on worker node",
                        affected_component="Kubernetes node security boundary",
                        confidence=Confidence.MEDIUM,
                        false_positive_probability=0.3,
                        mitre_attack_ids=["T1610"],
                        tags=["cloud", "kubernetes", "control-plane", "node-security"],
                    )
                )

        kubelet_config = cloud_data.get("kubelet_config_raw")
        if kubelet_config:
            read_only_port = kubelet_config.get("read_only_port")
            if read_only_port is not None and read_only_port == 10255:
                findings.append(
                    self.finding(
                        finding_id="003",
                        title="Kubelet Read-Only Port Exposed",
                        description=(
                            "Kubelet is exposing a read-only API port (10255). "
                            "This port provides unauthenticated access to pod and node information."
                        ),
                        rationale=(
                            "The kubelet read-only port (10255) allows any network actor with access "
                            "to enumerate running pods, containers, and node state. "
                            "This should be disabled in production environments."
                        ),
                        remediation=(
                            "Edit /var/lib/kubelet/config.yaml and set readOnlyPort: 0\n"
                            "Then restart kubelet: sudo systemctl restart kubelet"
                        ),
                        evidence=RegistryEvidence(
                            key="kubelet_config.readOnlyPort",
                            value=str(read_only_port),
                            expected="0",
                            source=kubelet_config.get("path", "kubelet config"),
                        ),
                        detected_value=str(read_only_port),
                        expected_value="0",
                        affected_component="kubelet read-only port",
                        confidence=Confidence.HIGH,
                        mitre_attack_ids=["T1610", "T1046"],
                        cis_benchmarks=["CIS Kubernetes: 4.2.1"],
                        tags=["cloud", "kubernetes", "kubelet", "hardening"],
                    )
                )

        return findings
