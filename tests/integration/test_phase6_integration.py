"""Integration tests for Phase 6: Cloud & Compliance."""

from usaf.checks.cloud.cloud_checks import (
    CloudAgentHealthCheck,
    CloudIAMCredentialAuditCheck,
    CloudMetadataExposureCheck,
    IMDSv2Check,
    KubernetesNodeSecurityCheck,
    PublicCloudStorageExposureCheck,
)
from usaf.core.compliance.evaluator import ComplianceEvaluator
from usaf.correlation.rules import (
    CloudCompromiseRule,
    ComplianceGapRule,
    PriorityRemediationRule,
)
from usaf.models.finding import Finding
from usaf.models.severity import CheckCategory, Severity

# ──────────────────────────────────────────────
# Realistic collectors data for cloud checks
# ──────────────────────────────────────────────

CLOUD_COLLECTORS_AWS = {
    "cloud": {
        "provider": "aws",
        "on_cloud": True,
        "metadata_service": {
            "imds_reachable": False,
            "imds_v1_accessible": False,
            "imds_v2_required": True,
            "provider": "aws",
        },
        "agents": {
            "aws_ssm_agent": True,
            "gcp_guest_agent": False,
            "azure_waagent": False,
            "oracle_agent": False,
        },
        "kubernetes": {
            "detected": False,
            "kubelet_running": False,
            "kubelet_config": None,
            "pods_running": 0,
            "secrets_present": False,
        },
        "credentials": {
            "aws_credentials_exist": False,
            "aws_credential_count": 0,
            "gcp_credentials_exist": False,
            "gcp_credential_count": 0,
            "azure_credentials_exist": False,
            "azure_credential_count": 0,
        },
        "storage_tools": {
            "aws_cli": False,
            "gcloud_cli": False,
            "az_cli": False,
            "s3cmd": False,
            "mc_cli": False,
        },
        "environment": {
            "aws_region": "us-east-1",
            "gcp_project": None,
            "azure_subscription": None,
            "k8s_service_host": None,
        },
        "kubelet_config_raw": None,
    },
    "processes": {
        "processes": [],
    },
}

CLOUD_COLLECTORS_VULNERABLE = {
    "cloud": {
        "provider": "aws",
        "on_cloud": True,
        "metadata_service": {
            "imds_reachable": True,
            "imds_v1_accessible": True,
            "imds_v2_required": False,
            "provider": "aws",
        },
        "agents": {
            "aws_ssm_agent": False,
            "gcp_guest_agent": False,
            "azure_waagent": False,
            "oracle_agent": False,
        },
        "kubernetes": {
            "detected": False,
            "kubelet_running": False,
            "kubelet_config": None,
            "pods_running": 0,
            "secrets_present": False,
        },
        "credentials": {
            "aws_credentials_exist": True,
            "aws_credential_count": 3,
            "gcp_credentials_exist": True,
            "gcp_credential_count": 2,
            "azure_credentials_exist": False,
            "azure_credential_count": 0,
        },
        "storage_tools": {
            "aws_cli": True,
            "gcloud_cli": True,
            "az_cli": False,
            "s3cmd": False,
            "mc_cli": False,
        },
        "environment": {
            "aws_region": "us-east-1",
            "gcp_project": None,
            "azure_subscription": None,
            "k8s_service_host": None,
        },
        "kubelet_config_raw": None,
    },
    "processes": {
        "processes": [],
    },
}

CLOUD_COLLECTORS_K8S = {
    "cloud": {
        "provider": None,
        "on_cloud": False,
        "metadata_service": {
            "imds_reachable": False,
            "imds_v1_accessible": False,
            "imds_v2_required": None,
            "provider": None,
        },
        "agents": {
            "aws_ssm_agent": False,
            "gcp_guest_agent": False,
            "azure_waagent": False,
            "oracle_agent": False,
        },
        "kubernetes": {
            "detected": True,
            "kubelet_running": True,
            "kubelet_config": "present",
            "pods_running": 12,
            "secrets_present": True,
        },
        "credentials": {
            "aws_credentials_exist": False,
            "aws_credential_count": 0,
            "gcp_credentials_exist": False,
            "gcp_credential_count": 0,
            "azure_credentials_exist": False,
            "azure_credential_count": 0,
        },
        "storage_tools": {
            "aws_cli": False,
            "gcloud_cli": True,
            "az_cli": False,
            "s3cmd": False,
            "mc_cli": False,
        },
        "environment": {
            "aws_region": None,
            "gcp_project": None,
            "azure_subscription": None,
            "k8s_service_host": "10.96.0.1",
        },
        "kubelet_config_raw": {
            "path": "/var/lib/kubelet/config.yaml",
            "read_only_port": 10255,
            "authentication": {"anonymous": {"enabled": True}},
        },
    },
    "processes": {
        "processes": [
            {"name": "kubelet", "pid": 1234, "cmdline": "/usr/bin/kubelet --config=/var/lib/kubelet/config.yaml"},
            {"name": "kube-proxy", "pid": 1235, "cmdline": "/usr/bin/kube-proxy"},
        ],
    },
}


class TestCloudChecksIntegration:
    def test_cloud_metadata_exposure_passes_on_secure_aws(self):
        result = CloudMetadataExposureCheck().evaluate(CLOUD_COLLECTORS_AWS)
        assert result.passed
        assert len(result.findings) == 0

    def test_cloud_metadata_exposure_fails_on_vulnerable(self):
        result = CloudMetadataExposureCheck().evaluate(CLOUD_COLLECTORS_VULNERABLE)
        assert not result.passed
        assert len(result.findings) >= 1

    def test_imdsv2_passes_on_secure_aws(self):
        result = IMDSv2Check().evaluate(CLOUD_COLLECTORS_AWS)
        assert result.passed
        assert len(result.findings) == 0

    def test_cloud_iam_creds_passes_on_secure_aws(self):
        result = CloudIAMCredentialAuditCheck().evaluate(CLOUD_COLLECTORS_AWS)
        assert result.passed
        assert len(result.findings) == 0

    def test_cloud_iam_creds_fails_on_vulnerable(self):
        result = CloudIAMCredentialAuditCheck().evaluate(CLOUD_COLLECTORS_VULNERABLE)
        assert not result.passed
        assert len(result.findings) >= 2

    def test_cloud_agent_health_passes_on_secure_aws(self):
        result = CloudAgentHealthCheck().evaluate(CLOUD_COLLECTORS_AWS)
        assert result.passed
        assert len(result.findings) == 0

    def test_cloud_agent_health_fails_on_vulnerable(self):
        result = CloudAgentHealthCheck().evaluate(CLOUD_COLLECTORS_VULNERABLE)
        assert not result.passed
        assert any("SSM Agent" in f.title for f in result.findings)

    def test_storage_exposure_fails_on_vulnerable(self):
        result = PublicCloudStorageExposureCheck().evaluate(CLOUD_COLLECTORS_VULNERABLE)
        assert not result.passed
        assert len(result.findings) >= 1

    def test_k8s_check_detects_read_only_port(self):
        result = KubernetesNodeSecurityCheck().evaluate(CLOUD_COLLECTORS_K8S)
        assert not result.passed
        assert any("read-only" in f.title.lower() for f in result.findings)

    def test_all_cloud_checks_have_correct_category(self):
        assert CloudMetadataExposureCheck.category == CheckCategory.CLOUD
        assert IMDSv2Check.category == CheckCategory.CLOUD
        assert PublicCloudStorageExposureCheck.category == CheckCategory.CLOUD
        assert CloudIAMCredentialAuditCheck.category == CheckCategory.CLOUD
        assert CloudAgentHealthCheck.category == CheckCategory.CLOUD
        assert KubernetesNodeSecurityCheck.category == CheckCategory.CLOUD


class TestComplianceEvaluatorIntegration:
    def test_evaluator_returns_all_frameworks(self):
        evaluator = ComplianceEvaluator()
        results = evaluator.evaluate([])
        check_ids = {r.check_id for r in results}
        expected = {"CMP-201", "CMP-202", "CMP-203", "CMP-301", "CMP-401", "CMP-402", "CMP-403", "CMP-501", "CMP-502", "CMP-503"}
        assert check_ids == expected, f"Missing: {expected - check_ids}"

    def test_evaluator_produces_findings_for_failed_controls(self):
        evaluator = ComplianceEvaluator()
        findings = [
            Finding(
                id="KERN-101-001",
                check_id="KERN-101",
                category=CheckCategory.KERNEL,
                severity=Severity.HIGH,
                risk_score=7.5,
                title="ASLR disabled",
                description="ASLR is disabled",
                rationale="Test",
                remediation="Enable ASLR",
                source="test",
                cis_benchmarks=["CIS Ubuntu 22.04: 1.5.1"],
            )
        ]
        results = evaluator.evaluate(findings)
        cmp201 = [r for r in results if r.check_id == "CMP-201"][0]
        aslr_controls = [
            f for f in cmp201.findings
            if "ASLR" in f.title or "1.5.1" in str(f.cis_benchmarks)
        ]
        assert len(aslr_controls) >= 1


class TestCorrelationRulesIntegration:
    def test_cloud_compromise_rule(self):
        rule = CloudCompromiseRule()
        findings = [
            Finding(
                id="CLD-301-001",
                check_id="CLD-301",
                category=CheckCategory.CLOUD,
                severity=Severity.HIGH,
                risk_score=7.5,
                title="Cloud creds found",
                description="Test",
                rationale="Test",
                remediation="Fix",
                source="test",
            ),
            Finding(
                id="CLD-101-001",
                check_id="CLD-101",
                category=CheckCategory.CLOUD,
                severity=Severity.HIGH,
                risk_score=7.5,
                title="IMDS accessible",
                description="Test",
                rationale="Test",
                remediation="Fix",
                source="test",
            ),
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_compliance_gap_rule(self):
        rule = ComplianceGapRule()
        findings = [
            Finding(
                id=f"CMP-201-{i:03d}",
                check_id="CMP-201",
                category=CheckCategory.COMPLIANCE,
                severity=Severity.HIGH,
                risk_score=7.5,
                title=f"CIS Control {i} Failed",
                description="Test",
                rationale="Test",
                remediation="Fix",
                source="test",
            )
            for i in range(12)
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
        assert result[0].severity == Severity.CRITICAL

    def test_priority_remediation_rule(self):
        rule = PriorityRemediationRule()
        findings = [
            Finding(
                id=f"CMP-{check_id}-001",
                check_id=check_id,
                category=CheckCategory.COMPLIANCE,
                severity=Severity.HIGH,
                risk_score=7.5,
                title=f"{check_id} finding",
                description="Test",
                rationale="Test",
                remediation="Fix",
                source="test",
                cis_benchmarks=["CIS Ubuntu 22.04: 5.2.1"],
                tags=["compliance"],
            )
            for check_id in ("CMP-201", "CMP-301", "CMP-401")
        ]
        result = rule.evaluate(findings)
        assert len(result) == 1
