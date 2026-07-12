from usaf.checks.cloud.cloud_checks import (
    CloudAgentHealthCheck,
    CloudIAMCredentialAuditCheck,
    CloudMetadataExposureCheck,
    IMDSv2Check,
    KubernetesNodeSecurityCheck,
    PublicCloudStorageExposureCheck,
)
from usaf.models.severity import CheckCategory, Confidence, Severity


class TestCloudMetadataExposureCheck:
    def test_passes_when_not_on_cloud(self):
        check = CloudMetadataExposureCheck()
        result = check.evaluate({"cloud": {"provider": None, "metadata_service": {}}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_imds_not_reachable(self):
        check = CloudMetadataExposureCheck()
        result = check.evaluate({
            "cloud": {
                "provider": "aws",
                "metadata_service": {
                    "imds_reachable": False,
                    "imds_v1_accessible": False,
                    "imds_v2_required": True,
                },
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_imds_v1_accessible(self):
        check = CloudMetadataExposureCheck()
        result = check.evaluate({
            "cloud": {
                "provider": "aws",
                "metadata_service": {
                    "imds_reachable": True,
                    "imds_v1_accessible": True,
                    "imds_v2_required": False,
                },
            }
        })
        assert not result.passed
        assert any("001" in str(f.id) for f in result.findings)

    def test_returns_correct_category(self):
        assert CloudMetadataExposureCheck.category == CheckCategory.CLOUD

    def test_returns_correct_severity(self):
        assert CloudMetadataExposureCheck.severity == Severity.HIGH

    def test_finding_has_proper_evidence(self):
        check = CloudMetadataExposureCheck()
        result = check.evaluate({
            "cloud": {
                "provider": "aws",
                "metadata_service": {
                    "imds_reachable": True,
                    "imds_v1_accessible": True,
                    "imds_v2_required": False,
                },
            }
        })
        assert not result.passed
        f = result.findings[0]
        assert f.evidence is not None
        assert "True" in str(f.evidence)
        assert f.mitre_attack_ids
        assert "T1552.005" in f.mitre_attack_ids


class TestIMDSv2Check:
    def test_passes_when_not_aws(self):
        check = IMDSv2Check()
        result = check.evaluate({"cloud": {"provider": "gcp"}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_not_on_cloud(self):
        check = IMDSv2Check()
        result = check.evaluate({"cloud": {"provider": None}})
        assert result.passed
        assert len(result.findings) == 0

    def test_finding_when_imdsv2_unknown(self):
        check = IMDSv2Check()
        result = check.evaluate({
            "cloud": {
                "provider": "aws",
                "metadata_service": {
                    "imds_v2_required": None,
                },
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert "unknown" in result.findings[0].detected_value


class TestPublicCloudStorageExposureCheck:
    def test_passes_when_no_storage_tools(self):
        check = PublicCloudStorageExposureCheck()
        result = check.evaluate({
            "cloud": {
                "storage_tools": {
                    "aws_cli": False,
                    "gcloud_cli": False,
                    "az_cli": False,
                    "s3cmd": False,
                    "mc_cli": False,
                }
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_storage_tools_present(self):
        check = PublicCloudStorageExposureCheck()
        result = check.evaluate({
            "cloud": {
                "storage_tools": {
                    "aws_cli": True,
                    "gcloud_cli": False,
                    "az_cli": False,
                    "s3cmd": False,
                    "mc_cli": False,
                }
            }
        })
        assert not result.passed
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "aws_cli" in f.evidence.value

    def test_confidence_medium(self):
        check = PublicCloudStorageExposureCheck()
        result = check.evaluate({
            "cloud": {
                "storage_tools": {
                    "aws_cli": True,
                    "gcloud_cli": True,
                    "az_cli": False,
                    "s3cmd": False,
                    "mc_cli": False,
                }
            }
        })
        assert result.findings[0].confidence == Confidence.MEDIUM

    def test_category(self):
        assert PublicCloudStorageExposureCheck.category == CheckCategory.CLOUD


class TestCloudIAMCredentialAuditCheck:
    def test_passes_when_no_credentials(self):
        check = CloudIAMCredentialAuditCheck()
        result = check.evaluate({
            "cloud": {
                "credentials": {
                    "aws_credentials_exist": False,
                    "aws_credential_count": 0,
                    "gcp_credentials_exist": False,
                    "gcp_credential_count": 0,
                    "azure_credentials_exist": False,
                    "azure_credential_count": 0,
                }
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_aws_creds_exist(self):
        check = CloudIAMCredentialAuditCheck()
        result = check.evaluate({
            "cloud": {
                "credentials": {
                    "aws_credentials_exist": True,
                    "aws_credential_count": 2,
                    "gcp_credentials_exist": False,
                    "gcp_credential_count": 0,
                    "azure_credentials_exist": False,
                    "azure_credential_count": 0,
                }
            }
        })
        assert not result.passed
        assert any("AWS" in f.title for f in result.findings)

    def test_fails_when_gcp_creds_exist(self):
        check = CloudIAMCredentialAuditCheck()
        result = check.evaluate({
            "cloud": {
                "credentials": {
                    "aws_credentials_exist": False,
                    "aws_credential_count": 0,
                    "gcp_credentials_exist": True,
                    "gcp_credential_count": 3,
                    "azure_credentials_exist": False,
                    "azure_credential_count": 0,
                }
            }
        })
        assert not result.passed
        assert any("GCP" in f.title for f in result.findings)

    def test_fails_when_azure_creds_exist(self):
        check = CloudIAMCredentialAuditCheck()
        result = check.evaluate({
            "cloud": {
                "credentials": {
                    "aws_credentials_exist": False,
                    "aws_credential_count": 0,
                    "gcp_credentials_exist": False,
                    "gcp_credential_count": 0,
                    "azure_credentials_exist": True,
                    "azure_credential_count": 1,
                }
            }
        })
        assert not result.passed
        assert any("Azure" in f.title for f in result.findings)

    def test_fails_with_multiple_providers(self):
        check = CloudIAMCredentialAuditCheck()
        result = check.evaluate({
            "cloud": {
                "credentials": {
                    "aws_credentials_exist": True,
                    "aws_credential_count": 1,
                    "gcp_credentials_exist": True,
                    "gcp_credential_count": 1,
                    "azure_credentials_exist": False,
                    "azure_credential_count": 0,
                }
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_severity_high(self):
        assert CloudIAMCredentialAuditCheck.severity == Severity.HIGH


class TestCloudAgentHealthCheck:
    def test_passes_when_not_on_cloud(self):
        check = CloudAgentHealthCheck()
        result = check.evaluate({"cloud": {"provider": None, "agents": {}}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_agent_running_aws(self):
        check = CloudAgentHealthCheck()
        result = check.evaluate({
            "cloud": {
                "provider": "aws",
                "agents": {"aws_ssm_agent": True},
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_ssm_agent_not_running(self):
        check = CloudAgentHealthCheck()
        result = check.evaluate({
            "cloud": {
                "provider": "aws",
                "agents": {"aws_ssm_agent": False},
            }
        })
        assert not result.passed
        assert "SSM Agent" in result.findings[0].title

    def test_fails_when_gcp_agent_not_running(self):
        check = CloudAgentHealthCheck()
        result = check.evaluate({
            "cloud": {
                "provider": "gcp",
                "agents": {"gcp_guest_agent": False},
            }
        })
        assert not result.passed
        assert "GCP" in result.findings[0].title

    def test_fails_when_azure_agent_not_running(self):
        check = CloudAgentHealthCheck()
        result = check.evaluate({
            "cloud": {
                "provider": "azure",
                "agents": {"azure_waagent": False},
            }
        })
        assert not result.passed
        assert "Azure" in result.findings[0].title

    def test_mitre_mappings_present(self):
        check = CloudAgentHealthCheck()
        result = check.evaluate({
            "cloud": {
                "provider": "aws",
                "agents": {"aws_ssm_agent": False},
            }
        })
        assert result.findings[0].mitre_attack_ids
        assert "T1562.001" in result.findings[0].mitre_attack_ids


class TestKubernetesNodeSecurityCheck:
    def test_passes_when_no_k8s(self):
        check = KubernetesNodeSecurityCheck()
        result = check.evaluate({
            "cloud": {"kubernetes": {"detected": False}},
            "processes": {},
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_when_kubelet_not_running(self):
        check = KubernetesNodeSecurityCheck()
        result = check.evaluate({
            "cloud": {
                "kubernetes": {
                    "detected": True,
                    "kubelet_running": False,
                },
                "kubelet_config_raw": None,
            },
            "processes": {"processes": []},
        })
        assert not result.passed
        assert any("Kubelet" in f.title for f in result.findings)

    def test_fails_when_read_only_port_exposed(self):
        check = KubernetesNodeSecurityCheck()
        result = check.evaluate({
            "cloud": {
                "kubernetes": {
                    "detected": True,
                    "kubelet_running": True,
                },
                "kubelet_config_raw": {
                    "path": "/var/lib/kubelet/config.yaml",
                    "read_only_port": 10255,
                },
            },
            "processes": {"processes": []},
        })
        assert not result.passed
        read_only_findings = [f for f in result.findings if "read-only" in f.title.lower()]
        assert len(read_only_findings) >= 1

    def test_kubelet_not_running_mitre(self):
        check = KubernetesNodeSecurityCheck()
        result = check.evaluate({
            "cloud": {
                "kubernetes": {
                    "detected": True,
                    "kubelet_running": False,
                },
                "kubelet_config_raw": None,
            },
            "processes": {"processes": []},
        })
        assert any("T1578.002" in f.mitre_attack_ids for f in result.findings if f.check_id == "CLD-501")

    def test_category(self):
        assert KubernetesNodeSecurityCheck.category == CheckCategory.CLOUD

    def test_severity(self):
        assert KubernetesNodeSecurityCheck.severity == Severity.HIGH
