from __future__ import annotations

from usaf.checks.cloud.cloud_security_checks import (
    CloudEnvCredentialsCheck,
    CloudProviderInfoCheck,
    KubeletAnonymousAuthCheck,
    KubeletProtectKernelCheck,
    KubeletReadOnlyPortCheck,
    KubeletSeccompCheck,
    KubeletSecretsCheck,
    MultiCloudCredentialsCheck,
)


class TestCloudEnvCredentialsCheck:
    def test_passes_no_env(self):
        check = CloudEnvCredentialsCheck()
        result = check.evaluate({"cloud": {"environment": {}}})
        assert result.passed

    def test_fails_with_creds(self):
        check = CloudEnvCredentialsCheck()
        result = check.evaluate({"cloud": {"environment": {"aws_region": "us-east-1"}}})
        assert not result.passed


class TestKubeletAnonymousAuthCheck:
    def test_passes_no_kubelet(self):
        check = KubeletAnonymousAuthCheck()
        result = check.evaluate({"cloud": {}})
        assert result.passed

    def test_passes_anon_disabled(self):
        check = KubeletAnonymousAuthCheck()
        result = check.evaluate({"cloud": {"kubelet_config_raw": {"authentication": {"anonymous": {"enabled": False}}}}})
        assert result.passed

    def test_fails_anon_enabled(self):
        check = KubeletAnonymousAuthCheck()
        result = check.evaluate({"cloud": {"kubelet_config_raw": {"authentication": {"anonymous": {"enabled": True}}}}})
        assert not result.passed


class TestKubeletReadOnlyPortCheck:
    def test_passes_disabled(self):
        check = KubeletReadOnlyPortCheck()
        result = check.evaluate({"cloud": {"kubelet_config_raw": {"read_only_port": 0}}})
        assert result.passed

    def test_fails_enabled(self):
        check = KubeletReadOnlyPortCheck()
        result = check.evaluate({"cloud": {"kubelet_config_raw": {"read_only_port": 10255}}})
        assert not result.passed


class TestKubeletSeccompCheck:
    def test_passes_configured(self):
        check = KubeletSeccompCheck()
        result = check.evaluate({"cloud": {"kubelet_config_raw": {"seccomp_default": True}}})
        assert result.passed

    def test_fails_not_configured(self):
        check = KubeletSeccompCheck()
        result = check.evaluate({"cloud": {"kubelet_config_raw": {}}})
        assert not result.passed


class TestKubeletProtectKernelCheck:
    def test_passes_enabled(self):
        check = KubeletProtectKernelCheck()
        result = check.evaluate({"cloud": {"kubelet_config_raw": {"protect_kernel_defaults": True}}})
        assert result.passed

    def test_fails_disabled(self):
        check = KubeletProtectKernelCheck()
        result = check.evaluate({"cloud": {"kubelet_config_raw": {"protect_kernel_defaults": False}}})
        assert not result.passed


class TestCloudProviderInfoCheck:
    def test_skips_no_provider(self):
        check = CloudProviderInfoCheck()
        result = check.evaluate({"cloud": {"provider": None}})
        assert result.passed

    def test_reports_provider(self):
        check = CloudProviderInfoCheck()
        result = check.evaluate({"cloud": {"provider": "aws"}})
        assert not result.passed
        assert len(result.findings) == 1


class TestKubeletSecretsCheck:
    def test_passes_no_k8s(self):
        check = KubeletSecretsCheck()
        result = check.evaluate({"cloud": {"kubernetes": {"detected": False}}})
        assert result.passed

    def test_fails_secrets_present(self):
        check = KubeletSecretsCheck()
        result = check.evaluate({"cloud": {"kubernetes": {"detected": True, "secrets_present": True}}})
        assert not result.passed


class TestMultiCloudCredentialsCheck:
    def test_passes_none(self):
        check = MultiCloudCredentialsCheck()
        result = check.evaluate({"cloud": {"credentials": {}}})
        assert result.passed

    def test_passes_one(self):
        check = MultiCloudCredentialsCheck()
        result = check.evaluate({"cloud": {"credentials": {"aws_credentials_exist": True, "aws_credential_count": 2}}})
        assert result.passed

    def test_fails_multiple(self):
        check = MultiCloudCredentialsCheck()
        result = check.evaluate({"cloud": {"credentials": {"aws_credentials_exist": True, "aws_credential_count": 2, "gcp_credentials_exist": True, "gcp_credential_count": 1}}})
        assert not result.passed
