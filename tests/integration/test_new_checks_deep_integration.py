from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.checks.boot.boot_security_checks import (
    KernelImageCountCheck,
    BootPartitionMountCheck,
    GrubConfigPermissionsCheck,
)
from usaf.checks.cloud.cld_security_checks import CloudCliToolsCheck, CloudEnvCredentialsCheck
from usaf.checks.compliance.cmp_security_checks import LegacyServicesCheck, AvahiServiceCheck
from usaf.checks.compromise.com_extended_checks import ReverseShellDetectionCheck, HiddenProcessCheck
from usaf.checks.containers.ctn_security_checks import ContainerAddedCapabilitiesCheck, ContainerLatestTagCheck
from usaf.checks.filesystem.fs_security_checks import (
    SensitiveFilePermissionsCheck,
    TempDirMountSecurityCheck,
    HomeDirectoryPermissionsCheck,
)
from usaf.checks.forensics.log_security_checks import (
    JournaldRuntimeOnlyCheck,
    JournaldCompressionCheck,
    JournaldForwardingCheck,
)
from usaf.checks.kernel.krn_security_checks import DebugFsCheck, KernelAslrCheck, SysRqKeyCheck
from usaf.checks.network.net_security_checks import (
    ListeningAllInterfacesCheck,
    ExposedUdpServicesCheck,
    NonRootPrivilegedPortsCheck,
    InterfacePromiscuousCheck,
    DnsResolverConfigCheck,
    EphemeralPortExhaustionCheck,
)
from usaf.checks.packages.pkg_security_checks import (
    MissingRecommendedPackagesCheck,
    ObsoleteKernelPackagesCheck,
    DevPackagesInstalledCheck,
)
from usaf.checks.permissions.prm_security_checks import (
    GroupWritableSetuidCheck,
    SGIDOnWorldWritableDirsCheck,
    SetuidWithCapabilitiesCheck,
    CriticalDirectoryOwnershipCheck,
)
from usaf.checks.security.fw_boot_check import FirewallServiceBootCheck
from usaf.checks.security.sec_security_checks import (
    SeccompStatusCheck,
    AppArmorComplainModeCheck,
    LsmStackingCheck,
)
from usaf.checks.secrets.secr_extended_checks import GitlabTokensCheck, SlackTokensCheck, StripeKeysCheck
from usaf.checks.services.svc_security_checks import (
    ServiceLoadFailuresCheck,
    TimerServiceMismatchCheck,
    UnitFileOwnershipCheck,
)
from usaf.checks.system.ssh_security_extended import SshAgentForwardingCheck, SshPubkeyAuthOnlyCheck, SshMacAlgorithmsCheck
from usaf.checks.users.usr_security_checks import (
    ServiceAccountsWithShellCheck,
    UsersInPrivilegedGroupsCheck,
    InactiveUserAccountsCheck,
    EmptyGroupsCheck,
    UidGidMismatchCheck,
)
from usaf.models.severity import Severity


BASE_COLLECTORS: dict = {
    "kernel_params": {
        "kernel.randomize_va_space": "2",
        "kernel.sysrq": "0",
        "net.ipv4.ip_local_port_range": "32768 60999",
    },
    "users": {
        "users": [
            {"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash"},
            {"username": "alice", "uid": 1001, "gid": 1001, "home": "/home/alice", "shell": "/bin/bash"},
            {"username": "bob", "uid": 1002, "gid": 1002, "home": "/home/bob", "shell": "/bin/bash"},
        ],
        "shadow": [
            {"username": "root", "last_changed": 20650, "locked": False},
            {"username": "alice", "last_changed": 20651, "locked": False},
            {"username": "bob", "last_changed": 20652, "locked": False},
        ],
    },
    "groups": {
        "groups": [
            {"name": "root", "gid": 0, "members": ["root"]},
            {"name": "sudo", "gid": 27, "members": ["admin_user"]},
            {"name": "alice", "gid": 1001, "members": ["alice"]},
            {"name": "bob", "gid": 1002, "members": ["bob"]},
            {"name": "docker", "gid": 999, "members": ["bob"]},
            {"name": "staff", "gid": 1004, "members": ["bob"]},
        ],
    },
    "sockets": {
        "tcp": [
            {"local_address": "192.168.1.1", "local_port": 22, "state": "LISTEN", "uid": 0},
        ],
        "tcp6": [],
        "udp": [],
        "udp6": [],
        "unix": [],
    },
    "interfaces": {
        "interfaces": [
            {"name": "eth0", "promisc": False, "mac": "52:54:00:12:34:56", "state": "up"},
        ],
    },
    "mounts": {
        "mounts": [
            {"mount_point": "/", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
            {"mount_point": "/boot", "fstype": "ext4", "options": "rw,nosuid,nodev,relatime", "device": "/dev/sda2"},
            {"mount_point": "/tmp", "fstype": "tmpfs", "options": "rw,nosuid,nodev,noexec,relatime", "device": "tmpfs"},
        ],
    },
    "boot": {
        "kernel_images": {
            "images": [
                {"name": "vmlinuz-6.8.0-35-generic", "path": "/boot/vmlinuz-6.8.0-35-generic", "modified": 1000.0},
            ],
        },
        "grub": {"cfg_path": "/boot/grub/grub.cfg"},
        "kernel_lockdown": {"mode": "integrity"},
    },
    "systemd": {
        "services": [
            {"name": "ssh.service", "load": "loaded", "active": "active", "sub": "running", "description": "SSH"},
            {"name": "cron.service", "load": "loaded", "active": "active", "sub": "running", "description": "Cron"},
            {"name": "daily-cleanup.service", "load": "loaded", "active": "active", "sub": "running", "description": ""},
        ],
        "timers": [
            {"name": "daily-cleanup.timer", "load": "loaded", "active": "active", "sub": "waiting", "description": ""},
        ],
        "sockets": [
            {"name": "ssh.socket", "load": "loaded", "active": "active", "sub": "listening", "description": ""},
        ],
    },
    "dns": {
        "resolv_conf": {"nameservers": ["1.1.1.1"]},
        "mdns": {"avahi_running": False, "avahi_enabled": False},
        "resolved_status": {"current_dns": ["1.1.1.1"], "running": True},
    },
    "apt": {
        "packages": [
            {"name": "coreutils", "version": "1.0", "status": "installed"},
            {"name": "ufw", "version": "0.36", "status": "installed"},
            {"name": "auditd", "version": "1.0", "status": "installed"},
            {"name": "fail2ban", "version": "1.0", "status": "installed"},
        ],
        "repositories": [
            {"url": "http://archive.ubuntu.com", "suite": "jammy", "source": "sources.list"},
        ],
    },
    "processes": {
        "processes": [
            {"pid": 1, "name": "systemd", "binary": "/lib/systemd/systemd", "cmdline": "/sbin/init",
             "state": "S", "uid": 0, "ppid": 0, "memory_mbytes": 50},
            {"pid": 100, "name": "sshd", "binary": "/usr/sbin/sshd", "cmdline": "/usr/sbin/sshd -D",
             "state": "S", "uid": 0, "ppid": 1, "memory_mbytes": 10},
        ],
    },
    "filesystem": {
        "suid_files": [
            {"path": "/usr/bin/su", "mode": "0o104755", "uid": 0, "gid": 0, "size": 100},
        ],
        "world_writable": [
            {"path": "/tmp", "mode": "0o41777", "uid": 0, "is_dir": True},
        ],
        "capabilities": [],
    },
    "containers": {
        "docker": {
            "detailed": [
                {"id": "abc", "names": "nginx", "image": "nginx:1.25", "state": "running",
                 "privileged": False, "user": "", "cap_add": [], "cap_drop": [],
                 "security_opt": [], "bind_mounts": [], "created": "2026-07-01T00:00:00Z"},
            ],
        },
    },
    "cloud": {
        "on_cloud": False,
        "provider": None,
        "agents": {},
        "kubernetes": {"detected": False},
        "storage_tools": {},
    },
    "ssh_config": {
        "sshd_config": {
            "directives": {
                "protocol": "2",
                "permitrootlogin": "no",
                "kexalgorithms": "curve25519-sha256,diffie-hellman-group-exchange-sha256",
                "maxauthtries": "6",
                "permitemptypasswords": "no",
                "clientaliveinterval": "300",
                "clientalivecountmax": "3",
                "allowagentforwarding": "no",
                "pubkeyauthentication": "yes",
                "passwordauthentication": "no",
                "macs": "hmac-sha2-256,hmac-sha2-512",
            },
            "path": "/etc/ssh/sshd_config",
        },
        "host_keys": [
            {"type": "ssh-rsa", "size": 4096, "path": "/etc/ssh/ssh_host_rsa_key"},
        ],
    },
    "secrets": {
        "gitlab_tokens": [],
        "slack_tokens": [],
        "npm_tokens": [],
        "stripe_keys": [],
        "twilio_keys": [],
        "docker_creds": [],
        "azure_devops": [],
    },
}


class TestFilesystemIntegration:
    def test_fs601_passes_with_secure_perms(self):
        mock_stat_obj = type("MockStat", (), {
            "st_mode": 0o100640, "st_uid": 0, "st_gid": 0,
            "st_size": 100, "st_mtime": 1000.0, "st_atime": 1000.0,
            "st_ctime": 1000.0, "st_nlink": 1,
        })
        with (
            patch("usaf.checks.filesystem.fs_security_checks.Path.exists", return_value=True),
            patch("usaf.checks.filesystem.fs_security_checks.Path.stat", return_value=mock_stat_obj),
        ):
            result = SensitiveFilePermissionsCheck().evaluate(BASE_COLLECTORS)
            assert result.passed

    def test_fs604_passes_with_secure_mounts(self):
        result = TempDirMountSecurityCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_fs604_fails_with_insecure_mount(self):
        data = dict(BASE_COLLECTORS)
        data["mounts"] = {"mounts": [
            {"mount_point": "/tmp", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda1"},
        ]}
        result = TempDirMountSecurityCheck().evaluate(data)
        assert not result.passed


class TestBootIntegration:
    def test_boot602_passes_with_few_kernels(self):
        result = KernelImageCountCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_boot607_passes_with_secure_mounts(self):
        result = BootPartitionMountCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_boot607_fails_without_nosuid(self):
        data = dict(BASE_COLLECTORS)
        data["mounts"] = {"mounts": [
            {"mount_point": "/boot", "fstype": "ext4", "options": "rw,relatime", "device": "/dev/sda2"},
        ]}
        result = BootPartitionMountCheck().evaluate(data)
        assert not result.passed


class TestContainerIntegration:
    def test_ctn701_passes_with_no_extra_caps(self):
        result = ContainerAddedCapabilitiesCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_ctn703_passes_with_pinned_tag(self):
        result = ContainerLatestTagCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestCloudIntegration:
    def test_cld601_passes_without_cli_tools(self):
        result = CloudCliToolsCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_cld602_passes_without_env_creds(self):
        result = CloudEnvCredentialsCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestComplianceIntegration:
    def test_cmp201_passes_without_legacy(self):
        result = LegacyServicesCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_cmp203_passes_without_avahi(self):
        result = AvahiServiceCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestCompromiseIntegration:
    def test_com302_passes_with_clean_processes(self):
        result = ReverseShellDetectionCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_com305_passes_with_valid_binaries(self):
        result = HiddenProcessCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestKernelIntegration:
    def test_kern901_passes_with_aslr_2(self):
        result = KernelAslrCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_kern902_passes_without_debugfs(self):
        result = DebugFsCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_kern904_passes_with_sysrq_0(self):
        result = SysRqKeyCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestLoggingIntegration:
    def test_log606_passes_with_persistent_logging(self):
        result = JournaldRuntimeOnlyCheck().evaluate({
            "journald": {
                "config": {"storage": "auto"},
                "persistence": {"runtime_logs_only": False, "persistent_logs": True},
            },
        })
        assert result.passed

    def test_log601_passes_with_compression(self):
        result = JournaldCompressionCheck().evaluate({
            "journald": {"config": {"compress": True}},
        })
        assert result.passed

    def test_log602_passes_without_forwarding(self):
        result = JournaldForwardingCheck().evaluate({
            "journald": {"config": {"forward_to_kmsg": False, "forward_to_console": False}},
        })
        assert result.passed


class TestNetworkIntegration:
    def test_net701_passes_with_non_all(self):
        result = ListeningAllInterfacesCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_net701_fails_with_all_interfaces(self):
        data = dict(BASE_COLLECTORS)
        data["sockets"]["tcp"] = [{"local_address": "0.0.0.0", "local_port": 8080, "state": "LISTEN", "uid": 0}]
        result = ListeningAllInterfacesCheck().evaluate(data)
        assert not result.passed

    def test_net704_passes_without_exposed_udp(self):
        result = ExposedUdpServicesCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_net705_passes_with_root_ports(self):
        result = NonRootPrivilegedPortsCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_net709_passes_without_promisc(self):
        result = InterfacePromiscuousCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_net710_passes_with_consistent_dns(self):
        result = DnsResolverConfigCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_net708_passes_with_large_range(self):
        result = EphemeralPortExhaustionCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestPackagesIntegration:
    def test_pkg601_fails_with_many_missing(self):
        data = dict(BASE_COLLECTORS)
        data["apt"] = {"packages": [{"name": "coreutils"}]}
        result = MissingRecommendedPackagesCheck().evaluate(data)
        assert not result.passed

    def test_pkg602_passes_with_few_kernels(self):
        result = ObsoleteKernelPackagesCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_pkg603_passes_without_dev_pkgs(self):
        result = DevPackagesInstalledCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestPermissionsIntegration:
    def test_prm401_passes_with_secure_suid(self):
        result = GroupWritableSetuidCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_prm402_passes_without_sgid_ww(self):
        result = SGIDOnWorldWritableDirsCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_prm403_passes_without_caps(self):
        result = SetuidWithCapabilitiesCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestServicesIntegration:
    def test_svc601_passes_with_healthy_services(self):
        result = ServiceLoadFailuresCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_svc603_passes_with_matching_timers(self):
        result = TimerServiceMismatchCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestSSHIntegration:
    def test_ssh603_passes(self):
        result = SshAgentForwardingCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_ssh604_passes_with_proper_config(self):
        result = SshPubkeyAuthOnlyCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_ssh604_fails_with_password_auth(self):
        bad = dict(BASE_COLLECTORS)
        bad["ssh_config"]["sshd_config"]["directives"]["passwordauthentication"] = "yes"
        result = SshPubkeyAuthOnlyCheck().evaluate(bad)
        assert not result.passed

    def test_ssh601_passes_with_strong_macs(self):
        result = SshMacAlgorithmsCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestSecretsIntegration:
    def test_secr601_passes_without_tokens(self):
        result = GitlabTokensCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_secr602_passes_without_tokens(self):
        result = SlackTokensCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_secr606_passes_without_keys(self):
        result = StripeKeysCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestUsersIntegration:
    def test_usr501_passes_with_normal_users(self):
        result = ServiceAccountsWithShellCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_usr502_passes_without_excess_priv(self):
        result = UsersInPrivilegedGroupsCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_usr503_passes_with_current_passwords(self):
        result = InactiveUserAccountsCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_usr505_passes_with_populated_groups(self):
        result = EmptyGroupsCheck().evaluate(BASE_COLLECTORS)
        assert result.passed

    def test_usr507_passes_with_matching_gids(self):
        result = UidGidMismatchCheck().evaluate(BASE_COLLECTORS)
        assert result.passed


class TestSecurityIntegration:
    def test_sec204_fails_without_seccomp(self):
        with patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=False):
            result = SeccompStatusCheck().evaluate(BASE_COLLECTORS)
            assert not result.passed

    def test_sec205_passes_with_apparmor_in_stack(self):
        with (
            patch("usaf.checks.security.sec_security_checks.Path.exists", return_value=True),
            patch.object(Path, "read_text", return_value="lockdown,apparmor,yama"),
        ):
            result = LsmStackingCheck().evaluate(BASE_COLLECTORS)
            assert result.passed


class TestFWIntegration:
    def test_fw209_passes_with_ufw_enabled(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "enabled\n"
            mock_run.return_value.returncode = 0
            result = FirewallServiceBootCheck().evaluate(BASE_COLLECTORS)
            assert result.passed
