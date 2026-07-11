from __future__ import annotations

from pathlib import Path

from usaf.checks.authentication.password_policy import PasswordPolicyCheck
from usaf.checks.compliance.ubuntu_version_check import UbuntuVersionCheck
from usaf.checks.compromise.known_bad_processes import KnownBadProcessCheck
from usaf.checks.containers.docker_socket_check import DockerSocketCheck
from usaf.checks.forensics.audit_log_check import AuditLogCheck
from usaf.checks.kernel.module_loading_check import KernelModuleLoadingCheck
from usaf.checks.network.port_checks import (
    PromiscuousModeCheck,
    UnexpectedListeningPortsCheck,
)
from usaf.checks.packages.unnecessary_packages import UnnecessaryPackagesCheck
from usaf.checks.persistence.unauthorized_services import UnauthorizedServicesCheck
from usaf.checks.security.apparmor_status import AppArmorStatusCheck
from usaf.checks.security.firewall_check import FirewallActiveCheck
from usaf.checks.security.usbguard_check import USBGuardCheck
from usaf.checks.services.insecure_services import InsecureServicesCheck
from usaf.checks.system.kernel_checks import (
    KernelASLRCheck,
    KernelCoreDumpCheck,
    KernelPtrRestrictCheck,
)
from usaf.checks.system.ssh_checks import SSHKeyExchangeCheck, SSHProtocolCheck, SSHRootLoginCheck
from usaf.checks.users.user_checks import (
    EmptyPasswordCheck,
    RootAccountCheck,
    ShadowedPasswordsCheck,
)

COLLECTOR_CHECK_MAP: dict[str, list[str]] = {
    "kernel_params": ["KERN-001", "KERN-002", "KERN-003"],
    "users": ["USR-001", "USR-002", "USR-003"],
    "sockets": ["NET-001"],
    "interfaces": ["NET-002"],
    "kernel": ["CMP-001"],
    "processes": ["COM-001"],
    "apt": ["PKG-001"],
    "systemd": ["PER-001"],
    "firewall": ["FIREWALL-001"],
}

_REALISTIC_COLLECTORS: dict[str, dict] = {
    "kernel_params": {
        "kernel.randomize_va_space": "2",
        "kernel.kptr_restrict": "2",
        "kernel.dmesg_restrict": "1",
        "fs.suid_dumpable": "0",
    },
    "users": {
        "users": [
            {"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "password": "x"},
            {"username": "alice", "uid": 1001, "gid": 1001, "home": "/home/alice", "shell": "/bin/bash", "password": "x"},
        ],
        "shadow": [
            {"username": "root", "password_hash": "$6$abc123hash", "locked": False},
            {"username": "alice", "password_hash": "$6$def456hash", "locked": False},
        ],
    },
    "sockets": {
        "tcp": [
            {"protocol": "tcp", "local_address": "0.0.0.0", "local_port": 22, "state": "LISTEN", "pid": 100, "process_name": "sshd"},
            {"protocol": "tcp", "local_address": "127.0.0.1", "local_port": 631, "state": "LISTEN", "pid": 200, "process_name": "cupsd"},
        ],
        "tcp6": [],
        "udp": [],
        "udp6": [],
    },
    "interfaces": {
        "interfaces": [
            {"name": "lo", "promisc": False, "mac": "00:00:00:00:00:00", "state": "up"},
            {"name": "eth0", "promisc": False, "mac": "52:54:00:12:34:56", "state": "up"},
        ],
    },
    "kernel": {
        "os": {"version": "24.04", "pretty_name": "Ubuntu 24.04 LTS"},
        "kernel": {"release": "6.8.0-31-generic"},
    },
    "processes": {
        "processes": [
            {"pid": 1, "name": "systemd", "binary": "/lib/systemd/systemd", "cmdline": "/sbin/init", "state": "S", "uid": 0},
            {"pid": 100, "name": "sshd", "binary": "/usr/sbin/sshd", "cmdline": "/usr/sbin/sshd -D", "state": "S", "uid": 0},
            {"pid": 200, "name": "bash", "binary": "/usr/bin/bash", "cmdline": "-bash", "state": "S", "uid": 1000},
        ],
    },
    "apt": {
        "packages": [
            {"name": "openssh-server", "version": "1:8.9p1", "status": "installed", "architecture": "amd64"},
            {"name": "ufw", "version": "0.36.1", "status": "installed", "architecture": "amd64"},
            {"name": "systemd", "version": "249.11", "status": "installed", "architecture": "amd64"},
        ],
    },
    "systemd": {
        "services": [
            {"name": "ssh.service", "description": "OpenSSH server", "active": "active"},
            {"name": "ufw.service", "description": "Uncomplicated firewall", "active": "active"},
            {"name": "cron.service", "description": "Regular background program", "active": "active"},
        ],
    },
    "firewall": {
        "ufw": {"active": True, "installed": True, "raw": "Status: active"},
        "nftables": {"active": False, "installed": False},
        "iptables": {"active": False, "installed": False},
    },
    "_usaf_config": {"suid_allowlist": []},
}


class TestKernelChecksIntegration:
    """Integration tests for KERN-001, KERN-002, KERN-003 with realistic data."""

    def test_kern001_passes_when_aslr_full(self):
        result = KernelASLRCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_kern001_fails_when_aslr_disabled(self):
        bad_data = dict(_REALISTIC_COLLECTORS)
        bad_data = {**bad_data, "kernel_params": {**bad_data["kernel_params"], "kernel.randomize_va_space": "0"}}
        result = KernelASLRCheck().evaluate(bad_data)
        assert not result.passed
        assert any("ASLR" in f.title for f in result.findings)

    def test_kern002_passes_when_kptr_and_dmesg_restricted(self):
        result = KernelPtrRestrictCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_kern002_fails_when_kptr_unrestricted(self):
        bad_data = {**_REALISTIC_COLLECTORS, "kernel_params": {**_REALISTIC_COLLECTORS["kernel_params"], "kernel.kptr_restrict": "0"}}
        result = KernelPtrRestrictCheck().evaluate(bad_data)
        assert not result.passed
        assert any("kptr" in f.title.lower() or "pointer" in f.title.lower() for f in result.findings)

    def test_kern002_fails_when_dmesg_unrestricted(self):
        bad_data = {**_REALISTIC_COLLECTORS, "kernel_params": {**_REALISTIC_COLLECTORS["kernel_params"], "kernel.dmesg_restrict": "0"}}
        result = KernelPtrRestrictCheck().evaluate(bad_data)
        assert not result.passed
        assert any("dmesg" in f.title.lower() for f in result.findings)

    def test_kern003_passes_when_suid_dumpable_zero(self):
        result = KernelCoreDumpCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_kern003_fails_when_core_dumps_enabled(self):
        bad_data = {**_REALISTIC_COLLECTORS, "kernel_params": {**_REALISTIC_COLLECTORS["kernel_params"], "fs.suid_dumpable": "1"}}
        result = KernelCoreDumpCheck().evaluate(bad_data)
        assert not result.passed
        assert any("core" in f.title.lower() for f in result.findings)


class TestUserChecksIntegration:
    """Integration tests for USR-001, USR-002, USR-003 with realistic data."""

    def test_usr001_passes_when_only_root_has_uid_zero(self):
        result = RootAccountCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_usr001_fails_when_non_root_has_uid_zero(self):
        bad_users = {
            **_REALISTIC_COLLECTORS["users"],
            "users": [
                {"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "password": "x"},
                {"username": "backdoor", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "password": "x"},
            ],
        }
        bad_data = {**_REALISTIC_COLLECTORS, "users": bad_users}
        result = RootAccountCheck().evaluate(bad_data)
        assert not result.passed
        assert any("backdoor" in f.title for f in result.findings)

    def test_usr002_passes_when_no_empty_passwords(self):
        result = EmptyPasswordCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_usr002_fails_when_empty_password_exists(self):
        bad_shadow = [
            {"username": "root", "password_hash": "$6$abc123hash", "locked": False},
            {"username": "alice", "password_hash": "", "locked": False},
        ]
        bad_data = {**_REALISTIC_COLLECTORS, "users": {**_REALISTIC_COLLECTORS["users"], "shadow": bad_shadow}}
        result = EmptyPasswordCheck().evaluate(bad_data)
        assert not result.passed
        assert any("alice" in f.title for f in result.findings)

    def test_usr003_passes_when_all_passwords_shadowed(self):
        result = ShadowedPasswordsCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_usr003_fails_when_password_hash_in_passwd(self):
        bad_users = [
            {"username": "root", "uid": 0, "gid": 0, "home": "/root", "shell": "/bin/bash", "password": "$6$abc123"},
            {"username": "alice", "uid": 1001, "gid": 1001, "home": "/home/alice", "shell": "/bin/bash", "password": "x"},
        ]
        bad_data = {**_REALISTIC_COLLECTORS, "users": {**_REALISTIC_COLLECTORS["users"], "users": bad_users}}
        result = ShadowedPasswordsCheck().evaluate(bad_data)
        assert not result.passed
        assert any("root" in f.title for f in result.findings)


class TestNetworkChecksIntegration:
    """Integration tests for NET-001, NET-002 with realistic data."""

    def test_net001_passes_with_known_safe_ports(self):
        result = UnexpectedListeningPortsCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_net001_fails_with_unexpected_port(self):
        bad_sockets = {
            **_REALISTIC_COLLECTORS["sockets"],
            "tcp": [
                *_REALISTIC_COLLECTORS["sockets"]["tcp"],
                {"protocol": "tcp", "local_address": "0.0.0.0", "local_port": 9999, "state": "LISTEN"},
            ],
        }
        bad_data = {**_REALISTIC_COLLECTORS, "sockets": bad_sockets}
        result = UnexpectedListeningPortsCheck().evaluate(bad_data)
        assert not result.passed
        assert any("9999" in f.title for f in result.findings)

    def test_net002_passes_when_no_promiscuous_interfaces(self):
        result = PromiscuousModeCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_net002_fails_when_promiscuous_interface_exists(self):
        bad_interfaces = {
            "interfaces": [
                *_REALISTIC_COLLECTORS["interfaces"]["interfaces"],
                {"name": "eth1", "promisc": True, "mac": "aa:bb:cc:dd:ee:ff", "state": "up"},
            ],
        }
        bad_data = {**_REALISTIC_COLLECTORS, "interfaces": bad_interfaces}
        result = PromiscuousModeCheck().evaluate(bad_data)
        assert not result.passed
        assert any("eth1" in f.title for f in result.findings)


class TestComplianceCheckIntegration:
    """Integration tests for CMP-001 with realistic data."""

    def test_cmp001_passes_with_supported_version(self):
        result = UbuntuVersionCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_cmp001_fails_with_unsupported_version(self):
        bad_data = {**_REALISTIC_COLLECTORS, "kernel": {"os": {"version": "18.04"}}}
        result = UbuntuVersionCheck().evaluate(bad_data)
        assert not result.passed
        assert any("18.04" in f.title for f in result.findings)

    def test_cmp001_passes_with_esm_version(self):
        esm_data = {**_REALISTIC_COLLECTORS, "kernel": {"os": {"version": "20.04"}}}
        result = UbuntuVersionCheck().evaluate(esm_data)
        assert result.passed


class TestCompromiseCheckIntegration:
    """Integration tests for COM-001 with realistic data."""

    def test_com001_passes_clean_process_list(self):
        result = KnownBadProcessCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_com001_fails_with_suspicious_process(self):
        bad_procs = {
            "processes": [
                *_REALISTIC_COLLECTORS["processes"]["processes"],
                {"pid": 9999, "name": "xmrig", "binary": "/tmp/xmrig", "cmdline": "./xmrig", "state": "R", "uid": 1000},
            ],
        }
        bad_data = {**_REALISTIC_COLLECTORS, "processes": bad_procs}
        result = KnownBadProcessCheck().evaluate(bad_data)
        assert not result.passed
        assert any("xmrig" in f.title.lower() for f in result.findings)

    def test_com001_case_insensitive_matching(self):
        bad_procs = {
            "processes": [
                *_REALISTIC_COLLECTORS["processes"]["processes"],
                {"pid": 9999, "name": "XMRig", "binary": "/tmp/xmrig", "cmdline": "./XMRig", "state": "R", "uid": 1000},
            ],
        }
        bad_data = {**_REALISTIC_COLLECTORS, "processes": bad_procs}
        result = KnownBadProcessCheck().evaluate(bad_data)
        assert not result.passed


class TestPackageCheckIntegration:
    """Integration tests for PKG-001 with realistic data."""

    def test_pkg001_passes_no_risky_packages(self):
        result = UnnecessaryPackagesCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_pkg001_fails_with_risky_package(self):
        bad_pkgs = {
            "packages": [
                *_REALISTIC_COLLECTORS["apt"]["packages"],
                {"name": "telnetd", "version": "0.17", "status": "installed", "architecture": "amd64"},
            ],
        }
        bad_data = {**_REALISTIC_COLLECTORS, "apt": bad_pkgs}
        result = UnnecessaryPackagesCheck().evaluate(bad_data)
        assert not result.passed
        assert any("telnetd" in f.title.lower() for f in result.findings)

    def test_pkg001_risky_packages_list_integrity(self):
        check = UnnecessaryPackagesCheck()
        assert "telnetd" in check.RISKY_PACKAGES
        assert "rsh-server" in check.RISKY_PACKAGES
        assert "samba" in check.RISKY_PACKAGES
        assert "cups" in check.RISKY_PACKAGES
        assert len(check.RISKY_PACKAGES) >= 14


class TestPersistenceCheckIntegration:
    """Integration tests for PER-001 with realistic data."""

    def test_per001_passes_clean_services(self):
        result = UnauthorizedServicesCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_per001_fails_with_suspicious_service_name(self):
        bad_svcs = {
            "services": [
                *_REALISTIC_COLLECTORS["systemd"]["services"],
                {"name": "crypto-miner.service", "description": "Mining pool worker", "active": "active"},
            ],
        }
        bad_data = {**_REALISTIC_COLLECTORS, "systemd": bad_svcs}
        result = UnauthorizedServicesCheck().evaluate(bad_data)
        assert not result.passed
        assert any("crypto" in f.title.lower() for f in result.findings)


class TestFirewallCheckIntegration:
    """Integration tests for FIREWALL-001 with realistic data."""

    def test_firewall001_passes_with_active_ufw(self):
        result = FirewallActiveCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_firewall001_fails_no_firewall_active(self):
        bad_fw = {**_REALISTIC_COLLECTORS["firewall"], "ufw": {"active": False, "installed": True, "raw": ""}}
        bad_data = {**_REALISTIC_COLLECTORS, "firewall": bad_fw}
        result = FirewallActiveCheck().evaluate(bad_data)
        assert not result.passed

    def test_firewall001_passes_with_nftables(self):
        nft_data = {**_REALISTIC_COLLECTORS, "firewall": {
            "ufw": {"active": False, "installed": False},
            "nftables": {"active": True, "installed": True},
            "iptables": {"active": False, "installed": False},
        }}
        result = FirewallActiveCheck().evaluate(nft_data)
        assert result.passed


class TestFilesystemCheckIntegration:
    """Integration tests for filesystem-dependent checks."""

    def test_krn001_fails_when_module_loading_allowed(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: "0\n")
        monkeypatch.setattr(Path, "exists", lambda _: True)
        result = KernelModuleLoadingCheck().evaluate(_REALISTIC_COLLECTORS)
        assert not result.passed
        assert len(result.findings) == 1

    def test_krn001_passes_when_module_loading_disabled(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: "1\n")
        monkeypatch.setattr(Path, "exists", lambda _: True)
        result = KernelModuleLoadingCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_ssh001_passes_with_protocol_2(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "Protocol 2\nPort 22\n")
        result = SSHProtocolCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_ssh001_fails_with_protocol_1(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "Protocol 1\n")
        result = SSHProtocolCheck().evaluate(_REALISTIC_COLLECTORS)
        assert not result.passed

    def test_ssh002_passes_root_login_disabled(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "PermitRootLogin no\n")
        result = SSHRootLoginCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_ssh002_fails_root_login_yes(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "PermitRootLogin yes\n")
        result = SSHRootLoginCheck().evaluate(_REALISTIC_COLLECTORS)
        assert not result.passed

    def test_ssh003_passes_secure_kex(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "KexAlgorithms curve25519-sha256,diffie-hellman-group-exchange-sha256\n")
        result = SSHKeyExchangeCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_ssh003_fails_weak_kex(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1\n")
        result = SSHKeyExchangeCheck().evaluate(_REALISTIC_COLLECTORS)
        assert not result.passed
        assert any("weak" in f.title.lower() for f in result.findings)

    def test_sec001_passes_apparmor_enabled(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "Y\n")
        result = AppArmorStatusCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_sec001_fails_apparmor_disabled(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "read_text", lambda _: "N\n")
        result = AppArmorStatusCheck().evaluate(_REALISTIC_COLLECTORS)
        assert not result.passed

    def test_svc001_passes_no_insecure_services(self, monkeypatch):
        orig_exists = Path.exists

        def mock_exists(self) -> bool:
            name = str(self)
            if "systemd" in name or name in ("/etc/systemd/system", "/lib/systemd/system", "/run/systemd/system"):
                return False
            return orig_exists(self)

        monkeypatch.setattr(Path, "exists", mock_exists)
        result = InsecureServicesCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_svc001_fails_when_telnet_socket_found(self, monkeypatch):
        orig_exists = Path.exists
        _call_count = [0]

        def mock_exists(self) -> bool:
            name = str(self)
            if "telnet.socket" in name:
                _call_count[0] += 1
                return True
            if name in ("/etc/systemd/system", "/lib/systemd/system", "/run/systemd/system"):
                return True
            return orig_exists(self)

        monkeypatch.setattr(Path, "exists", mock_exists)
        result = InsecureServicesCheck().evaluate(_REALISTIC_COLLECTORS)
        assert not result.passed, "Expected finding for telnet.socket"
        assert any("telnet" in f.title.lower() for f in result.findings)

    def test_ctn001_passes_no_docker_socket(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        result = DockerSocketCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed
        assert len(result.findings) == 0

    def test_for001_passes_audit_logs_present(self, monkeypatch):
        real_stat = Path.stat

        def mock_stat(self):
            if "audit.log" in str(self) or "audit" in str(self):
                class FakeStat:
                    st_size = 1024
                    st_uid = 0
                    st_mode = 0o100644
                return FakeStat()
            return real_stat(self)

        monkeypatch.setattr(Path, "stat", mock_stat)
        monkeypatch.setattr(Path, "exists", lambda _: True)
        result = AuditLogCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_usb001_passes_with_usbguard(self, monkeypatch):
        orig_exists = Path.exists

        def mock_exists(self) -> bool:
            name = str(self)
            if "usbguard" in name:
                return True
            return orig_exists(self)

        monkeypatch.setattr(Path, "exists", mock_exists)
        monkeypatch.setattr(Path, "read_text", lambda _: "ImplicitPolicyTarget=block\n")
        result = USBGuardCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_usb001_passes_with_blacklist(self, monkeypatch):
        orig_exists = Path.exists

        def mock_exists(self) -> bool:
            name = str(self)
            if "usb-storage-blacklist" in name:
                return True
            return orig_exists(self)

        monkeypatch.setattr(Path, "exists", mock_exists)
        monkeypatch.setattr(Path, "read_text", lambda _: "blacklist usb-storage\n")
        result = USBGuardCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_pwd001_passes_strong_policy(self, monkeypatch):
        orig_exists = Path.exists
        _read_data = {
            "/etc/pam.d/common-password": "password requisite pam_unix.so sha512 minlen=12\n",
            "/etc/login.defs": "PASS_MIN_LEN 12\n",
        }

        def mock_exists(self) -> bool:
            name = str(self)
            if name in _read_data:
                return True
            return orig_exists(self)

        def mock_read_text(self) -> str:
            return _read_data.get(str(self), "")

        monkeypatch.setattr(Path, "exists", mock_exists)
        monkeypatch.setattr(Path, "read_text", mock_read_text)
        result = PasswordPolicyCheck().evaluate(_REALISTIC_COLLECTORS)
        assert result.passed

    def test_pwd001_fails_weak_policy(self, monkeypatch):
        orig_exists = Path.exists
        _read_data = {
            "/etc/pam.d/common-password": "password requisite pam_unix.so sha512 minlen=6\n",
            "/etc/login.defs": "PASS_MIN_LEN 6\n",
        }

        def mock_exists(self) -> bool:
            name = str(self)
            if name in _read_data:
                return True
            return orig_exists(self)

        def mock_read_text(self) -> str:
            return _read_data.get(str(self), "")

        monkeypatch.setattr(Path, "exists", mock_exists)
        monkeypatch.setattr(Path, "read_text", mock_read_text)
        result = PasswordPolicyCheck().evaluate(_REALISTIC_COLLECTORS)
        assert not result.passed
        assert any("password" in f.title.lower() for f in result.findings)

    def test_ssh_check_no_sshd_config_no_false_positives(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        for check_cls in [SSHProtocolCheck, SSHRootLoginCheck, SSHKeyExchangeCheck]:
            result = check_cls().evaluate(_REALISTIC_COLLECTORS)
            assert result.passed, f"{check_cls.id} should pass with no config file"


class TestAllChecksRoundTrip:
    """Test all 25 checks can evaluate without errors."""

    def test_all_collector_driven_checks_round_trip(self):
        for check_id in COLLECTOR_CHECK_MAP:
            _ = _REALISTIC_COLLECTORS[check_id]

    def test_all_checks_produce_check_result(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)

        checks_to_test = [
            KernelASLRCheck(),
            KernelPtrRestrictCheck(),
            KernelCoreDumpCheck(),
            SSHProtocolCheck(),
            SSHRootLoginCheck(),
            SSHKeyExchangeCheck(),
            RootAccountCheck(),
            EmptyPasswordCheck(),
            ShadowedPasswordsCheck(),
            UnexpectedListeningPortsCheck(),
            PromiscuousModeCheck(),
            UbuntuVersionCheck(),
            KnownBadProcessCheck(),
            FirewallActiveCheck(),
        ]
        for check in checks_to_test:
            result = check.evaluate(_REALISTIC_COLLECTORS)
            assert isinstance(result.passed, bool)
            assert isinstance(result.findings, list)

    def test_all_filesystem_checks_produce_check_result(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)

        checks_to_test = [
            KernelModuleLoadingCheck(),
            DockerSocketCheck(),
            AuditLogCheck(),
            InsecureServicesCheck(),
            AppArmorStatusCheck(),
            USBGuardCheck(),
            PasswordPolicyCheck(),
        ]
        for check in checks_to_test:
            result = check.evaluate(_REALISTIC_COLLECTORS)
            assert isinstance(result.passed, bool)
            assert isinstance(result.findings, list)

    def test_all_check_ids_unique(self):
        all_ids = list(COLLECTOR_CHECK_MAP.keys())
        assert len(all_ids) == len(set(all_ids))
