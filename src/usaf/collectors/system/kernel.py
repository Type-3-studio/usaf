from __future__ import annotations

import platform
from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class KernelCollector(BaseCollector):
    """Collects kernel and system information."""

    name = "kernel"
    description = "Kernel version, parameters, and system info"

    def _do_collect(self) -> dict[str, dict[str, str | list[str] | bool]]:
        uname = platform.uname()
        sysctl_params = self._read_sysctl()
        cmdline = self._read_cmdline()

        return {
            "kernel": {
                "release": uname.release,
                "version": uname.version,
                "machine": uname.machine,
                "node": uname.node,
                "system": uname.system,
            },
            "os": {
                "name": self._read_os_release("NAME", "Ubuntu"),
                "version": self._read_os_release("VERSION_ID", "unknown"),
                "id": self._read_os_release("ID", "linux"),
            },
            "sysctl": sysctl_params,
            "cmdline": {"full": cmdline},
            "boot_time": self._get_boot_time(),
        }

    def _read_sysctl(self) -> dict[str, str]:
        params: dict[str, str] = {}
        keys = [
            "kernel.hostname",
            "kernel.osrelease",
            "kernel.ostype",
            "kernel.version",
        ]
        for key in keys:
            try:
                result = self._sysctl_get(key)
                params[key] = result
            except (OSError, FileNotFoundError):
                continue
        return params

    def _sysctl_get(self, key: str) -> str:
        path = Path("/proc/sys") / key.replace(".", "/")
        return path.read_text().strip()

    def _read_cmdline(self) -> str:
        try:
            return Path("/proc/cmdline").read_text().strip()
        except OSError:
            return ""

    def _read_os_release(self, key: str, default: str) -> str:
        try:
            for line in Path("/etc/os-release").read_text().splitlines():
                if line.startswith(f"{key}="):
                    return line.split("=", 1)[1].strip('"')
        except OSError:
            pass
        return default

    def _get_boot_time(self) -> dict[str, str | float]:
        try:
            with open("/proc/stat") as f:
                for line in f:
                    if line.startswith("btime "):
                        btime = float(line.split()[1])
                        return {"timestamp": btime}
        except OSError:
            pass
        return {}


@register_collector
class KernelParametersCollector(BaseCollector):
    """Collects security-relevant kernel parameters."""

    name = "kernel_params"
    description = "Security-relevant kernel parameters"
    depends = ["kernel"]

    def _do_collect(self) -> dict[str, str]:
        params: dict[str, str] = {}
        security_params = [
            "kernel.randomize_va_space",
            "kernel.kptr_restrict",
            "kernel.dmesg_restrict",
            "kernel.printk",
            "kernel.unprivileged_bpf_disabled",
            "kernel.yama.ptrace_scope",
            "kernel.core_uses_pid",
            "kernel.ctrl-alt-del",
            "net.ipv4.conf.all.rp_filter",
            "net.ipv4.conf.default.rp_filter",
            "net.ipv4.tcp_syncookies",
            "net.ipv4.ip_forward",
            "net.ipv4.conf.all.accept_source_route",
            "net.ipv4.conf.default.accept_source_route",
            "net.ipv4.conf.all.accept_redirects",
            "net.ipv4.conf.default.accept_redirects",
            "net.ipv4.conf.all.secure_redirects",
            "net.ipv4.conf.default.secure_redirects",
            "net.ipv4.conf.all.log_martians",
            "net.ipv4.conf.default.log_martians",
            "net.ipv4.icmp_echo_ignore_broadcasts",
            "net.ipv4.icmp_ignore_bogus_error_responses",
            "net.ipv4.tcp_rfc1337",
            "net.ipv6.conf.all.accept_ra",
            "net.ipv6.conf.all.accept_redirects",
            "net.ipv6.conf.all.disable_ipv6",
            "fs.suid_dumpable",
            "fs.protected_hardlinks",
            "fs.protected_symlinks",
            "fs.protected_regular",
            "fs.protected_fifos",
            "dev.tty.ldisc_autoload",
            "vm.mmap_min_addr",
            "vm.unprivileged_userfaultfd",
        ]
        for key in security_params:
            try:
                path = Path("/proc/sys") / key.replace(".", "/")
                params[key] = path.read_text().strip()
            except OSError:
                continue
        return params
