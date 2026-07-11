from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.collectors.system.kernel import KernelCollector, KernelParametersCollector


class TestKernelCollector:
    def test_parse_sysctl(self, monkeypatch):
        def fake_read_text(p):
            if str(p).endswith("kernel/hostname"):
                return "testhost\n"
            if str(p).endswith("kernel/osrelease"):
                return "6.8.0\n"
            raise OSError("not found")

        monkeypatch.setattr(Path, "read_text", fake_read_text)

        with patch("platform.uname") as mock_uname:
            mock_uname.return_value.release = "6.8.0"
            mock_uname.return_value.version = "#1 SMP"
            mock_uname.return_value.machine = "x86_64"
            mock_uname.return_value.node = "testhost"
            mock_uname.return_value.system = "Linux"

            collector = KernelCollector()
            data = collector.collect()

        assert data["kernel"]["release"] == "6.8.0"
        assert data["kernel"]["node"] == "testhost"
        assert data["kernel"]["machine"] == "x86_64"
        assert data["sysctl"]["kernel.hostname"] == "testhost"

    def test_read_os_release(self, monkeypatch):
        os_release_content = 'NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n'

        def fake_read_text(p):
            if str(p).endswith("os-release"):
                return os_release_content
            if str(p).endswith("cmdline"):
                return "BOOT_IMAGE=/vmlinuz root=/dev/sda1\n"
            if str(p).endswith("kernel/hostname"):
                return "host\n"
            if str(p).endswith("stat"):
                return "btime 1234567890\n"
            raise OSError("not found")

        monkeypatch.setattr(Path, "read_text", fake_read_text)
        monkeypatch.setattr(Path, "exists", lambda p: True)

        with patch("platform.uname") as mock_uname:
            mock_uname.return_value.release = "6.8.0"
            mock_uname.return_value.version = "#1 SMP"
            mock_uname.return_value.machine = "x86_64"
            mock_uname.return_value.node = "testhost"
            mock_uname.return_value.system = "Linux"

            collector = KernelCollector()
            data = collector.collect()

        assert data["os"]["name"] == "Ubuntu"
        assert data["os"]["version"] == "24.04"
        assert data["os"]["id"] == "ubuntu"

    def test_read_os_release_fallback(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: (_ for _ in ()).throw(OSError))
        monkeypatch.setattr(Path, "exists", lambda p: True)
        with patch("platform.uname") as mock_uname:
            mock_uname.return_value.release = "6.8.0"
            mock_uname.return_value.version = "#1 SMP"
            mock_uname.return_value.machine = "x86_64"
            mock_uname.return_value.node = "testhost"
            mock_uname.return_value.system = "Linux"
            collector = KernelCollector()
            data = collector.collect()

        assert data["os"]["name"] == "Ubuntu"
        assert data["os"]["version"] == "unknown"

    def test_boot_time(self, monkeypatch):
        boot_time_data = {"timestamp": 1700000000.0}

        def fake_read(p):
            s = str(p)
            if s.endswith("os-release"):
                return 'NAME="Ubuntu"\nVERSION_ID="24.04"\n'
            if s.endswith("cmdline"):
                return "BOOT_IMAGE=/vmlinuz\n"
            if "kernel/hostname" in s:
                return "host\n"
            if "kernel/osrelease" in s:
                return "6.8.0\n"
            raise OSError("not found")

        monkeypatch.setattr(KernelCollector, "_get_boot_time", lambda self: boot_time_data)
        monkeypatch.setattr(Path, "read_text", fake_read)
        monkeypatch.setattr(Path, "exists", lambda _: True)

        with patch("platform.uname") as mock_uname:
            mock_uname.return_value.release = "6.8.0"
            mock_uname.return_value.version = "#1"
            mock_uname.return_value.machine = "x86_64"
            mock_uname.return_value.node = "h"
            mock_uname.return_value.system = "Linux"
            collector = KernelCollector()
            data = collector.collect()

        assert data["boot_time"]["timestamp"] == 1700000000.0


class TestKernelParametersCollector:
    def test_collects_security_params(self, monkeypatch):
        def fake_read_text(p):
            path_str = str(p)
            if "randomize_va_space" in path_str:
                return "2\n"
            if "kptr_restrict" in path_str:
                return "2\n"
            if "dmesg_restrict" in path_str:
                return "1\n"
            if "ip_forward" in path_str:
                return "0\n"
            raise OSError("not found")

        monkeypatch.setattr(Path, "read_text", fake_read_text)

        collector = KernelParametersCollector()
        data = collector.collect()

        assert data["kernel.randomize_va_space"] == "2"
        assert data["kernel.kptr_restrict"] == "2"
        assert data["net.ipv4.ip_forward"] == "0"

    def test_skips_unreadable_params(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: (_ for _ in ()).throw(OSError))
        collector = KernelParametersCollector()
        data = collector.collect()
        assert all(k.startswith("_") for k in data) or data == {}
