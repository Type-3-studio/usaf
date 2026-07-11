from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from usaf.collectors.packages.apt import APTCollector, get_package_for_file

DPKG_OUTPUT = """\
openssh-server\t1.0\tinstall ok installed\tamd64
ufw\t2.0\tinstall ok installed\tamd64
telnetd\t0.17\tinstall ok installed\tamd64
"""


class TestAPTCollector:
    def test_get_installed_packages(self):
        collector = APTCollector()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = DPKG_OUTPUT
            mock_run.return_value.returncode = 0
            data = collector.collect()

        assert len(data["packages"]) == 3
        assert data["packages"][0]["name"] == "openssh-server"
        assert data["packages"][0]["version"] == "1.0"
        assert data["packages"][0]["architecture"] == "amd64"

    def test_handles_subprocess_error(self):
        collector = APTCollector()
        with patch("subprocess.run", side_effect=OSError("not found")):
            data = collector.collect()
        assert data["packages"] == []


class TestGetPackageForFile:
    def setup_method(self):
        from usaf.collectors.packages import apt as apt_module
        apt_module._file_owner_cache = None

    def test_returns_none_for_unknown(self, monkeypatch):
        monkeypatch.setattr(Path, "is_dir", lambda p: True)
        monkeypatch.setattr(Path, "glob", lambda p, pattern: [])
        result = get_package_for_file("/usr/bin/unknown")
        assert result is None

    def test_returns_package_for_known_file(self, monkeypatch):
        class FakeListFile:
            stem = "openssh-server"
            def read_text(self):
                return "/usr/bin/ssh\n/etc/ssh/sshd_config\n"

        monkeypatch.setattr(Path, "is_dir", lambda p: True)
        monkeypatch.setattr(Path, "glob", lambda p, pattern: [FakeListFile()])
        result = get_package_for_file("/usr/bin/ssh")
        assert result == "openssh-server"

    def test_handles_missing_info_dir(self, monkeypatch):
        monkeypatch.setattr(Path, "is_dir", lambda p: False)
        result = get_package_for_file("/usr/bin/ssh")
        assert result is None
