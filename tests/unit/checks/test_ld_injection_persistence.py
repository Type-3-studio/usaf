from __future__ import annotations

from usaf.checks.persistence.ld_injection_persistence import (
    LdLibraryPathAnomalyCheck,
    LdPreloadEnvironmentCheck,
    LdSoPreloadCheck,
)
from usaf.models.severity import Severity


class TestLdPreloadEnvironmentCheck:
    def test_passes_with_no_processes(self):
        check = LdPreloadEnvironmentCheck()
        result = check.evaluate({"processes": {"processes": []}})
        assert result.passed

    def test_passes_without_ld_preload(self):
        check = LdPreloadEnvironmentCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 1, "name": "systemd", "environment": {}}]
            }
        })
        assert result.passed

    def test_fails_with_ld_preload(self):
        check = LdPreloadEnvironmentCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 100, "name": "bash", "binary": "/bin/bash", "environment": {"LD_PRELOAD": "/tmp/malicious.so"}}]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_ld_preload_case_insensitive(self):
        check = LdPreloadEnvironmentCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 101, "name": "zsh", "environment": {"ld_preload": "/tmp/hook.so"}}]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_string_environment(self):
        check = LdPreloadEnvironmentCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 102, "name": "python", "environment": "LD_PRELOAD=/tmp/inject.so\nPATH=/usr/bin"}]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_detects_multiple_preload_processes(self):
        check = LdPreloadEnvironmentCheck()
        result = check.evaluate({
            "processes": {
                "processes": [
                    {"pid": 100, "name": "bash", "environment": {"LD_PRELOAD": "/tmp/a.so"}},
                    {"pid": 200, "name": "zsh", "environment": {"LD_PRELOAD": "/tmp/b.so"}},
                    {"pid": 300, "name": "systemd", "environment": {}},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_has_mitre_mapping(self):
        check = LdPreloadEnvironmentCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 100, "name": "bash", "binary": "/bin/bash", "environment": {"LD_PRELOAD": "/tmp/malicious.so"}}]
            }
        })
        assert len(result.findings) > 0
        assert len(result.findings[0].mitre_attack_ids) > 0


class TestLdSoPreloadCheck:
    def test_passes_with_no_preload_file(self):
        check = LdSoPreloadCheck()
        result = check.evaluate({})
        assert result.passed

    def test_has_mitre_mapping(self):
        check = LdSoPreloadCheck()
        result = check.evaluate({})
        assert all(len(f.mitre_attack_ids) > 0 for f in result.findings)


class TestLdLibraryPathAnomalyCheck:
    def test_passes_with_no_processes(self):
        check = LdLibraryPathAnomalyCheck()
        result = check.evaluate({"processes": {"processes": []}})
        assert result.passed

    def test_passes_without_ld_library_path(self):
        check = LdLibraryPathAnomalyCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 1, "name": "systemd", "environment": {}}]
            }
        })
        assert result.passed

    def test_passes_with_standard_ld_library_path(self):
        check = LdLibraryPathAnomalyCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 1, "name": "app", "environment": {"LD_LIBRARY_PATH": "/usr/lib/x86_64-linux-gnu:/usr/lib"}}]
            }
        })
        assert result.passed

    def test_fails_with_nonstandard_ld_library_path(self):
        check = LdLibraryPathAnomalyCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 200, "name": "app", "binary": "/usr/bin/app", "environment": {"LD_LIBRARY_PATH": "/tmp/malicious"}}]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_tmp_directory_in_path(self):
        check = LdLibraryPathAnomalyCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 201, "name": "app", "environment": {"LD_LIBRARY_PATH": "/usr/lib:/tmp/hacked"}}]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_string_environment(self):
        check = LdLibraryPathAnomalyCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 202, "name": "python", "environment": "LD_LIBRARY_PATH=/opt/malicious\nPATH=/usr/bin"}]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_has_mitre_mapping(self):
        check = LdLibraryPathAnomalyCheck()
        result = check.evaluate({
            "processes": {
                "processes": [{"pid": 200, "name": "app", "binary": "/usr/bin/app", "environment": {"LD_LIBRARY_PATH": "/tmp/malicious"}}]
            }
        })
        assert len(result.findings) > 0
        assert len(result.findings[0].mitre_attack_ids) > 0
