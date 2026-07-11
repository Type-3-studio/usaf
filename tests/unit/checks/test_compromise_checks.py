from __future__ import annotations

from usaf.checks.compromise.known_bad_processes import KnownBadProcessCheck
from usaf.models.severity import Confidence, Severity


class TestKnownBadProcessCheck:
    def test_passes_when_no_suspicious_processes(self):
        check = KnownBadProcessCheck()
        result = check.evaluate({"processes": {"processes": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_benign_processes(self):
        check = KnownBadProcessCheck()
        result = check.evaluate({
            "processes": {
                "processes": [
                    {"name": "sshd", "pid": 1, "uid": 0, "state": "S"},
                    {"name": "bash", "pid": 2, "uid": 1000, "state": "S"},
                ]
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_detects_known_malicious_process(self):
        check = KnownBadProcessCheck()
        result = check.evaluate({
            "processes": {
                "processes": [
                    {"name": "xmrig", "pid": 31337, "uid": 0, "state": "R", "binary": "/usr/bin/xmrig", "cmdline": "./xmrig"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "xmrig" in f.title
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.MEDIUM
        assert "T1496" in f.mitre_attack_ids

    def test_detects_multiple_malicious_processes(self):
        check = KnownBadProcessCheck()
        result = check.evaluate({
            "processes": {
                "processes": [
                    {"name": "xmrig", "pid": 100, "uid": 0, "state": "R"},
                    {"name": "minerd", "pid": 200, "uid": 0, "state": "R"},
                    {"name": "bash", "pid": 300, "uid": 1000, "state": "S"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_case_insensitive_matching(self):
        check = KnownBadProcessCheck()
        result = check.evaluate({
            "processes": {
                "processes": [
                    {"name": "XMRig", "pid": 42, "uid": 0, "state": "R"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_handles_missing_process_fields(self):
        check = KnownBadProcessCheck()
        result = check.evaluate({
            "processes": {
                "processes": [
                    {"name": "xmrig", "pid": 123},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
