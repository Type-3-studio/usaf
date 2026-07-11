from __future__ import annotations

import io
import os

from usaf.checks.persistence.systemd_persistence import (
    SuspiciousSystemdTimersCheck,
    SystemdPathUnitsCheck,
    SystemdServiceDropinsCheck,
)
from usaf.models.severity import Confidence, Severity


class TestSuspiciousSystemdTimersCheck:

    def test_passes_with_no_timers(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({"systemd": {"timers": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_missing_timers_key(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({"systemd": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_known_safe_timers(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [
                    {"name": "apt-daily.timer", "active": "active"},
                    {"name": "fstrim.timer", "active": "active"},
                    {"name": "logrotate.timer", "active": "active"},
                ],
            },
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_suspicious_timer_name(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{"name": "backdoor.timer", "active": "active"}],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.id == "PER-202-001"
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.LOW
        assert f.false_positive_probability == 0.6

    def test_all_suspicious_patterns_detected(self):
        check = SuspiciousSystemdTimersCheck()
        patterns = ["backdoor", "reverse", "beacon", "implant", "miner", "crypto", "meterp", "proxy"]
        for pat in patterns:
            result = check.evaluate({
                "systemd": {
                    "timers": [{"name": f"{pat}.timer", "active": "active"}],
                },
            })
            assert not result.passed, f"pattern {pat!r} not detected"

    def test_suspicious_pattern_case_insensitive(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{"name": "BackDoor.timer", "active": "active"}],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_suspicious_timer_inactive_still_detected(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{"name": "backdoor.timer", "active": "inactive"}],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_detects_unknown_active_timer(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{"name": "my-custom-check.timer", "active": "active"}],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.id == "PER-202-002"
        assert "unknown" in f.title.lower()

    def test_skips_inactive_unknown_timers(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{"name": "my-custom-check.timer", "active": "inactive"}],
            },
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_suspicious_precedence_over_unknown(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [
                    {"name": "backdoor-custom.timer", "active": "active"},
                ],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert result.findings[0].id == "PER-202-001"

    def test_skips_known_timers_regardless_of_active_state(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [
                    {"name": "apt-daily.timer", "active": "active"},
                    {"name": "logrotate.timer", "active": "inactive"},
                ],
            },
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_skips_timers_with_no_name(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{}, {"active": "active"}],
            },
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_detects_multiple_suspicious_timers(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [
                    {"name": "backdoor.timer", "active": "active"},
                    {"name": "miner.timer", "active": "active"},
                    {"name": "apt-daily.timer", "active": "active"},
                ],
            },
        })
        assert not result.passed
        assert len(result.findings) == 2
        for f in result.findings:
            assert f.id == "PER-202-001"

    def test_mixes_suspicious_and_unknown_timers(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [
                    {"name": "backdoor.timer", "active": "active"},
                    {"name": "stranger.timer", "active": "active"},
                ],
            },
        })
        assert not result.passed
        assert len(result.findings) == 2
        ids = {f.id for f in result.findings}
        assert ids == {"PER-202-001", "PER-202-002"}

    def test_limits_unknown_timer_findings_to_five(self):
        check = SuspiciousSystemdTimersCheck()
        timers = [{"name": f"custom-{i}.timer", "active": "active"} for i in range(10)]
        result = check.evaluate({"systemd": {"timers": timers}})
        assert len(result.findings) == 5
        for f in result.findings:
            assert f.id == "PER-202-002"

    def test_unknown_timer_has_correct_properties(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{"name": "strange.timer", "active": "active"}],
            },
        })
        f = result.findings[0]
        assert f.confidence == Confidence.LOW
        assert f.false_positive_probability == 0.5
        assert f.severity == Severity.MEDIUM

    def test_suspicious_timer_has_mitre_mapping(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{"name": "backdoor.timer", "active": "active"}],
            },
        })
        assert "T1053.006" in result.findings[0].mitre_attack_ids

    def test_unknown_timer_has_mitre_mapping(self):
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{"name": "stranger.timer", "active": "active"}],
            },
        })
        assert "T1053.006" in result.findings[0].mitre_attack_ids

    def test_passes_with_many_known_timers(self):
        known = [
            "apt-daily.timer", "apt-daily-upgrade.timer", "dpkg-db-backup.timer",
            "e2scrub_all.timer", "fstrim.timer", "logrotate.timer",
            "man-db.timer", "motd-news.timer", "networkd-dispatcher.timer",
            "phc2sys.timer", "pollinate.timer", "plymouth-read-write.timer",
            "snapd.snap-repair.timer", "sysstat-collect.timer", "sysstat-summary.timer",
            "systemd-tmpfiles-clean.timer", "ua-timer.timer",
            "update-notifier-download.timer", "update-notifier-motd.timer",
        ]
        check = SuspiciousSystemdTimersCheck()
        result = check.evaluate({
            "systemd": {
                "timers": [{"name": n, "active": "active"} for n in known],
            },
        })
        assert result.passed
        assert len(result.findings) == 0


class TestSystemdServiceDropinsCheck:

    def test_passes_with_no_services(self):
        check = SystemdServiceDropinsCheck()
        result = check.evaluate({"systemd": {"services": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_dropin_dirs_missing(self, monkeypatch):
        monkeypatch.setattr(os.path, "isdir", lambda _: False)
        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "ssh.service", "active": "active"}],
            },
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_skips_override_conf(self, monkeypatch):
        dirs = {"/etc/systemd/system", "/etc/systemd/system/ssh.service.d"}
        listings = {
            "/etc/systemd/system": ["ssh.service.d"],
            "/etc/systemd/system/ssh.service.d": ["override.conf"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "ssh.service", "active": "active"}],
            },
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_detects_active_dropin_with_execstart(self, monkeypatch):
        dirs = {"/etc/systemd/system", "/etc/systemd/system/ssh.service.d"}
        listings = {
            "/etc/systemd/system": ["ssh.service.d"],
            "/etc/systemd/system/ssh.service.d": ["exec.conf"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Service]\nExecStart=/usr/bin/malicious\n",
        ))

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "ssh.service", "active": "active"}],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.id == "PER-203-001"
        assert "ssh.service" in f.title
        assert f.confidence == Confidence.MEDIUM
        assert f.false_positive_probability == 0.3
        assert f.severity == Severity.MEDIUM

    def test_detects_dropin_with_execstartpre(self, monkeypatch):
        dirs = {"/etc/systemd/system", "/etc/systemd/system/cups.service.d"}
        listings = {
            "/etc/systemd/system": ["cups.service.d"],
            "/etc/systemd/system/cups.service.d": ["pre.conf"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Service]\nExecStartPre=/usr/bin/steal-creds\n",
        ))

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "cups.service", "active": "active"}],
            },
        })
        assert not result.passed
        assert result.findings[0].id == "PER-203-001"

    def test_detects_dropin_with_execstartpost(self, monkeypatch):
        dirs = {"/etc/systemd/system", "/etc/systemd/system/sshd.service.d"}
        listings = {
            "/etc/systemd/system": ["sshd.service.d"],
            "/etc/systemd/system/sshd.service.d": ["post.conf"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Service]\nExecStartPost=/usr/bin/exfil\n",
        ))

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "sshd.service", "active": "active"}],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_inactive_dropin_uses_finding_id_002(self, monkeypatch):
        dirs = {"/etc/systemd/system", "/etc/systemd/system/ssh.service.d"}
        listings = {
            "/etc/systemd/system": ["ssh.service.d"],
            "/etc/systemd/system/ssh.service.d": ["exec.conf"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Service]\nExecStart=/usr/bin/malicious\n",
        ))

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "ssh.service", "active": "inactive"}],
            },
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.id == "PER-203-002"
        assert f.confidence == Confidence.LOW
        assert f.false_positive_probability == 0.6

    def test_does_not_flag_dropin_without_execstart(self, monkeypatch):
        dirs = {"/etc/systemd/system", "/etc/systemd/system/ssh.service.d"}
        listings = {
            "/etc/systemd/system": ["ssh.service.d"],
            "/etc/systemd/system/ssh.service.d": ["env.conf"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Service]\nEnvironment=FOO=bar\n",
        ))

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "ssh.service", "active": "active"}],
            },
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_handles_permission_error_on_listdir(self, monkeypatch):
        def mock_listdir(_):
            raise PermissionError
        monkeypatch.setattr(os.path, "isdir", lambda _: True)
        monkeypatch.setattr(os, "listdir", mock_listdir)

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "ssh.service", "active": "active"}],
            },
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_handles_oserror_on_open(self, monkeypatch):
        dirs = {"/etc/systemd/system", "/etc/systemd/system/ssh.service.d"}
        listings = {
            "/etc/systemd/system": ["ssh.service.d"],
            "/etc/systemd/system/ssh.service.d": ["exec.conf"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr("builtins.open", lambda *_: (_ for _ in ()).throw(PermissionError))

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "ssh.service", "active": "active"}],
            },
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_scans_etc_and_run_directories(self, monkeypatch):
        dirs = {
            "/etc/systemd/system", "/run/systemd/system",
            "/etc/systemd/system/ssh.service.d", "/run/systemd/system/ssh.service.d",
        }
        listings = {
            "/etc/systemd/system": ["ssh.service.d"],
            "/run/systemd/system": ["ssh.service.d"],
            "/etc/systemd/system/ssh.service.d": ["exec.conf"],
            "/run/systemd/system/ssh.service.d": ["malicious.conf"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Service]\nExecStart=/usr/bin/malicious\n",
        ))

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "ssh.service", "active": "active"}],
            },
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_active_dropin_has_mitre_mapping(self, monkeypatch):
        dirs = {"/etc/systemd/system", "/etc/systemd/system/ssh.service.d"}
        listings = {
            "/etc/systemd/system": ["ssh.service.d"],
            "/etc/systemd/system/ssh.service.d": ["exec.conf"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Service]\nExecStart=/usr/bin/malicious\n",
        ))

        check = SystemdServiceDropinsCheck()
        result = check.evaluate({
            "systemd": {
                "services": [{"name": "ssh.service", "active": "active"}],
            },
        })
        assert "T1543.002" in result.findings[0].mitre_attack_ids


class TestSystemdPathUnitsCheck:

    def test_passes_with_no_path_units(self, monkeypatch):
        monkeypatch.setattr(os.path, "isdir", lambda _: False)
        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_when_path_unit_dirs_missing(self, monkeypatch):
        monkeypatch.setattr(os.path, "isdir", lambda _: False)
        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_skips_known_path_units(self, monkeypatch):
        dirs = {"/etc/systemd/system"}
        listings = {
            "/etc/systemd/system": [
                "systemd-networkd-wait-online.service",
                "systemd-resolved.service",
            ],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_detects_unexpected_path_unit(self, monkeypatch):
        dirs = {"/etc/systemd/system"}
        listings = {"/etc/systemd/system": ["watcher.path"]}
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Path]\nPathModified=/var/log/auth.log\n",
        ))

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.id == "PER-204-001"
        assert "watcher.path" in f.title
        assert f.confidence == Confidence.LOW
        assert f.false_positive_probability == 0.5
        assert f.severity == Severity.MEDIUM

    def test_detects_pathchanged_trigger(self, monkeypatch):
        dirs = {"/etc/systemd/system"}
        listings = {"/etc/systemd/system": ["trigger.path"]}
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Path]\nPathChanged=/etc/shadow\n",
        ))

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert not result.passed
        assert len(result.findings) == 1

    def test_detects_pathexists_trigger(self, monkeypatch):
        dirs = {"/etc/systemd/system"}
        listings = {"/etc/systemd/system": ["exists.path"]}
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Path]\nPathExists=/tmp/malicious\n",
        ))

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert not result.passed
        assert len(result.findings) == 1

    def test_ignores_path_unit_without_monitoring_directive(self, monkeypatch):
        dirs = {"/etc/systemd/system"}
        listings = {"/etc/systemd/system": ["harmless.path"]}
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Unit]\nDescription=Harmless\n",
        ))

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_handles_permission_error_on_listdir(self, monkeypatch):
        def mock_listdir(_):
            raise PermissionError
        monkeypatch.setattr(os.path, "isdir", lambda _: True)
        monkeypatch.setattr(os, "listdir", mock_listdir)

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_handles_oserror_on_file_open(self, monkeypatch):
        dirs = {"/etc/systemd/system"}
        listings = {"/etc/systemd/system": ["watcher.path"]}
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)
        monkeypatch.setattr("builtins.open", lambda *_: (_ for _ in ()).throw(PermissionError))

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_scans_etc_usr_and_run_directories(self, monkeypatch):
        dirs = {
            "/etc/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system",
        }
        listings = {
            "/etc/systemd/system": ["w1.path"],
            "/usr/lib/systemd/system": ["w2.path"],
            "/run/systemd/system": ["w3.path"],
        }
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Path]\nPathModified=/var/log/auth.log\n",
        ))

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert not result.passed
        assert len(result.findings) == 3

    def test_skips_non_path_file_extensions(self, monkeypatch):
        dirs = {"/etc/systemd/system"}
        listings = {"/etc/systemd/system": ["ssh.service", "apt-daily.timer", "watcher.path"]}
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Path]\nPathModified=/var/log/auth.log\n",
        ))

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert not result.passed
        assert len(result.findings) == 1

    def test_ignores_known_path_units_even_with_triggers(self, monkeypatch):
        dirs = {"/usr/lib/systemd/system"}
        listings = {"/usr/lib/systemd/system": ["systemd-networkd-wait-online.service"]}
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Path]\nPathModified=/some/path\n",
        ))

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_path_unit_has_mitre_mapping(self, monkeypatch):
        dirs = {"/etc/systemd/system"}
        listings = {"/etc/systemd/system": ["watcher.path"]}
        monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
        monkeypatch.setattr(os, "listdir", lambda p: listings.get(p, []))
        monkeypatch.setattr(os.path, "isfile", lambda _: True)
        monkeypatch.setattr("builtins.open", lambda *_: io.StringIO(
            "[Path]\nPathModified=/var/log/auth.log\n",
        ))

        check = SystemdPathUnitsCheck()
        result = check.evaluate({"systemd": {}})
        assert "T1543.002" in result.findings[0].mitre_attack_ids
