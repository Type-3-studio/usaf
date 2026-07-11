from __future__ import annotations

from pathlib import Path

from usaf.collectors.processes.procfs import ProcessCollector

FAKE_PROC_STATUS = """\
Name:	sshd
State:	S (sleeping)
Ppid:	1
Uid:	0	0	0	0
Gid:	0	0	0	0
Threads:	1
VmRSS:	5120 kB
"""


class TestProcessCollector:
    def test_get_process_info(self, monkeypatch):
        def fake_is_dir(p):
            s = str(p)
            return s.endswith("/proc") or "/proc/" in s

        def fake_iterdir(_):
            return [type("Entry", (), {"name": "1", "isdigit": lambda: True})()]

        def fake_read_text(p):
            s = str(p)
            if s.endswith("/status"):
                return FAKE_PROC_STATUS
            return ""

        def fake_read_bytes(p):
            return b"/usr/sbin/sshd\x00-D\x00"

        monkeypatch.setattr(Path, "is_dir", fake_is_dir)
        monkeypatch.setattr(Path, "iterdir", fake_iterdir)
        monkeypatch.setattr(Path, "read_text", fake_read_text)
        monkeypatch.setattr(Path, "read_bytes", fake_read_bytes)

        monkeypatch.setattr(Path, "resolve", lambda _: Path("/usr/sbin/sshd"))

        collector = ProcessCollector()
        data = collector.collect()

        assert len(data["processes"]) >= 1
        proc = data["processes"][0]
        assert proc["pid"] == 1
        assert proc["name"] == "sshd"
        assert proc["state"] == "S (sleeping)"
        assert proc["ppid"] == 1
        assert proc["uid"] == 0
        assert proc["threads"] == 1
        assert proc["vm_rss_kb"] == 5120
        assert proc["binary"] == "/usr/sbin/sshd"

    def test_handles_os_error(self, monkeypatch):
        def fake_is_dir(p):
            s = str(p)
            return s.endswith("/proc") or "/proc/" in s

        def fake_iterdir(_):
            return [type("Entry", (), {"name": "1", "isdigit": lambda: True})()]

        monkeypatch.setattr(Path, "is_dir", fake_is_dir)
        monkeypatch.setattr(Path, "iterdir", fake_iterdir)
        monkeypatch.setattr(Path, "read_text", lambda _: (_ for _ in ()).throw(OSError))

        collector = ProcessCollector()
        data = collector.collect()
        assert len(data["processes"]) == 0

    def test_empty_when_no_proc(self, monkeypatch):
        monkeypatch.setattr(Path, "iterdir", lambda p: iter([]))
        monkeypatch.setattr(Path, "is_dir", lambda p: True)

        collector = ProcessCollector()
        data = collector.collect()
        assert len(data["processes"]) == 0
