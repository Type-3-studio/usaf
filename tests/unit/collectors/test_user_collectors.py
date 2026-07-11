from __future__ import annotations

from pathlib import Path

from usaf.collectors.users.passwd import GroupCollector, SudoCollector, UserCollector

FAKE_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bob:x:1000:1000:Bob,,,:/home/bob:/bin/bash
"""

FAKE_SHADOW = """\
root:$6$hash:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
bob:$6$hash2:19000:0:99999:7:::
"""

FAKE_GROUP = """\
root:x:0:
sudo:x:27:bob
docker:x:999:bob
bob:x:1000:
"""


class TestUserCollector:
    def test_parse_passwd(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: FAKE_PASSWD)

        collector = UserCollector()
        data = collector.collect()

        assert len(data["users"]) == 3
        assert data["users"][0]["username"] == "root"
        assert data["users"][0]["uid"] == 0
        assert data["users"][0]["shell"] == "/bin/bash"
        assert data["users"][2]["username"] == "bob"
        assert data["users"][2]["uid"] == 1000

    def test_parse_shadow(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: FAKE_SHADOW)

        collector = UserCollector()
        data = collector.collect()

        assert len(data["shadow"]) == 3
        assert data["shadow"][0]["username"] == "root"
        assert data["shadow"][0]["password_hash"] == "$6$hash"
        assert data["shadow"][0]["locked"] is False
        assert data["shadow"][1]["locked"] is True

    def test_handles_os_error(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: (_ for _ in ()).throw(OSError))

        collector = UserCollector()
        data = collector.collect()

        assert data["users"] == []
        assert data["shadow"] == []


class TestGroupCollector:
    def test_parse_groups(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: FAKE_GROUP)

        collector = GroupCollector()
        data = collector.collect()

        assert len(data["groups"]) == 4
        assert data["groups"][0]["name"] == "root"
        assert data["groups"][1]["name"] == "sudo"
        assert data["groups"][1]["members"] == ["bob"]

    def test_handles_os_error(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: (_ for _ in ()).throw(OSError))

        collector = GroupCollector()
        data = collector.collect()
        assert data["groups"] == []


class TestSudoCollector:
    FAKE_SUDOERS = """\
root ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL
"""

    FAKE_SUDOERS_D = {"admin": "bob ALL=(ALL) ALL"}

    def test_parse_sudoers(self, monkeypatch):
        def fake_exists(p):
            s = str(p)
            return s == "/etc/sudoers" or s == "/etc/sudoers.d"

        def fake_is_dir(p):
            return str(p) == "/etc/sudoers.d"

        class FakeEntry:
            name = "admin"
            is_file = lambda self: True
            def __str__(self):
                return "/etc/sudoers.d/admin"

        def fake_iterdir(_):
            return [FakeEntry()]

        def fake_read_text(p):
            s = str(p)
            if s == "/etc/sudoers":
                return self.FAKE_SUDOERS
            if s == "/etc/sudoers.d/admin":
                return "bob ALL=(ALL) ALL\n"
            return ""

        monkeypatch.setattr(Path, "exists", fake_exists)
        monkeypatch.setattr(Path, "is_dir", fake_is_dir)
        monkeypatch.setattr(Path, "iterdir", fake_iterdir)
        monkeypatch.setattr(Path, "read_text", fake_read_text)

        collector = SudoCollector()
        data = collector.collect()

        assert len(data["sudoers_files"]) == 2
        assert "/etc/sudoers" in data["sudoers_files"]
        assert len(data["sudoers_entries"]) == 3
