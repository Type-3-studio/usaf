from __future__ import annotations

from pathlib import Path

from usaf.collectors.filesystem.mounts import MountCollector

FAKE_MOUNTS = """\
/dev/sda1 / ext4 rw,relatime 0 0
/dev/sda2 /home ext4 rw,relatime 0 0
tmpfs /run tmpfs rw,nosuid 0 0
"""

FAKE_FSTAB = """\
# /etc/fstab
UUID=abc / ext4 defaults 0 1
UUID=def /home ext4 defaults 0 2
UUID=ghi swap swap defaults 0 0
"""


class TestMountCollector:
    def test_parse_mounts(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: FAKE_MOUNTS)

        collector = MountCollector()
        data = collector.collect()

        assert len(data["mounts"]) == 3
        assert data["mounts"][0]["device"] == "/dev/sda1"
        assert data["mounts"][0]["mount_point"] == "/"
        assert data["mounts"][0]["fstype"] == "ext4"

    def test_parse_fstab(self, monkeypatch):
        def fake_read_text(p):
            if str(p).endswith("mounts"):
                return FAKE_MOUNTS
            if str(p).endswith("fstab"):
                return FAKE_FSTAB
            if str(p).endswith("mountinfo"):
                return ""
            return ""

        monkeypatch.setattr(Path, "read_text", fake_read_text)

        collector = MountCollector()
        data = collector.collect()

        assert len(data["fstab"]) == 3
        assert data["fstab"][0]["device"] == "UUID=abc"
        assert data["fstab"][0]["mount_point"] == "/"

    def test_handles_os_error(self, monkeypatch):
        monkeypatch.setattr(Path, "read_text", lambda _: (_ for _ in ()).throw(OSError))

        collector = MountCollector()
        data = collector.collect()

        assert data["mounts"] == []
        assert data["fstab"] == []
