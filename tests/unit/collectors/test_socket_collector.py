from __future__ import annotations

from pathlib import Path

from usaf.collectors.network.sockets import InterfaceCollector, SocketCollector


PROC_NET_TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23456 1 0000000000000000 100 0 0 10 0
"""

PROC_NET_UDP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 34567 1 0000000000000000 100 0 0 10 0
"""

PROC_NET_TCP_LISTEN = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 34567 1 0000000000000000 100 0 0 10 0
"""


class TestSocketCollector:
    def test_parse_tcp(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: True)
        monkeypatch.setattr(Path, "read_text", lambda _: PROC_NET_TCP)

        collector = SocketCollector()
        data = collector.collect()

        assert len(data["tcp"]) == 2
        assert data["tcp"][0]["local_address"] == "127.0.0.1"
        assert data["tcp"][0]["local_port"] == 25
        assert data["tcp"][0]["state"] == "LISTEN"
        assert data["tcp"][1]["local_address"] == "0.0.0.0"
        assert data["tcp"][1]["local_port"] == 443

    def test_parse_udp(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda p: True)
        monkeypatch.setattr(Path, "read_text", lambda _: PROC_NET_UDP)

        collector = SocketCollector()
        data = collector.collect()

        assert len(data["udp"]) == 0

    def test_returns_empty_when_no_proc_net(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: False)
        collector = SocketCollector()
        data = collector.collect()
        assert data["tcp"] == []
        assert data["udp"] == []

    def test_parse_socket_addr_ipv4(self):
        collector = SocketCollector()
        addr, port = collector._parse_socket_addr("0100007F:0019")
        assert addr == "127.0.0.1"
        assert port == 25

    def test_tcp_state_mapping(self):
        collector = SocketCollector()
        assert collector._tcp_state("0A") == "LISTEN"
        assert collector._tcp_state("01") == "ESTABLISHED"
        assert collector._tcp_state("FF") == "UNKNOWN(FF)"


class TestInterfaceCollector:
    def test_collect_interfaces(self, monkeypatch):
        class FakeEntry:
            def __init__(self, name):
                self.name = name
            def __lt__(self, other):
                return self.name < other.name
            def __str__(self):
                return self.name

        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "iterdir", lambda _: [
            FakeEntry("eth0"),
            FakeEntry("eth1"),
        ])

        def fake_read_text(p):
            s = str(p)
            if s.endswith("operstate"):
                return "up"
            if s.endswith("carrier"):
                return "1"
            if s.endswith("address"):
                return "00:11:22:33:44:55"
            if s.endswith("mtu"):
                return "1500"
            if s.endswith("flags"):
                return "0x1103"
            return ""

        monkeypatch.setattr(Path, "read_text", fake_read_text)

        collector = InterfaceCollector()
        data = collector.collect()

        assert len(data["interfaces"]) == 2
        assert data["interfaces"][0]["name"] == "eth0"
        assert data["interfaces"][1]["name"] == "eth1"

    def test_skips_loopback(self, monkeypatch):
        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "iterdir", lambda _: [
            type("Entry", (), {"name": "lo"})(),
        ])

        collector = InterfaceCollector()
        data = collector.collect()
        assert data["interfaces"] == []

    def test_detects_promiscuous(self, monkeypatch):
        class FakeEntry:
            def __init__(self, name):
                self.name = name
            def __lt__(self, other):
                return self.name < other.name

        monkeypatch.setattr(Path, "exists", lambda _: True)
        monkeypatch.setattr(Path, "iterdir", lambda _: [
            FakeEntry("prom0"),
        ])

        def fake_read_text(p):
            s = str(p)
            if s.endswith("operstate"):
                return "up"
            if s.endswith("carrier"):
                return "1"
            if s.endswith("address"):
                return "aa:bb:cc:dd:ee:ff"
            if s.endswith("mtu"):
                return "1500"
            if s.endswith("flags"):
                return "0x1103"
            return ""

        monkeypatch.setattr(Path, "read_text", fake_read_text)

        collector = InterfaceCollector()
        data = collector.collect()
        assert len(data["interfaces"]) == 1
