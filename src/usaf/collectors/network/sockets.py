from __future__ import annotations

from pathlib import Path

from usaf.collectors.base import BaseCollector
from usaf.collectors.registry import register_collector


@register_collector
class SocketCollector(BaseCollector):
    """Collects listening sockets and connection information from /proc/net."""

    name = "sockets"
    description = "TCP and UDP listening sockets and connections"

    def _do_collect(self) -> dict[str, list[dict[str, str | int | None]]]:
        return {
            "tcp": self._parse_tcp("tcp"),
            "tcp6": self._parse_tcp("tcp6"),
            "udp": self._parse_tcp("udp"),
            "udp6": self._parse_tcp("udp6"),
            "unix": self._parse_unix(),
        }

    def _parse_tcp(self, proto: str) -> list[dict[str, str | int | None]]:
        """Parse /proc/net/{tcp,tcp6,udp,udp6}."""
        sockets: list[dict[str, str | int | None]] = []
        path = Path(f"/proc/net/{proto}")
        if not path.exists():
            return sockets

        try:
            lines = path.read_text().splitlines()
        except OSError:
            return sockets

        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) < 12:
                continue

            local = parts[1]
            remote = parts[2]
            state_code = parts[3]
            inode = parts[9]

            local_addr, local_port = self._parse_socket_addr(local)
            remote_addr, remote_port = self._parse_socket_addr(remote)

            socket_info: dict[str, str | int | None] = {
                "protocol": proto.rstrip("6").upper(),
                "local_address": local_addr,
                "local_port": local_port,
                "remote_address": remote_addr,
                "remote_port": remote_port,
                "state": self._tcp_state(state_code) if proto in ("tcp", "tcp6") else None,
                "inode": int(inode) if inode.isdigit() else None,
            }

            if proto in ("tcp", "tcp6") and socket_info["state"] in ("LISTEN", None):
                sockets.append(socket_info)

        return sockets

    def _parse_socket_addr(self, hex_addr: str) -> tuple[str, int]:
        """Parse hex socket address like '0100007F:0019' -> ('127.0.0.1', 25)."""
        addr_part, port_part = hex_addr.split(":")
        port = int(port_part, 16)

        if len(addr_part) == 8:  # IPv4
            addr = ".".join(str(int(addr_part[i : i + 2], 16)) for i in [6, 4, 2, 0])
        elif len(addr_part) == 32:  # IPv6
            addr = ":".join(addr_part[i : i + 4] for i in range(0, 32, 4))
            addr = self._collapse_ipv6(addr)
        else:
            addr = addr_part

        return addr, port

    def _collapse_ipv6(self, addr: str) -> str:
        """Basic IPv6 zero-collapse."""
        groups = addr.split(":")
        # Collapse longest run of zeros
        zero_runs: list[tuple[int, int]] = []
        i = 0
        while i < len(groups):
            if groups[i] == "0000":
                start = i
                while i < len(groups) and groups[i] == "0000":
                    i += 1
                zero_runs.append((start, i - start))
            else:
                i += 1

        if zero_runs:
            longest = max(zero_runs, key=lambda x: x[1])
            start, length = longest
            if length > 1:
                result = ":".join(groups[:start]) + "::" + ":".join(groups[start + length :])
                return result.strip(":")
            if length == 8:
                return "::"

        return ":".join(groups)

    def _tcp_state(self, state: str) -> str:
        states = {
            "01": "ESTABLISHED",
            "02": "SYN_SENT",
            "03": "SYN_RECV",
            "04": "FIN_WAIT1",
            "05": "FIN_WAIT2",
            "06": "TIME_WAIT",
            "07": "CLOSE",
            "08": "CLOSE_WAIT",
            "09": "LAST_ACK",
            "0A": "LISTEN",
            "0B": "CLOSING",
        }
        return states.get(state, f"UNKNOWN({state})")

    def _parse_unix(self) -> list[dict[str, str | int | None]]:
        sockets: list[dict[str, str | int | None]] = []
        path = Path("/proc/net/unix")
        if not path.exists():
            return sockets

        try:
            lines = path.read_text().splitlines()
        except OSError:
            return sockets

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 7:
                continue
            sockets.append(
                {
                    "protocol": "UNIX",
                    "local_address": parts[6] if len(parts) > 7 else "",
                    "state": parts[4] if len(parts) > 4 else None,
                    "inode": int(parts[6]) if parts[6].isdigit() else None,
                }
            )

        return sockets


@register_collector
class InterfaceCollector(BaseCollector):
    """Collects network interface information."""

    name = "interfaces"
    description = "Network interfaces, IP addresses, and flags"

    def _do_collect(self) -> dict[str, list[dict[str, str | int | list[str] | bool | None]]]:
        interfaces: dict[str, list[dict[str, str | int | list[str] | bool | None]]] = {"interfaces": []}

        net_path = Path("/sys/class/net")
        if not net_path.exists():
            return interfaces

        for iface in sorted(net_path.iterdir()):
            name = iface.name
            if name == "lo":
                continue
            info = self._get_interface_info(name)
            if info:
                interfaces["interfaces"].append(info)

        return interfaces

    def _get_interface_info(self, name: str) -> dict[str, str | int | list[str] | bool | None] | None:
        base = Path(f"/sys/class/net/{name}")
        try:
            operstate = (base / "operstate").read_text().strip()
            carrier = (
                int((base / "carrier").read_text().strip()) if (base / "carrier").exists() else 0
            )
            address = (base / "address").read_text().strip()
            mtu = int((base / "mtu").read_text().strip())
            flags_str = (base / "flags").read_text().strip()
        except OSError:
            return None

        flags: list[str] = []
        flag_map = {
            "0x1": "LOOPBACK",
            "0x2": "BROADCAST",
            "0x4": "POINTTOPOINT",
            "0x8": "MULTICAST",
            "0x10": "PROMISC",
            "0x40": "RUNNING",
            "0x100": "NOARP",
            "0x200": "ALLMULTI",
            "0x4000": "SLAVE",
        }
        try:
            flag_val = int(flags_str, 16) if flags_str.startswith("0x") else int(flags_str)
            for hex_val, label in flag_map.items():
                if flag_val & int(hex_val, 16):
                    flags.append(label)
        except (ValueError, AttributeError):
            pass

        return {
            "name": name,
            "mac": address,
            "mtu": mtu,
            "state": operstate,
            "carrier": bool(carrier),
            "promisc": "PROMISC" in flags,
            "flags": flags,
        }
