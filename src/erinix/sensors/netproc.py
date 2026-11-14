"""Rootless network sensor: reads /proc/net/tcp* and reports new connections and new listening ports.

A socket is tied to its program through /proc/<pid>/fd: without root only the sockets of your own
programs can be tied (the others are still listed, with no program). Polling means a connection that opens and closes
between two polls is missed. Everything here is read-only.
"""

from __future__ import annotations

import ipaddress
import os
import time
from dataclasses import dataclass

from erinix.core.events import Event, EventType, NetInfo, Source
from erinix.sensors.procfs import ProcRecord, to_info

ESTABLISHED, LISTEN = "01", "0A"
MAX_SOCKETS = 4000
INODE_REFRESH_SECONDS = 2.0


@dataclass(frozen=True, slots=True)
class Socket:
    proto: str
    local: str
    lport: int
    remote: str
    rport: int
    state: str
    uid: int
    inode: int


def _addr(hexa: str) -> str | None:
    try:
        raw = bytes.fromhex(hexa)
        if len(raw) == 4:
            return str(ipaddress.IPv4Address(raw[::-1]))
        if len(raw) == 16:
            words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            ip = ipaddress.IPv6Address(words)
            return str(ip.ipv4_mapped or ip)
    except ValueError:
        pass
    return None


def parse_table(text: str, proto: str = "tcp") -> list[Socket]:
    sockets: list[Socket] = []
    for line in text.splitlines()[1:MAX_SOCKETS + 1]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            la, lp = parts[1].rsplit(":", 1)
            ra, rp = parts[2].rsplit(":", 1)
            local, remote = _addr(la), _addr(ra)
            if local is None or remote is None:
                continue
            sockets.append(Socket(proto, local, int(lp, 16), remote, int(rp, 16), parts[3], int(parts[7]), int(parts[9])))
        except ValueError:
            continue
    return sockets


def read_sockets(proc: str = "/proc") -> list[Socket]:
    sockets: list[Socket] = []
    for name, proto in (("tcp", "tcp"), ("tcp6", "tcp")):
        try:
            with open(f"{proc}/net/{name}", "rb") as handle:
                sockets += parse_table(handle.read(2_000_000).decode("ascii", "replace"), proto)
        except OSError:
            continue
    return sockets


def inode_owners(proc: str = "/proc") -> dict[int, int]:
    """socket inode -> pid, for every process whose descriptors we may read."""
    owners: dict[int, int] = {}
    try:
        names = os.listdir(proc)
    except OSError:
        return owners
    for name in names:
        if not (name.isascii() and name.isdigit()):
            continue
        try:
            for fd in os.listdir(f"{proc}/{name}/fd"):
                try:
                    target = os.readlink(f"{proc}/{name}/fd/{fd}")
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    try:
                        owners[int(target[8:-1])] = int(name)
                    except ValueError:
                        pass
        except OSError:
            continue
    return owners


class NetworkSensor:
    name = "Network connections"

    def __init__(self, processes, proc: str = "/proc", clock=time.monotonic) -> None:
        self.processes = processes                      # the ProcessSensor: it knows the programs
        self.proc = proc
        self.clock = clock
        self.owners: dict[int, int] = {}
        self._refreshed = -1e9
        self.seen: set[tuple] = set()
        self.baseline_done = False
        self.sockets: list[Socket] = []
        self.error = ""

    def _owner(self, sock: Socket) -> ProcRecord | None:
        pid = self.owners.get(sock.inode)
        return self.processes.known.get(pid) if pid else None

    def poll(self) -> list[Event]:
        self.sockets = read_sockets(self.proc)
        self.error = "" if self.sockets or os.path.exists(f"{self.proc}/net/tcp") else "cannot read /proc/net"
        interesting = [s for s in self.sockets if s.state in (ESTABLISHED, LISTEN)]
        keys = {(s.local, s.lport, s.remote, s.rport, s.state, s.inode) for s in interesting}
        new = [s for s in interesting if (s.local, s.lport, s.remote, s.rport, s.state, s.inode) not in self.seen]
        if new and self.clock() - self._refreshed >= INODE_REFRESH_SECONDS and any(s.inode not in self.owners for s in new):
            self.owners = inode_owners(self.proc)
            self._refreshed = self.clock()
        events: list[Event] = []
        if self.baseline_done:
            listening_ports = {s.lport for s in interesting if s.state == LISTEN}
            for sock in new:
                record = self._owner(sock)
                if record is None:
                    continue                                       # an event needs its program; the socket still shows in the inventory
                info = to_info(record, self.processes.known.get(record.ppid))
                if sock.state == LISTEN:
                    kind = EventType.NET_LISTEN
                    payload = NetInfo.build(protocol="tcp", local_addr=sock.local, local_port=sock.lport)
                else:
                    kind = EventType.NET_ACCEPT if sock.lport in listening_ports else EventType.NET_CONNECT
                    payload = NetInfo.build(protocol="tcp", local_addr=sock.local, local_port=sock.lport,
                                            remote_addr=sock.remote, remote_port=sock.rport)
                events.append(Event(kind, Source.MINIMAL, process=info, payload=payload))
        self.seen = keys
        self.baseline_done = True
        return events

    def inventory(self) -> tuple[list[dict], list[dict]]:
        """(listening, connections) as plain dictionaries for the dashboard."""
        if self.sockets and any(s.inode not in self.owners for s in self.sockets):
            if self.clock() - self._refreshed >= INODE_REFRESH_SECONDS:
                self.owners = inode_owners(self.proc)
                self._refreshed = self.clock()
        listening, connections = [], []
        for sock in self.sockets:
            if sock.state not in (ESTABLISHED, LISTEN):
                continue
            record = self._owner(sock)
            row = {"local": f"{sock.local}:{sock.lport}", "port": sock.lport, "pid": record.pid if record else None,
                   "program": (os.path.basename(record.exe) or record.comm) if record else "", "uid": sock.uid}
            if sock.state == LISTEN:
                listening.append({**row, "exposed": sock.local not in ("127.0.0.1", "::1")})
            else:
                connections.append({**row, "remote": f"{sock.remote}:{sock.rport}", "external": NetInfo.build(
                    protocol="tcp", remote_addr=sock.remote, remote_port=sock.rport).remote_is_external})
        listening.sort(key=lambda r: r["port"])
        return listening[:300], connections[:300]
