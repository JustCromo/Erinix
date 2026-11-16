"""Port scan detection: counts how many DIFFERENT ports one address knocks on.

A scan (nmap, masscan) sends a packet to many ports and almost never finishes a connection, so it leaves nothing in
/proc/net. To see it Erinix listens to incoming packets with a raw socket (needs root, so it runs in the root helper).
The socket sees a packet before the firewall decides what to do with it: closed or filtered ports are seen too.

What counts as a probe: a TCP packet with only SYN set (the normal scan and connect scan), or with no flags / only FIN /
FIN+PSH+URG (the null, FIN and Xmas scans). Normal traffic never does the latter.

Everything here is bounded: the number of sources, the ports kept per source and the size of what is reported. The
packet parser never trusts a length. Source addresses of a scan can be forged: Erinix only reports and the action to
block an address always asks first (and never blocks the gateway or this machine's own addresses).
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable

ETH_P_ALL = 0x0003
ETH_P_IP, ETH_P_IPV6 = 0x0800, 0x86DD
PACKET_HOST = 0                                 # addressed to this machine (not broadcast, multicast, nor outgoing)
ARPHRD_LOOPBACK = 772
PROBE_FLAGS = frozenset({0x02, 0x00, 0x01, 0x29})   # SYN | none | FIN | FIN+PSH+URG, looking only at SYN FIN RST PSH ACK URG
FLAG_MASK = 0x3F

FAST_PORTS, FAST_SECONDS = 10, 10.0
SLOW_PORTS, SLOW_SECONDS = 25, 300.0
WIDE_PORTS = 100
MAX_SOURCES = 2048
MAX_PORTS_PER_SOURCE = 512
MAX_PENDING = 256


@dataclass(frozen=True, slots=True)
class Probe:
    src: str
    port: int


@dataclass(frozen=True, slots=True)
class Detection:
    src: str
    kind: str                  # fast | slow | wide
    port_count: int
    ports: tuple[int, ...]


def parse_packet(proto: int, data: bytes) -> Probe | None:
    """An IPv4/IPv6 packet (no link header) -> the probe it carries, or None if it is not one."""
    try:
        if proto == ETH_P_IP:
            if len(data) < 20 or data[0] >> 4 != 4:
                return None
            ihl = (data[0] & 0x0F) * 4
            if ihl < 20 or data[9] != 6 or struct.unpack("!H", data[6:8])[0] & 0x1FFF:      # TCP, first fragment only
                return None
            src, tcp = socket.inet_ntop(socket.AF_INET, data[12:16]), data[ihl:]
        elif proto == ETH_P_IPV6:
            if len(data) < 40 or data[0] >> 4 != 6 or data[6] != 6:                         # TCP directly after the header
                return None
            src, tcp = socket.inet_ntop(socket.AF_INET6, data[8:24]), data[40:]
        else:
            return None
        if len(tcp) < 14 or (tcp[13] & FLAG_MASK) not in PROBE_FLAGS:
            return None
        port = struct.unpack("!H", tcp[2:4])[0]
        return Probe(src, port) if port else None
    except (struct.error, ValueError, IndexError, OSError):
        return None


def _usable(src: str, ignore: frozenset[str]) -> bool:
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast) and src not in ignore


class ScanDetector:
    """Feeds on probes, says when one source has touched too many different ports."""

    def __init__(self, *, ignore: frozenset[str] = frozenset(), clock: Callable[[], float] = time.monotonic) -> None:
        self.ignore, self.clock = ignore, clock
        self._seen: OrderedDict[str, dict[int, float]] = OrderedDict()     # source -> port -> last time
        self._level: dict[str, int] = {}                                    # source -> 0 quiet, 1 said fast/slow, 2 said wide
        self.dropped = 0

    def feed(self, src: str, port: int, now: float | None = None) -> Detection | None:
        now = self.clock() if now is None else now
        if not 1 <= port <= 65535 or not _usable(src, self.ignore):
            return None
        ports = self._seen.get(src)
        if ports is None:
            if len(self._seen) >= MAX_SOURCES:                              # forged sources cannot grow memory: the oldest goes
                old, _ = self._seen.popitem(last=False)
                self._level.pop(old, None)
                self.dropped += 1
            ports = self._seen[src] = {}
        self._seen.move_to_end(src)
        known = port in ports
        if not known and len(ports) >= MAX_PORTS_PER_SOURCE:                # already far past every threshold
            oldest = min(ports, key=ports.__getitem__)
            del ports[oldest]
        ports[port] = now
        if known:
            return None
        level = self._level.get(src, 0)
        if level == 2:
            return None
        fast = sum(1 for t in ports.values() if now - t <= FAST_SECONDS)
        slow = sum(1 for t in ports.values() if now - t <= SLOW_SECONDS)
        if slow >= WIDE_PORTS:
            kind, count, new_level = "wide", slow, 2
        elif level == 0 and fast >= FAST_PORTS:
            kind, count, new_level = "fast", fast, 1
        elif level == 0 and slow >= SLOW_PORTS:
            kind, count, new_level = "slow", slow, 1
        else:
            return None
        self._level[src] = new_level
        return Detection(src, kind, count, tuple(sorted(ports))[:16])

    def forget_old(self, now: float | None = None) -> None:
        """Drop sources that have been quiet for longer than the slow window."""
        now = self.clock() if now is None else now
        for src in [s for s, p in self._seen.items() if p and now - max(p.values()) > SLOW_SECONDS]:
            self._seen.pop(src, None)
            self._level.pop(src, None)


class ScanWatcher:
    """Listens on a raw socket in a thread and queues detections. Without root it stays off and says why."""

    def __init__(self, *, ignore: frozenset[str] = frozenset(), open_socket: Callable[[], socket.socket] | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.detector = ScanDetector(ignore=ignore, clock=clock)
        self._open = open_socket or self._raw
        self.state, self.detail = "off", "not started"
        self._pending: deque[Detection] = deque(maxlen=MAX_PENDING)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock: socket.socket | None = None

    @staticmethod
    def _raw() -> socket.socket:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
        sock.settimeout(1.0)
        return sock

    def start(self) -> bool:
        try:
            self._sock = self._open()
        except (OSError, AttributeError, PermissionError) as exc:
            self.state, self.detail = "blind", f"cannot listen to packets ({getattr(exc, 'strerror', None) or type(exc).__name__})"
            return False
        self.state, self.detail = "ok", "listening to incoming packets (port scans)"
        self._thread = threading.Thread(target=self._loop, name="erinix-scanwatch", daemon=True)
        self._thread.start()
        return True

    def _loop(self) -> None:
        sock, last_clean = self._sock, time.monotonic()
        while not self._stop.is_set() and sock is not None:
            try:
                data, addr = sock.recvfrom(128)                # headers are enough: only the first bytes are read
            except socket.timeout:
                data, addr = b"", None
            except OSError:
                self.state, self.detail = "blind", "the packet socket stopped"
                return
            if addr is not None:
                try:
                    _ifname, proto, pkttype, hatype, _mac = addr
                except (TypeError, ValueError):
                    continue
                if pkttype == PACKET_HOST and hatype != ARPHRD_LOOPBACK:
                    probe = parse_packet(proto, data)
                    if probe is not None:
                        found = self.detector.feed(probe.src, probe.port)
                        if found is not None:
                            self._pending.append(found)
            if time.monotonic() - last_clean > 60:
                last_clean = time.monotonic()
                self.detector.forget_old()

    def drain(self) -> list[Detection]:
        out = []
        while self._pending:
            out.append(self._pending.popleft())
        return out

    def stop(self) -> None:
        self._stop.set()
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def local_addresses() -> frozenset[str]:
    """This machine's own addresses: a packet that claims to come from one of them is never a scan."""
    found: set[str] = set()
    try:
        with open("/proc/net/fib_trie", "rb") as handle:
            lines = handle.read(500_000).decode("ascii", "replace").splitlines()
        for i, line in enumerate(lines):
            if "/32 host LOCAL" in line and i > 0:
                parts = lines[i - 1].split()
                if parts:
                    found.add(parts[-1])
    except OSError:
        pass
    return frozenset(found)


class ScanSensor:
    """Turns detections into events. The packets come from the root helper (view) or, when Erinix itself is root, from here."""

    name = "Port scans"

    def __init__(self, view=None, *, privileged: bool = False, watcher: ScanWatcher | None = None) -> None:
        self.view, self.watcher = view, None
        self.state, self.detail = "off", "needs root: press R in the cockpit to turn it on"
        if view is None and (privileged or watcher is not None):
            self.watcher = watcher or ScanWatcher(ignore=local_addresses())
            self.watcher.start()

    def poll(self):
        from erinix.core.events import Event, EventType, ScanInfo, Source

        if self.view is not None:
            found = self.view.drain_scans()
            self.state, self.detail = self.view.scan_state, self.view.scan_detail
        elif self.watcher is not None:
            found = self.watcher.drain()
            self.state, self.detail = self.watcher.state, self.watcher.detail
        else:
            return []
        events = []
        for item in found:
            try:
                info = ScanInfo.build(remote_addr=item.src, kind=item.kind, port_count=item.port_count, ports=item.ports)
            except ValueError:
                continue
            events.append(Event(EventType.SCAN_DETECTED, Source.MINIMAL, payload=info))
        return events

    def status(self) -> dict:
        state = {"ok": "ok", "off": "off"}.get(self.state, "blind")
        return {"name": self.name, "state": state, "detail": self.detail}

    def close(self) -> None:
        if self.watcher is not None:
            self.watcher.stop()
