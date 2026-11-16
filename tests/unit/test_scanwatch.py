import io
import json
import socket
import struct
import time

import pytest

from erinix import config as cfg
from erinix.agent import Agent
from erinix.commands.builtin import default_rules_path
from erinix.core.events import Event, EventType, ScanInfo, Source
from erinix.engine import Correlator
from erinix.incidents import build_incidents
from erinix.recorder import Recorder
from erinix.rules import load_rules
from erinix.sensors import procview, scanwatch
from erinix.sensors.scanwatch import (ETH_P_IP, ETH_P_IPV6, Detection, ScanDetector, ScanSensor, ScanWatcher, parse_packet)
from erinix.store import Store

SYN, ACK, FIN, RST, PSH, URG = 0x02, 0x10, 0x01, 0x04, 0x08, 0x20


def ipv4(src="203.0.113.50", port=22, flags=SYN, dst="192.168.1.10", proto=6, frag=0, ihl=5):
    tcp = struct.pack("!HHIIBBHHH", 40000, port, 0, 0, 5 << 4, flags, 1024, 0, 0)
    head = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, 0, 20 + len(tcp), 1, frag, 64, proto,
                       0, socket.inet_aton(src), socket.inet_aton(dst))
    return head + b"\x00" * ((ihl - 5) * 4) + tcp


def ipv6(src="2001:db8::5", port=22, flags=SYN, nxt=6):
    tcp = struct.pack("!HHIIBBHHH", 40000, port, 0, 0, 5 << 4, flags, 1024, 0, 0)
    head = struct.pack("!IHBB16s16s", 6 << 28, len(tcp), nxt, 64, socket.inet_pton(socket.AF_INET6, src),
                       socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
    return head + tcp


# ------------------------------------------------------------ the packet parser
def test_parses_a_syn_to_a_port():
    assert parse_packet(ETH_P_IP, ipv4(port=8080)) == scanwatch.Probe("203.0.113.50", 8080)
    assert parse_packet(ETH_P_IPV6, ipv6(port=443)) == scanwatch.Probe("2001:db8::5", 443)


@pytest.mark.parametrize("flags", [SYN, 0, FIN, FIN | PSH | URG])
def test_scan_flag_combinations_count(flags):
    assert parse_packet(ETH_P_IP, ipv4(flags=flags)) is not None


@pytest.mark.parametrize("flags", [SYN | ACK, ACK, RST, RST | ACK, FIN | ACK, PSH | ACK, SYN | FIN])
def test_normal_traffic_is_not_a_probe(flags):
    assert parse_packet(ETH_P_IP, ipv4(flags=flags)) is None


def test_not_tcp_fragments_and_port_zero_are_ignored():
    assert parse_packet(ETH_P_IP, ipv4(proto=17)) is None
    assert parse_packet(ETH_P_IP, ipv4(frag=185)) is None            # not the first fragment: no TCP header in it
    assert parse_packet(ETH_P_IP, ipv4(port=0)) is None
    assert parse_packet(ETH_P_IPV6, ipv6(nxt=44)) is None            # extension header: not followed
    assert parse_packet(0x0806, b"\x00" * 60) is None                # ARP


@pytest.mark.parametrize("data", [b"", b"\x45", b"\x45" + b"\x00" * 18, b"\xff" * 64, b"\x4f" + b"\x00" * 30, bytes(range(256))])
def test_hostile_packets_never_crash_the_parser(data):
    for proto in (ETH_P_IP, ETH_P_IPV6, 0):
        parse_packet(proto, data)                                     # must not raise


def test_truncated_and_lying_headers():
    assert parse_packet(ETH_P_IP, ipv4()[:30]) is None               # cut inside the TCP header
    assert parse_packet(ETH_P_IP, ipv4(ihl=15)[:40]) is None         # header length points past the data
    assert parse_packet(ETH_P_IPV6, ipv6()[:50]) is None


# ------------------------------------------------------------ the detector
def knock(det, src, ports, *, start=0.0, step=0.1):
    found = []
    for i, port in enumerate(ports):
        got = det.feed(src, port, start + i * step)
        if got:
            found.append(got)
    return found


def test_ten_ports_in_ten_seconds_is_a_fast_scan():
    det = ScanDetector()
    found = knock(det, "203.0.113.50", range(1, 30))
    assert [f.kind for f in found] == ["fast"] and found[0].port_count == 10 and found[0].ports[:3] == (1, 2, 3)


def test_the_same_port_again_and_again_is_not_a_scan():
    det = ScanDetector()
    assert knock(det, "203.0.113.50", [22] * 500, step=0.01) == []     # a client retrying one port: normal
    assert knock(det, "203.0.113.51", [22, 80, 443] * 100, step=0.01) == []


def test_a_slow_scan_is_seen_over_minutes():
    det = ScanDetector()
    found = knock(det, "203.0.113.50", range(1, 40), step=10.0)         # one port every 10 s: never 10 in 10 s
    assert [f.kind for f in found] == ["slow"] and found[0].port_count == 25


def test_a_big_scan_escalates_once_to_wide():
    det = ScanDetector()
    found = knock(det, "203.0.113.50", range(1, 1001), step=0.01)
    assert [f.kind for f in found] == ["fast", "wide"] and found[1].port_count >= 100


def test_each_source_is_counted_separately():
    det = ScanDetector()
    for i in range(9):
        assert det.feed("203.0.113.1", 100 + i, i) is None
        assert det.feed("203.0.113.2", 200 + i, i) is None             # 18 ports in all, but 9 each: nobody scans


def test_never_reports_ignored_loopback_or_own_addresses():
    det = ScanDetector(ignore=frozenset({"192.168.1.10"}))
    for src in ("127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "192.168.1.10", "not-an-ip", ""):
        assert knock(det, src, range(1, 60)) == []


def test_forged_sources_cannot_eat_memory():
    det = ScanDetector()
    for i in range(scanwatch.MAX_SOURCES * 3):
        det.feed(f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", 80, i * 0.001)
    assert len(det._seen) <= scanwatch.MAX_SOURCES and det.dropped > 0


def test_ports_kept_per_source_are_bounded():
    det = ScanDetector()
    knock(det, "203.0.113.50", range(1, 5001), step=0.001)
    assert len(det._seen["203.0.113.50"]) <= scanwatch.MAX_PORTS_PER_SOURCE


def test_a_quiet_source_is_forgotten_and_can_be_reported_again():
    det = ScanDetector()
    assert knock(det, "203.0.113.50", range(1, 20))
    det.forget_old(now=1000.0)
    assert not det._seen and knock(det, "203.0.113.50", range(1, 20), start=1000.0)


def test_bad_ports_are_ignored():
    det = ScanDetector()
    assert [det.feed("203.0.113.50", p, 0) for p in (0, -1, 70000)] == [None] * 3


# ------------------------------------------------------------ the watcher thread, with a fake socket
class FakeSock:
    def __init__(self, packets):
        self.packets, self.closed = list(packets), False

    def recvfrom(self, n):
        if self.closed:
            raise OSError("closed")
        if not self.packets:
            time.sleep(0.01)
            raise socket.timeout()
        return self.packets.pop(0)

    def close(self):
        self.closed = True


def packets(src, ports, pkttype=0, hatype=1):
    return [(ipv4(src=src, port=p), ("eth0", ETH_P_IP, pkttype, hatype, b"")) for p in ports]


def wait_for(watcher, n=1):
    end, got = time.monotonic() + 3, []
    while time.monotonic() < end and len(got) < n:
        got += watcher.drain()
        time.sleep(0.01)
    return got


def test_watcher_reports_a_scan():
    w = ScanWatcher(open_socket=lambda: FakeSock(packets("203.0.113.50", range(1, 40))))
    assert w.start() and w.state == "ok"
    got = wait_for(w)
    w.stop()
    assert got and got[0].src == "203.0.113.50" and got[0].kind == "fast"


def test_watcher_ignores_outgoing_loopback_and_broadcast_packets():
    pk = packets("203.0.113.50", range(1, 40), pkttype=4) + packets("203.0.113.51", range(1, 40), pkttype=1) \
        + packets("203.0.113.52", range(1, 40), hatype=scanwatch.ARPHRD_LOOPBACK)
    w = ScanWatcher(open_socket=lambda: FakeSock(pk))
    w.start()
    time.sleep(0.4)
    w.stop()
    assert w.drain() == []


def test_watcher_survives_odd_addresses_and_garbage():
    pk = [(b"\xff" * 50, ("eth0", ETH_P_IP, 0, 1, b"")), (b"", ("eth0", 0, 0, 1, b"")), (b"x", "not-a-tuple"), (b"x", None)]
    w = ScanWatcher(open_socket=lambda: FakeSock(pk + packets("203.0.113.50", range(1, 40))))
    w.start()
    assert wait_for(w)
    w.stop()


def test_watcher_without_permission_says_so_and_stays_off():
    def no():
        raise PermissionError(1, "Operation not permitted")
    w = ScanWatcher(open_socket=no)
    assert w.start() is False and w.state == "blind" and "Operation not permitted" in w.detail


def test_pending_detections_are_bounded():
    w = ScanWatcher(open_socket=lambda: FakeSock([]))
    for i in range(scanwatch.MAX_PENDING * 3):
        w._pending.append(Detection(f"203.0.113.{i % 250}", "fast", 10, (1,)))
    assert len(w.drain()) == scanwatch.MAX_PENDING


# ------------------------------------------------------------ over the helper pipe
def test_scan_roundtrip_over_the_pipe():
    line = procview.encode_scan(Detection("203.0.113.50", "wide", 300, (22, 80)))
    assert procview.decode_scan(line) == Detection("203.0.113.50", "wide", 300, (22, 80))


@pytest.mark.parametrize("bad", [
    {"src": "not-an-ip", "kind": "fast", "count": 10, "ports": [1]},
    {"src": "203.0.113.50", "kind": "boom", "count": 10, "ports": [1]},
    {"src": "203.0.113.50", "kind": "fast", "count": 0, "ports": [1]},
    {"src": "203.0.113.50", "kind": "fast", "count": 10**9, "ports": [1]},
    {"src": "203.0.113.50", "kind": "fast", "count": True, "ports": [1]},
    {"src": "203.0.113.50", "kind": "fast", "count": 10, "ports": list(range(1, 40))},
    {"src": "203.0.113.50", "kind": "fast", "count": 10, "ports": [0]},
    {"src": "203.0.113.50", "kind": "fast", "count": 10, "ports": [70000]},
    {"src": "203.0.113.50", "kind": "fast", "count": 10, "ports": "22"},
    {"src": "1" * 500, "kind": "fast", "count": 10, "ports": [1]},
    {"src": 5, "kind": "fast", "count": 10, "ports": [1]},
    {"kind": "fast"},
])
def test_hostile_scan_lines_are_rejected(bad):
    assert procview.decode_scan(json.dumps({"t": "scan", **bad})) is None
    assert procview.decode_scan("not json") is None


def test_helper_sends_hello_with_scan_status_and_scans():
    class W:
        state, detail = "ok", "listening"
        def start(self): return True
        def drain(self): return [Detection("203.0.113.50", "fast", 12, (1, 2, 3))] if not getattr(self, "done", False) and not setattr(self, "done", True) else []
        def stop(self): self.stopped = True
    import os
    w, out = W(), io.StringIO()
    r, wr = os.pipe()                                       # a parent that stays connected: closing stdin would stop the helper at once
    stdin = os.fdopen(r)
    procview.helper_main(out, interval=0.0, stop=iter([False, False, True]).__next__, sleep=lambda s: None, stdin=stdin, assess=False, watcher=w)
    os.close(wr)                                            # the reader thread sees the end, then the read side can be closed
    time.sleep(0.2)
    stdin.close()
    lines = [json.loads(x) for x in out.getvalue().splitlines()]
    assert lines[0]["t"] == "hello" and lines[0]["scan"] == "ok"
    assert [x for x in lines if x["t"] == "scan"][0]["src"] == "203.0.113.50" and w.stopped


def test_remote_view_collects_scans_and_hello_status():
    hello = json.dumps({"t": "hello", "uid": 0, "version": "x", "note": "", "scan": "ok", "scan_detail": "listening"}, separators=(",", ":"))
    scan = procview.encode_scan(Detection("203.0.113.50", "fast", 12, (1, 2)))
    view = procview.RemoteView(io.StringIO(hello + "\n" + scan + "\n" + '{"t":"scan","src":"bad"}\n')).start()
    view._thread.join(2)
    assert view.scan_state == "ok" and view.scan_detail == "listening"
    assert [d.src for d in view.drain_scans()] == ["203.0.113.50"] and view.drain_scans() == [] and view.bad_lines == 1


def test_a_flood_of_scan_lines_is_capped():
    scan = procview.encode_scan(Detection("203.0.113.50", "fast", 12, (1, 2)))
    view = procview.RemoteView(io.StringIO((scan + "\n") * 1000)).start()
    view._thread.join(2)
    assert len(view.drain_scans()) == 256


# ------------------------------------------------------------ events, rules, incidents
def test_scan_info_rejects_bad_input():
    for kw in ({"remote_addr": "127.0.0.1"}, {"remote_addr": "0.0.0.0"}, {"remote_addr": "224.0.0.1"}, {"remote_addr": "x"},
               {"remote_addr": "203.0.113.5", "kind": "boom"}, {"remote_addr": "203.0.113.5", "port_count": 0},
               {"remote_addr": "203.0.113.5", "port_count": True}, {"remote_addr": "203.0.113.5", "protocol": "udp"},
               {"remote_addr": "203.0.113.5", "ports": [70000]}):
        base = {"remote_addr": "203.0.113.5", "kind": "fast", "port_count": 12, "ports": (1,)}
        with pytest.raises(ValueError):
            ScanInfo.build(**{**base, **kw})
    assert len(ScanInfo.build(remote_addr="203.0.113.5", kind="fast", port_count=500, ports=range(1, 500)).ports) == 16


def test_scan_event_needs_its_payload():
    with pytest.raises(ValueError):
        Event(EventType.SCAN_DETECTED, Source.MINIMAL)


def test_rules_load_and_a_scan_becomes_an_incident(tmp_path):
    rules = load_rules(default_rules_path())
    assert not rules.problems and {"port-scan", "port-scan-wide"} <= {i.id for i in rules.indicators}
    store = Store(tmp_path / "e.db")
    rec = Recorder(store, Correlator(rules))
    info = ScanInfo.build(remote_addr="203.0.113.50", kind="fast", port_count=12, ports=(21, 22, 23, 25, 80))
    alerts = rec.feed(Event(EventType.SCAN_DETECTED, Source.MINIMAL, payload=info))
    assert [a.rule_id for a in alerts] == ["port-scan"] and alerts[0].severity.value == "medium"
    wide = ScanInfo.build(remote_addr="203.0.113.50", kind="wide", port_count=150, ports=(1, 2))
    alerts = rec.feed(Event(EventType.SCAN_DETECTED, Source.MINIMAL, payload=wide))
    assert [a.rule_id for a in alerts] == ["port-scan-wide"] and alerts[0].severity.value == "high"
    incidents = build_incidents(store)
    assert len(incidents) == 1 and "203.0.113.50" in json.dumps(incidents[0])


def test_rule_with_a_bad_scan_kind_is_refused(tmp_path):
    (tmp_path / "bad.toml").write_text('''schema = 1
[[indicator]]
id = "x"
event = "scan.detected"
severity = "low"
[indicator.match]
kind = ["nope"]
''')
    assert load_rules(tmp_path).problems


# ------------------------------------------------------------ the sensor and the agent
def test_sensor_without_root_is_off_and_explains():
    s = ScanSensor(None, privileged=False)
    assert s.poll() == [] and s.status()["state"] == "off" and "root" in s.status()["detail"]


def test_sensor_turns_detections_into_events_and_skips_bad_ones():
    class V:
        scan_state, scan_detail = "ok", "listening"
        def drain_scans(self): return [Detection("203.0.113.50", "fast", 12, (1,)), Detection("127.0.0.1", "fast", 12, (1,))]
    s = ScanSensor(V())
    events = s.poll()
    assert len(events) == 1 and events[0].type is EventType.SCAN_DETECTED and s.status()["state"] == "ok"


def test_agent_shows_a_scan_as_an_incident_and_lists_the_source(tmp_path):
    class V:
        scan_state, scan_detail = "ok", "listening to incoming packets (port scans)"
        privileged = True
        def __init__(self): self.sent = False
        def scan(self): return {}
        def sockets(self): return []
        def owners(self): return {}
        def drain_scans(self):
            if self.sent:
                return []
            self.sent = True
            return [Detection("203.0.113.50", "fast", 14, (21, 22, 23))]
    store = Store(tmp_path / "e.db")
    rules = load_rules(default_rules_path())
    agent = Agent(store, Recorder(store, Correlator(rules)), cfg.Config(), proc=str(tmp_path), view=V())
    agent.start()
    agent.step()
    assert agent.alerts >= 1 and build_incidents(store)
    assert any(r["name"] == "Port scans" and r["state"] == "ok" for r in agent.sources())
    agent.close()
