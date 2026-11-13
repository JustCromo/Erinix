import ipaddress

import pytest

from erinix.core.events import (
    AuthInfo, Event, EventType, FileInfo, NetInfo, PrivInfo, ProcessInfo, SensorInfo, Source, Text,
)
from erinix.demo.scenarios import SCENARIOS
from erinix.describe import MAX_SUMMARY, describe


def proc(exe="/usr/bin/bash", argv=None, uid=33):
    return ProcessInfo.build(pid=900, start_ns=1, uid=uid, euid=uid, exe=exe, argv=argv or [exe], comm=exe.rsplit("/", 1)[-1])


def test_every_demo_event_has_a_readable_line():
    seen = set()
    for scenario in SCENARIOS.values():
        for event in scenario.build():
            label, summary, remote = describe(event)
            assert label and summary and "\n" not in summary and len(summary) <= MAX_SUMMARY
            assert remote is None or ipaddress.ip_address(remote)
            seen.add(event.type)
    assert {EventType.WEB_REQUEST, EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS, EventType.PROCESS_EXEC, EventType.NET_CONNECT,
            EventType.PRIV_UID_CHANGE, EventType.FILE_ACCESS} <= seen


def test_wording():
    web = SCENARIOS["web"].build()[0]
    assert describe(web) == ("Web request", "GET / → 200", "192.168.50.20")
    ev = Event(EventType.PROCESS_EXEC, Source.EBPF, process=proc("/usr/bin/find", ["find", "/", "-perm", "-4000"]))
    assert describe(ev) == ("Program started", "find / -perm -4000 (user 33)", None)
    ev = Event(EventType.NET_CONNECT, Source.EBPF, process=proc(), payload=NetInfo.build(protocol="tcp", remote_addr="10.0.0.5", remote_port=4444))
    assert describe(ev) == ("Outgoing connection", "bash → 10.0.0.5:4444", "10.0.0.5")
    ev = Event(EventType.PRIV_UID_CHANGE, Source.EBPF, process=proc(), payload=PrivInfo(33, 0, 33, 0, Text("setuid")))
    assert describe(ev)[:2] == ("Privilege change", "setuid: user 33 → 0 (became root)")
    ev = Event(EventType.FILE_ACCESS, Source.EBPF, process=proc("/usr/bin/vim"), payload=FileInfo.build(path="/etc/shadow", operation="write"))
    assert describe(ev)[:2] == ("File access", "write /etc/shadow by vim")
    ev = Event(EventType.AUTH_FAILURE, Source.LOG, payload=AuthInfo.build(service="sshd", user="root", remote_addr="203.0.113.7"))
    assert describe(ev) == ("Login failed", "root via sshd", "203.0.113.7")
    ev = Event(EventType.SENSOR_STARTED, Source.EBPF, payload=SensorInfo.build(mode=Source.EBPF, detail="ready"))
    assert describe(ev)[0] == "Erinix sensor" and "ready" in describe(ev)[1]
    ev = Event(EventType.NET_LISTEN, Source.EBPF, process=proc("/usr/sbin/nginx"),
               payload=NetInfo.build(protocol="tcp", local_addr="0.0.0.0", local_port=443))
    assert describe(ev)[:2] == ("Port opened", "nginx listens on port 443")


@pytest.mark.parametrize("evil", ["a\nb\r\nc", "x" * 5000, "\x1b[31mred\x1b[0m", "<script>alert(1)</script>", "tab\tsep\x00nul", "'; DROP TABLE events; --"])
def test_hostile_text_stays_on_one_line_and_bounded(evil):
    events = [
        Event(EventType.AUTH_FAILURE, Source.LOG, payload=AuthInfo.build(service="sshd", user=evil, remote_addr="203.0.113.7")),
        Event(EventType.PROCESS_EXEC, Source.EBPF, process=proc(argv=["bash", evil, evil])),
        Event(EventType.FILE_ACCESS, Source.EBPF, process=proc(), payload=FileInfo.build(path=evil, operation="read")),
    ]
    for event in events:
        label, summary, _ = describe(event)
        assert "\n" not in summary and "\r" not in summary and len(summary) <= MAX_SUMMARY and label


def test_the_log_parser_output_is_described_too():
    from erinix.parsers import parse_caddy_line
    import json
    line = json.dumps({"level": "info", "logger": "http.log.access", "msg": "handled request", "status": 404, "size": 1,
                       "request": {"remote_ip": "198.51.100.9", "client_ip": "198.51.100.9", "method": "GET", "host": "x",
                                   "uri": "/a\nb<script>", "headers": {"User-Agent": ["ua"]}}})
    label, summary, remote = describe(Event(EventType.WEB_REQUEST, Source.LOG, payload=parse_caddy_line(line)))
    assert label == "Web request" and "\n" not in summary and "<script>" in summary and remote == "198.51.100.9"
