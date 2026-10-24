"""Reproducible event traces (no real process is touched)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from erinix.core.events import (
    AuthInfo, Event, EventType, FileInfo, NetInfo, PrivInfo, ProcessInfo, Source, Text,
)

SEC = 1_000_000_000


def _p(pid, start, ppid=None, pstart=None, exe="/usr/bin/bash", uid=33, loginuid=None, argv=None):
    return ProcessInfo.build(pid=pid, start_ns=start, uid=uid, euid=uid, exe=exe,
                             argv=argv or [exe], comm=exe.rsplit("/", 1)[-1], ppid=ppid,
                             parent_start_ns=pstart, loginuid=loginuid)


def _exec(p, sec):
    return Event(EventType.PROCESS_EXEC, Source.EBPF, process=p, mono_ns=int(sec * SEC))


def _connect(p, ip, port, sec):
    pl = NetInfo.build(protocol="tcp", remote_addr=ip, remote_port=port)
    return Event(EventType.NET_CONNECT, Source.EBPF, process=p, payload=pl, mono_ns=int(sec * SEC))


def _uid(p, sec, old=33, method="setuid"):
    return Event(EventType.PRIV_UID_CHANGE, Source.EBPF, process=p,
                 payload=PrivInfo(old, 0, old, 0, Text(method)), mono_ns=int(sec * SEC))


def _auth(kind, ip, sec, user="root"):
    return Event(kind, Source.AUDITD, mono_ns=int(sec * SEC),
                 payload=AuthInfo.build(service="sshd", user=user, remote_addr=ip))


def _write(p, path, sec):
    return Event(EventType.FILE_ACCESS, Source.EBPF, process=p, mono_ns=int(sec * SEC),
                 payload=FileInfo.build(path=path, operation="write"))


def _revshell() -> list[Event]:
    apache = _p(500, 10, 1, 0, "/usr/sbin/apache2", uid=33)
    worker = _p(510, 11, 500, 10, "/usr/sbin/apache2")
    shell = _p(900, 20, 500, 10)
    find = _p(950, 30, 900, 20, "/usr/bin/find", argv=["find", "/", "-perm", "-4000"])
    return [_exec(apache, 0.5), _exec(worker, 1.0), _exec(shell, 3.0),
            _connect(shell, "10.0.0.5", 4444, 4.5), _exec(find, 6.0), _uid(shell, 8.0)]


def _bruteforce() -> list[Event]:
    ip = "203.0.113.7"
    fail = EventType.AUTH_FAILURE
    ev = [_auth(fail, ip, 0.4 * i) for i in range(5)]
    ev.insert(2, _auth(fail, "198.51.100.20", 0.9, user="admin"))
    ev.append(_auth(EventType.AUTH_SUCCESS, ip, 4.0))
    return ev


def _admin() -> list[Event]:
    sshd = _p(700, 5, 1, 0, "/usr/sbin/sshd", uid=0)
    admin = _p(1200, 50, 700, 5, loginuid=1000, uid=1000)
    sudo = _p(1250, 60, 1200, 50, "/usr/bin/sudo", uid=1000, loginuid=1000, argv=["sudo", "-l"])
    return [_exec(sshd, 0.5), _exec(admin, 1.5), _exec(sudo, 3.0),
            _connect(admin, "93.184.216.34", 443, 4.5), _uid(admin, 6.0, old=1000, method="sudo")]


def _shadow() -> list[Event]:
    return [_write(_p(2001, 5, exe="/usr/bin/passwd", uid=0), "/etc/shadow", 0.5),
            _write(_p(2000, 6, exe="/usr/bin/vim", uid=1000), "/etc/shadow", 2.0)]


@dataclass(frozen=True, slots=True)
class Scenario:
    name: str
    title: str
    description: str
    build: Callable[[], list[Event]]
    expect_alerts: bool


SCENARIOS: dict[str, Scenario] = {s.name: s for s in (
    Scenario("revshell", "Compromised web server",
             "The web server spawns a shell, the shell opens an outbound connection, then becomes root.",
             _revshell, True),
    Scenario("bruteforce", "Brute force SSH",
             "Five failed logins from the same address, then a successful one. Another IP makes noise.",
             _bruteforce, True),
    Scenario("shadow", "Tampering with /etc/shadow",
             "passwd writes the file (normal); vim writes it (unexpected).",
             _shadow, True),
    Scenario("admin", "Administrator at work",
             "SSH session, sudo -l, outbound connection and sudo: legitimate activity, no alerts.",
             _admin, False),
)}
