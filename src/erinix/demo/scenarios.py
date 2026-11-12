"""Reproducible event traces (no real process is touched)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from erinix.core.events import (
    AuthInfo, Event, EventType, FileInfo, NetInfo, PrivInfo, ProcessInfo, Source, Text,
)
from erinix.parsers import parse_caddy_line, parse_ssh_line

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


def _caddy(ip, method, uri, status, sec, ua="Mozilla/5.0 (X11; Linux x86_64) Firefox/133.0"):
    """A request as a REAL Caddy access-log line, parsed by the production parser."""
    line = json.dumps({"level": "info", "logger": "http.log.access.log0", "msg": "handled request",
                       "request": {"remote_ip": ip, "client_ip": ip, "method": method, "host": "racoonix.lan",
                                   "uri": uri, "headers": {"User-Agent": [ua]}},
                       "size": 512, "status": status})
    info = parse_caddy_line(line)
    return Event(EventType.WEB_REQUEST, Source.LOG, payload=info, mono_ns=int(sec * SEC))


def _ssh(message, sec):
    """An sshd line as written in the system log, parsed by the production parser."""
    parsed = parse_ssh_line(message)
    return Event(parsed.kind, Source.LOG, payload=parsed.info, mono_ns=int(sec * SEC))


def _web() -> list[Event]:
    attacker, user, other = "192.168.50.31", "192.168.50.20", "192.168.50.44"
    events = [_caddy(user, "GET", "/", 200, 0.2), _caddy(user, "GET", "/static/app.js", 200, 0.4)]
    for i, path in enumerate(["/admin", "/backup", "/.git/config", "/wp-login.php", "/phpmyadmin", "/old",
                              "/test", "/api/v1/users", "/config", "/db", "/.env"]):
        events.append(_caddy(attacker, "GET", path, 404, 1.0 + i * 0.3, ua="python-requests/2.31"))
    events += [
        _caddy(attacker, "GET", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 200, 5.5),
        _caddy(attacker, "GET", "/view?page=..%2f..%2f..%2fetc%2fpasswd", 200, 6.5),
        _caddy(attacker, "GET", "/search?q=<script>alert(1)</script>", 200, 7.5),
        _caddy(attacker, "GET", "/ping?host=8.8.8.8%3Bcat%20%2Fvar%2Fdata", 200, 8.0),
        _caddy(attacker, "GET", "/products?id=5", 200, 8.5, ua="sqlmap/1.7.11#stable (https://sqlmap.org)"),
    ]
    for i in range(8):
        events.append(_caddy(other, "POST", "/login", 401, 9.0 + i * 0.4))
    events.append(_caddy(other, "POST", "/login", 302, 13.0))
    return events


def _webquiet() -> list[Event]:
    ip = "192.168.50.20"
    pages = ["/", "/static/app.js", "/static/style.css", "/products?sort=price&select=all", "/union-members",
             "/search?q=union+station", "/about", "/products?id=7", "/products?id=8"]
    events = [_caddy(ip, "GET", p, 200, 0.5 + i * 0.5) for i, p in enumerate(pages)]
    events += [_caddy(ip, "GET", "/favicon.ico", 404, 6.0), _caddy(ip, "GET", "/robots.txt", 404, 6.5),
               _caddy(ip, "POST", "/login", 401, 7.0), _caddy(ip, "POST", "/login", 302, 8.0)]
    return events


def _ssh_log() -> list[Event]:
    pi = "Nov 12 10:00:{:02d} pi sshd-session[812]: "
    attacker = "203.0.113.50 port 4444 ssh2"
    lines = [(0.2, pi.format(0) + f"Failed password for invalid user admin from {attacker}"),
             (0.8, pi.format(1) + f"Failed password for root from {attacker}"),
             # log injection: the user name carries a fake "from 198.51.100.9" tail, trying to frame someone else
             (1.4, pi.format(1) + f"Failed password for invalid user x from 198.51.100.9 port 22 ssh2 from {attacker}"),
             (2.0, pi.format(2) + f"Failed password for invalid user test from {attacker}"),
             (2.6, pi.format(3) + f"Failed password for invalid user oracle from {attacker}"),
             (3.2, pi.format(3) + "Failed password for invalid user guest from 192.0.2.77 port 5000 ssh2"),
             (6.0, pi.format(6) + f"Accepted password for root from {attacker}")]
    return [_ssh(text, sec) for sec, text in lines]


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
    Scenario("web", "Attacks on a web app",
             "Caddy access-log lines: page scanning, then SQL injection, path traversal, script injection and a "
             "scanner; elsewhere, password guessing on the login form.",
             _web, True),
    Scenario("webquiet", "Normal web traffic",
             "Ordinary browsing, a search for \"union station\", a few missing icons and a normal login: no alerts.",
             _webquiet, False),
    Scenario("ssh", "SSH password guessing in the system log",
             "sshd log lines, including a fake user name that tries to frame another address. Only the real "
             "source may be blamed.",
             _ssh_log, True),
    Scenario("admin", "Administrator at work",
             "SSH session, sudo -l, outbound connection and sudo: legitimate activity, no alerts.",
             _admin, False),
)}
