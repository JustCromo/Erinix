"""sshd log messages -> authentication events.

The classic log-injection trick: an attacker picks a user name that CONTAINS a
fake tail ("admin from 10.0.0.1 port 22 ssh2") so a naive parser blames
somebody else. We parse from the END of the message: the real address is
always the last "from <ip> port <n>" that sshd appends.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from erinix.core.events import AuthInfo, EventType
from erinix.parsers.web import LogParseError

MAX_MESSAGE = 8192        # real sshd lines are far shorter; longer ones are rejected, never cut

_FAILURES = ("Failed password for ", "Failed publickey for ", "Failed keyboard-interactive/pam for ",
             "Failed none for ", "Invalid user ")
_SUCCESSES = ("Accepted password for ", "Accepted publickey for ", "Accepted keyboard-interactive/pam for ")


@dataclass(frozen=True, slots=True)
class SshEvent:
    kind: EventType            # AUTH_FAILURE or AUTH_SUCCESS
    info: AuthInfo


def _is_iso_timestamp(token: str) -> bool:
    return len(token) >= 19 and token[:4].isdigit() and token[4] == "-" and "T" in token


def extract_ssh_message(line: str) -> str | None:
    """Message of a syslog line written BY sshd; None for lines from any other program.

    The program tag must be exactly where syslog puts it (right after the host name).
    Text that merely CONTAINS "sshd[1]: ..." inside another program's message is
    attacker-controlled and must never be mistaken for an sshd record.
    """
    parts = line.split(None, 3)
    if len(parts) < 4:
        return None
    if _is_iso_timestamp(parts[0]):                 # 2026-11-12T10:00:00+01:00 host tag[pid]: message
        tag, message = parts[2], parts[3]
    else:                                           # Nov 12 10:00:00 host tag[pid]: message
        parts = line.split(None, 5)
        if len(parts) < 6:
            return None
        tag, message = parts[4], parts[5]
    name, bracket, rest = tag.partition("[")
    pid, closing, tail = rest.partition("]")
    if name not in ("sshd", "sshd-session") or not bracket or not closing or tail != ":" or not pid.isdigit():
        return None
    return message


def _split_tail(rest: str) -> tuple[str, str] | None:
    """'<user> from <ip> port <n>...' -> (user, ip), reading from the END."""
    idx = rest.rfind(" from ")
    while idx != -1:
        tail = rest[idx + 6:].split(" ")
        if len(tail) >= 3 and tail[1] == "port" and tail[2].isascii() and tail[2].isdigit() \
                and len(tail[2]) <= 5 and int(tail[2]) <= 65535:
            try:
                return rest[:idx], str(ipaddress.ip_address(tail[0]))
            except ValueError:
                return None            # the real tail is invalid: never fall back to a forged one
        idx = rest.rfind(" from ", 0, idx)
    return None


def parse_ssh_message(message: str) -> SshEvent | None:
    """Return an event, None for lines we do not care about, or raise LogParseError."""
    msg = message
    if len(msg) > MAX_MESSAGE:
        raise LogParseError("sshd message too long")      # cutting it would lose the real address tail
    kind: EventType | None = None
    rest = ""
    for prefix in _FAILURES:
        if msg.startswith(prefix):
            kind, rest = EventType.AUTH_FAILURE, msg[len(prefix):]
            break
    else:
        for prefix in _SUCCESSES:
            if msg.startswith(prefix):
                kind, rest = EventType.AUTH_SUCCESS, msg[len(prefix):]
                break
    if kind is None:
        return None
    if rest.startswith("invalid user "):
        rest = rest[len("invalid user "):]
    parts = _split_tail(rest)
    if parts is None:
        raise LogParseError("sshd line without a valid 'from <address> port <n>' tail")
    user, address = parts
    return SshEvent(kind, AuthInfo.build(service="sshd", user=user, remote_addr=address))


def parse_ssh_line(line: str) -> SshEvent | None:
    """Parse a full syslog line (auth.log style). Lines from other programs are ignored."""
    message = extract_ssh_message(line)
    return None if message is None else parse_ssh_message(message)
