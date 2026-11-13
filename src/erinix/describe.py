"""One plain-language line for every event: what the live view and the alert timelines show.

The text may carry what an attacker typed (a URL, a user name, a program argument): it is
bounded, kept on one line and otherwise raw. It is escaped where it is displayed, never here.
"""

from __future__ import annotations

import os

from erinix.core.events import Event, EventType

MAX_SUMMARY = 200


def _line(text: object, limit: int = MAX_SUMMARY) -> str:
    flat = " ".join(str(text).split())              # one line: newlines and runs of spaces collapse
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _program(event: Event) -> str:
    p = event.process
    if p is None:
        return "?"
    return os.path.basename(p.exe.value) or p.comm.value or "?"


def describe(event: Event) -> tuple[str, str, str | None]:
    """(label, summary, remote address or None)."""
    t, payload, p = event.type, event.payload, event.process
    remote = getattr(payload, "remote_addr", None)
    where = None if remote is None else str(remote)
    if t is EventType.WEB_REQUEST:
        return "Web request", _line(f"{payload.method} {payload.target.value} → {payload.status}"), where
    if t is EventType.AUTH_FAILURE:
        return "Login failed", _line(f"{payload.user.value} via {payload.service.value}"), where
    if t is EventType.AUTH_SUCCESS:
        return "Login succeeded", _line(f"{payload.user.value} via {payload.service.value}"), where
    if t is EventType.PROCESS_EXEC:
        args = " ".join(a.value for a in p.argv[1:]) if p else ""
        return "Program started", _line(f"{_program(event)}{' ' + args if args else ''} (user {p.uid if p else '?'})"), None
    if t is EventType.PROCESS_EXIT:
        return "Program ended", _line(_program(event)), None
    if t is EventType.NET_CONNECT:
        port = f":{payload.remote_port}" if payload.remote_port else ""
        return "Outgoing connection", _line(f"{_program(event)} → {payload.remote_addr}{port}"), where
    if t is EventType.NET_ACCEPT:
        return "Incoming connection", _line(f"{payload.remote_addr} → port {payload.local_port}"), where
    if t is EventType.NET_LISTEN:
        return "Port opened", _line(f"{_program(event)} listens on port {payload.local_port}"), None
    if t is EventType.PRIV_UID_CHANGE:
        root = " (became root)" if payload.became_root else ""
        return "Privilege change", _line(f"{payload.method.value}: user {payload.old_euid} → {payload.new_euid}{root}"), None
    if t is EventType.FILE_ACCESS:
        return "File access", _line(f"{payload.operation} {payload.path.value} by {_program(event)}"), None
    return "Erinix sensor", _line(f"{t.value}: {getattr(payload, 'detail', '')}"), None
