"""Rootless process sensor: reads /proc and reports what starts, and who becomes root.

It works for any user (without root only what that user may read is complete) and on any Linux.
Limits, said plainly: it polls, so a program that starts and ends between two polls is missed;
eBPF (with root) has no such gap. Everything read from /proc is untrusted text: it is only length-limited here.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from erinix.core.events import (Event, EventType, PrivInfo, ProcessInfo, SensorInfo, Source, Text)

try:
    CLK_TCK = os.sysconf("SC_CLK_TCK")
except (ValueError, OSError):                      # pragma: no cover - every Linux has it
    CLK_TCK = 100
MAX_CMDLINE = 8192                  # bytes read from /proc/<pid>/cmdline
MAX_NEW_PER_POLL = 300              # a fork bomb must not become an event bomb
MAX_ARGS_KEPT = 64


@dataclass(frozen=True, slots=True)
class ProcRecord:
    pid: int
    ppid: int
    start_ticks: int
    uid: int
    euid: int
    comm: str
    exe: str
    argv: tuple[str, ...]

    @property
    def start_ns(self) -> int:
        return self.start_ticks * (1_000_000_000 // CLK_TCK)

    @property
    def key(self) -> tuple[int, int]:
        return (self.pid, self.start_ticks)

    @property
    def command(self) -> str:
        return " ".join(self.argv) if self.argv else (self.exe or self.comm)


def _read(path: str, limit: int) -> bytes | None:
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except OSError:
        return None


def read_process(pid: int, proc: str = "/proc") -> ProcRecord | None:
    """One process, or None if it vanished, is a kernel thread, or cannot be read at all."""
    stat = _read(f"{proc}/{pid}/stat", 4096)
    if not stat:
        return None
    text = stat.decode("utf-8", "replace")
    left, right = text.find("("), text.rfind(")")          # the name may contain spaces and brackets
    if left < 0 or right < left:
        return None
    comm = text[left + 1:right]
    rest = text[right + 2:].split()
    try:
        ppid, start_ticks = int(rest[1]), int(rest[19])
    except (IndexError, ValueError):
        return None
    if pid == 2 or ppid == 2:                              # kernel threads: not programs
        return None
    uid = euid = 0
    status = _read(f"{proc}/{pid}/status", 8192)
    if status:
        for line in status.decode("utf-8", "replace").splitlines():
            if line.startswith("Uid:"):
                parts = line.split()
                try:
                    uid, euid = int(parts[1]), int(parts[2])
                except (IndexError, ValueError):
                    pass
                break
    try:
        exe = os.readlink(f"{proc}/{pid}/exe")
    except OSError:
        exe = ""
    if exe.endswith(" (deleted)"):
        exe = exe[: -len(" (deleted)")]
    raw = _read(f"{proc}/{pid}/cmdline", MAX_CMDLINE) or b""
    argv = tuple(a.decode("utf-8", "backslashreplace") for a in raw.split(b"\0") if a)[:MAX_ARGS_KEPT]
    if not argv and not exe:
        return None                                        # nothing to show (zombie or unreadable)
    return ProcRecord(pid, ppid, start_ticks, uid, euid, comm, exe, argv)


def scan(proc: str = "/proc") -> dict[int, ProcRecord]:
    found: dict[int, ProcRecord] = {}
    try:
        names = os.listdir(proc)
    except OSError:
        return found
    for name in names:
        if name.isascii() and name.isdigit():
            record = read_process(int(name), proc)
            if record is not None:
                found[record.pid] = record
    return found


def to_info(record: ProcRecord, parent: ProcRecord | None) -> ProcessInfo:
    return ProcessInfo.build(
        pid=record.pid, start_ns=record.start_ns, uid=record.uid, euid=record.euid,
        exe=record.exe or None, argv=list(record.argv), comm=record.comm,
        ppid=record.ppid if parent is not None else None,
        parent_start_ns=parent.start_ns if parent is not None else None)


class ProcessSensor:
    """Compares two looks at /proc: new programs become process.exec, a user that turns root becomes priv.uid_change."""

    name = "Programs and commands"

    def __init__(self, proc: str = "/proc") -> None:
        self.proc = proc
        self.known: dict[int, ProcRecord] = {}
        self.baseline_done = False
        self.error = ""

    def poll(self) -> list[Event]:
        now = scan(self.proc)
        if not now:
            self.error = "cannot read /proc"
            return []
        self.error = ""
        events: list[Event] = []
        if self.baseline_done:
            new = [r for r in now.values() if self.known.get(r.pid) is None or self.known[r.pid].key != r.key]
            new = [r for r in new if r.ppid != os.getpid()]       # Erinix's own helpers (journalctl, docker) are not news
            new.sort(key=lambda r: r.start_ticks)
            for record in new[:MAX_NEW_PER_POLL]:
                events.append(Event(EventType.PROCESS_EXEC, Source.MINIMAL, process=to_info(record, now.get(record.ppid))))
            if len(new) > MAX_NEW_PER_POLL:
                events.append(Event(EventType.SENSOR_EVENTS_LOST, Source.MINIMAL,
                                    payload=SensorInfo.build(mode=Source.MINIMAL, detail="too many new programs in one moment",
                                                             lost=len(new) - MAX_NEW_PER_POLL)))
            for record in now.values():
                before = self.known.get(record.pid)
                if before is not None and before.key == record.key and before.euid != 0 and record.euid == 0:
                    payload = PrivInfo(before.uid, record.uid, before.euid, record.euid, Text("observed"))
                    events.append(Event(EventType.PRIV_UID_CHANGE, Source.MINIMAL, process=to_info(record, now.get(record.ppid)), payload=payload))
        self.known = now
        self.baseline_done = True
        return events

    def uptime_seconds(self) -> float:
        raw = _read(f"{self.proc}/uptime", 64)
        try:
            return float(raw.split()[0]) if raw else time.monotonic()
        except (ValueError, IndexError):
            return 0.0
