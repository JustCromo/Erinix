"""Log sources: files (with rotation), the systemd journal, and container logs, read as they grow.

Every source turns lines into events with one of the production parsers and keeps honest counters
(lines read, understood, ignored), so the dashboard can say what Erinix really sees, and why a source is blind.
A source never raises: it reports its state ("ok", "blind") and a plain-words reason.
"""

from __future__ import annotations

import grp
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable

from erinix.core.events import Event, EventType, Source
from erinix.parsers.auth import parse_ssh_line
from erinix.parsers.combined import parse_combined_line
from erinix.parsers.web import LogParseError, parse_caddy_line

MAX_LINE_BYTES = 65536          # a longer line is dropped, never cut: a cut line could be read as something else
MAX_READ = 1_000_000            # per poll, so one huge burst cannot freeze the loop
MAX_LINES_PER_POLL = 2000
FORMATS = ("caddy", "combined", "ssh")


def _web(info) -> Event:
    return Event(EventType.WEB_REQUEST, Source.LOG, payload=info)


def parse_line(fmt: str, line: str) -> Event | None:
    """One line -> one event, None when the line is not a record of this kind. Raises LogParseError if it is malformed."""
    if fmt == "caddy":
        info = parse_caddy_line(line)
        return None if info is None else _web(info)
    if fmt == "combined":
        info = parse_combined_line(line)
        return None if info is None else _web(info)
    if fmt == "ssh":
        parsed = parse_ssh_line(line)
        return None if parsed is None else Event(parsed.kind, Source.LOG, payload=parsed.info)
    raise ValueError(f"unknown format {fmt!r}")


@dataclass
class Counters:
    lines: int = 0
    understood: int = 0
    ignored: int = 0           # lines that are valid but not about requests/logins (or not in this format)
    last: float = 0.0          # when the last line arrived


@dataclass
class LogSource:
    name: str
    fmt: str
    state: str = "blind"
    detail: str = "not started"
    counters: Counters = field(default_factory=Counters)

    def read_lines(self) -> list[str]:                                   # pragma: no cover - overridden
        return []

    def poll(self, now: Callable[[], float] = time.time) -> list[Event]:
        events: list[Event] = []
        for raw in self.read_lines():
            self.counters.lines += 1
            self.counters.last = now()
            try:
                event = parse_line(self.fmt, raw)
            except LogParseError:
                self.counters.ignored += 1
                continue
            if event is None:
                self.counters.ignored += 1
            else:
                self.counters.understood += 1
                events.append(event)
        return events

    def status(self) -> dict:
        c = self.counters
        return {"name": self.name, "state": self.state, "detail": self.detail, "format": self.fmt,
                "lines": c.lines, "understood": c.understood, "ignored": c.ignored, "last": c.last or None}

    def close(self) -> None:
        pass


class FileTail(LogSource):
    """Follows a file like `tail -F`: starts at the end, survives rotation and truncation, tolerates a missing file."""

    def __init__(self, name: str, path: str, fmt: str, *, from_start: bool = False) -> None:
        super().__init__(name, fmt)
        self.path = path
        self.from_start = from_start
        self._fh = None
        self._ino: tuple[int, int] | None = None
        self._buf = b""
        self._skipping = False

    def _open(self) -> bool:
        try:
            fh = open(self.path, "rb")
        except FileNotFoundError:
            self.state, self.detail = "blind", f"{self.path} does not exist (yet)"
            self.from_start = True                      # when it appears, read it from its first line
            return False
        except PermissionError:
            self.state, self.detail = "blind", f"no permission to read {self.path} (add your user to the group that owns it)"
            return False
        except OSError as exc:
            self.state, self.detail = "blind", f"cannot open {self.path}: {exc.strerror}"
            return False
        st = os.fstat(fh.fileno())
        self._fh, self._ino, self._buf, self._skipping = fh, (st.st_dev, st.st_ino), b"", False
        if not self.from_start and self._ino is not None:
            fh.seek(0, os.SEEK_END)
        self.from_start = True                          # a file that appears or rotates later is read from its beginning
        self.state, self.detail = "ok", self.path
        return True

    def read_lines(self) -> list[str]:
        if self._fh is None and not self._open():
            return []
        try:
            st = os.stat(self.path)
            if (st.st_dev, st.st_ino) != self._ino:                 # rotated: finish the old file, then open the new one
                tail = self._fh.read(MAX_READ)
                self._fh.close()
                self._fh = None
                lines = self._split(tail)
                if self._open():
                    lines += self._split(self._fh.read(MAX_READ))
                return lines
            if st.st_size < self._fh.tell():                        # truncated in place
                self._fh.seek(0)
                self._buf = b""
            return self._split(self._fh.read(MAX_READ))
        except FileNotFoundError:
            self.state, self.detail = "blind", f"{self.path} disappeared (waiting for it)"
            self._fh = None
            return []
        except OSError as exc:
            self.state, self.detail = "blind", f"cannot read {self.path}: {exc.strerror}"
            self._fh = None
            return []

    def _split(self, data: bytes) -> list[str]:
        if not data:
            return []
        self._buf += data
        parts = self._buf.split(b"\n")
        self._buf = parts.pop()
        if len(self._buf) > MAX_LINE_BYTES:                         # an endless line without newline: drop it
            self._buf = b""
        return [p.decode("utf-8", "replace") for p in parts[:MAX_LINES_PER_POLL] if len(p) <= MAX_LINE_BYTES]

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None


class CommandTail(LogSource):
    """Follows the output of a fixed command (journalctl -f, docker logs -f). Restarts it, slowly, if it ends.

    The command is built by Erinix from validated settings; it is never a shell line and never taken from a log.
    """

    RESTART_AFTER = 5.0

    def __init__(self, name: str, argv: list[str], fmt: str, *, merge_stderr: bool = False, clock=time.monotonic) -> None:
        super().__init__(name, fmt)
        self.argv = argv
        self.merge_stderr = merge_stderr
        self.clock = clock
        self._proc: subprocess.Popen | None = None
        self._buf = b""
        self._next_try = 0.0
        self._warm = False

    def _start(self) -> None:
        if self.clock() < self._next_try:
            return
        self._next_try = self.clock() + self.RESTART_AFTER
        exe = shutil.which(self.argv[0])
        if exe is None:
            self.state, self.detail = "blind", f"{self.argv[0]} is not installed"
            return
        try:
            self._proc = subprocess.Popen([exe, *self.argv[1:]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                          stderr=subprocess.STDOUT if self.merge_stderr else subprocess.DEVNULL, close_fds=True)
            os.set_blocking(self._proc.stdout.fileno(), False)
        except OSError as exc:
            self.state, self.detail = "blind", f"cannot run {self.argv[0]}: {exc.strerror}"
            self._proc = None
            return
        self._buf, self._warm = b"", False
        self.state, self.detail = "ok", " ".join(self.argv)

    def read_lines(self) -> list[str]:
        if self._proc is None:
            self._start()
            if self._proc is None:
                return []
        data = b""
        try:
            data = os.read(self._proc.stdout.fileno(), MAX_READ)
        except BlockingIOError:
            pass
        except OSError:
            data = b""
        if not data and self._proc.poll() is not None:
            code = self._proc.returncode
            self.state, self.detail = "blind", f"{self.argv[0]} stopped (exit {code}); retrying"
            self._proc.stdout.close()
            self._proc = None
            return []
        if not data:
            return []
        self._buf += data
        parts = self._buf.split(b"\n")
        self._buf = parts.pop()
        if len(self._buf) > MAX_LINE_BYTES:
            self._buf = b""
        return [p.decode("utf-8", "replace") for p in parts[:MAX_LINES_PER_POLL] if len(p) <= MAX_LINE_BYTES]

    def close(self) -> None:
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                self._proc.kill()
            self._proc.stdout.close()
            self._proc = None


def user_groups() -> set[str]:
    names = set()
    for gid in os.getgroups() + [os.getegid()]:
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return names


def can_read_journal() -> tuple[bool, str]:
    if shutil.which("journalctl") is None:
        return False, "journalctl is not installed (this system does not use the systemd journal)"
    if os.geteuid() == 0 or user_groups() & {"systemd-journal", "adm", "wheel"}:
        return True, ""
    return False, "reading the system journal needs root or the 'systemd-journal' group"
