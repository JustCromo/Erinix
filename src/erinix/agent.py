"""The agent: looks at the machine again and again and hands what it sees to the engine.

One loop, three kinds of eyes: running programs, network connections, and log sources. Every event goes through the
same Recorder the demo uses, so alerts, incidents and the dashboard behave identically. Each look is isolated: a
source that fails is marked as such and the others keep working.
"""

from __future__ import annotations

import os
import socket
import time
from typing import Callable

from erinix import __version__
from erinix.config import Config
from erinix.core.events import Event
from erinix.recorder import Recorder
from erinix.sensors.netproc import NetworkSensor
from erinix.sensors.procfs import ProcessSensor

INVENTORY_EVERY = 2.5
PRUNE_EVERY = 600.0
MAX_PROCESSES = 400


def _host() -> dict:
    uname = os.uname()
    return {"name": uname.nodename, "system": f"{uname.sysname} {uname.release}", "machine": uname.machine,
            "user": _user(), "root": os.geteuid() == 0, "version": __version__}


def _user() -> str:
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except (ImportError, KeyError):
        return str(os.geteuid())


class Agent:
    def __init__(self, store, recorder: Recorder, config: Config, *, proc: str = "/proc", clock: Callable[[], float] = time.time) -> None:
        self.store, self.recorder, self.config, self.clock = store, recorder, config, clock
        self.processes = ProcessSensor(proc) if config.processes else None
        self.network = NetworkSensor(self.processes, proc) if config.network and self.processes else None
        self.logs = [spec.build() for spec in config.sources]
        self.events = 0
        self.alerts = 0
        self._inventory_at = 0.0
        self._prune_at = clock()
        self._last_beat = 0.0
        self.started = clock()

    # ------------------------------------------------------------ one look
    def step(self) -> int:
        """Look once at everything. Returns how many events were handled."""
        batch: list[Event] = []
        for eyes in (self.processes, self.network, *self.logs):
            if eyes is None:
                continue
            try:
                batch.extend(eyes.poll())
            except Exception as exc:                       # one broken source must not stop the others
                if hasattr(eyes, "state"):
                    eyes.state, eyes.detail = "blind", f"error: {type(exc).__name__}"
                else:
                    eyes.error = f"error: {type(exc).__name__}"
        for event in batch:
            try:
                self.alerts += len(self.recorder.feed(event))
            except Exception:                              # a bad event is skipped, never fatal
                continue
        self.events += len(batch)
        now = self.clock()
        if now - self._last_beat >= 1.0:
            self._last_beat = now
            self.store.set_meta("heartbeat", now)
        if now - self._inventory_at >= INVENTORY_EVERY:
            self._inventory_at = now
            try:
                self.store.set_meta("sources", self.sources())
                self.store.set_meta("inventory", self.inventory())
            except Exception:                              # the picture of the machine may fail; watching must not
                pass
        if now - self._prune_at >= PRUNE_EVERY:
            self._prune_at = now
            self.store.prune(now=now)
        return len(batch)

    # ------------------------------------------------------------ what it sees
    def sources(self) -> list[dict]:
        rows = []
        if self.processes is not None:
            rows.append({"name": self.processes.name, "state": "blind" if self.processes.error else "ok",
                         "detail": self.processes.error or "polling /proc (very short programs can slip between two looks)"})
        if self.network is not None:
            rows.append({"name": self.network.name, "state": "blind" if self.network.error else "ok",
                         "detail": self.network.error or ("all users" if os.geteuid() == 0 else "your own programs only (run as root to see all)")})
        rows.extend(log.status() for log in self.logs)
        return rows

    def inventory(self) -> dict:
        listening, connections = ([], [])
        if self.network is not None:
            listening, connections = self.network.inventory()
        procs = []
        if self.processes is not None:
            for rec in sorted(self.processes.known.values(), key=lambda r: -r.start_ticks)[:MAX_PROCESSES]:
                procs.append({"pid": rec.pid, "ppid": rec.ppid, "uid": rec.uid, "name": rec.comm, "command": rec.command[:300]})
        return {"at": self.clock(), "host": _host(), "processes": procs, "process_total": len(self.processes.known) if self.processes else 0,
                "listening": listening, "connections": connections}

    # ------------------------------------------------------------ the loop
    def start(self) -> None:
        self.store.set_meta("mode", "live")
        self.store.set_meta("started", self.started)
        self.step()

    def run(self, *, duration: float | None = None, stop: Callable[[], bool] = lambda: False,
            sleep: Callable[[float], None] = time.sleep) -> dict:
        self.start()
        end = None if duration is None else self.clock() + duration
        try:
            while not stop() and (end is None or self.clock() < end):
                began = self.clock()
                self.step()
                sleep(max(0.0, self.config.interval - (self.clock() - began)))
        finally:
            self.close()
        return {"events": self.events, "alerts": self.alerts}

    def close(self) -> None:
        for log in self.logs:
            log.close()


def hostname() -> str:
    return socket.gethostname()
