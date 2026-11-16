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
from erinix.sensors.scanwatch import ScanSensor

INVENTORY_EVERY = 2.5
PRUNE_EVERY = 600.0
ASSESS_EVERY = 1800.0
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
    def __init__(self, store, recorder: Recorder, config: Config, *, proc: str = "/proc", clock: Callable[[], float] = time.time, view=None, assess: bool = False) -> None:
        self.store, self.recorder, self.config, self.clock = store, recorder, config, clock
        self.view = view                                   # None: look at /proc ourselves; else a privileged helper looks for us
        self.privileged = os.geteuid() == 0
        self.processes = ProcessSensor(proc, view) if config.processes else None
        self.network = NetworkSensor(self.processes, proc, view=view) if config.network and self.processes else None
        self.scans = ScanSensor(view, privileged=self.privileged) if config.network else None
        self.logs = [spec.build() for spec in config.sources]
        self.events = 0
        self.alerts = 0
        self._inventory_at = 0.0
        self._prune_at = clock()
        self._last_beat = 0.0
        self.assess = assess                               # check the machine's posture now and every half hour (in a side thread)
        self._assess_at = -1e9
        self._assess_result: dict | None = None
        self._assess_thread = None
        self._assess_seen = None
        self.started = clock()

    # ------------------------------------------------------------ one look
    def step(self) -> int:
        """Look once at everything. Returns how many events were handled."""
        batch: list[Event] = []
        for eyes in (self.processes, self.network, self.scans, *self.logs):
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
        self._assessment(now)
        return len(batch)

    def request_assessment(self) -> None:
        """Check again as soon as possible (the cockpit's `a` key)."""
        self._assess_at = -1e9
        nudge = getattr(self.view, "nudge", None)
        if nudge is not None:
            nudge()

    def _assessment(self, now: float) -> None:
        """The posture check reads many files, so it runs beside the loop; only this thread of the loop touches the store."""
        if self._assess_result is not None:
            try:
                self.store.set_meta("assessment", self._assess_result)
            except Exception:
                pass
            self._assess_result = None
        if self.assess and self.view is not None and hasattr(self.view, "assessment"):     # a root helper does it with root's eyes
            got = self.view.assessment
            if got is not None and got is not self._assess_seen:
                self._assess_seen = got
                try:
                    self.store.set_meta("assessment", got)
                except Exception:
                    pass
            return
        if not self.assess or now - self._assess_at < ASSESS_EVERY or (self._assess_thread is not None and self._assess_thread.is_alive()):
            return
        self._assess_at = now
        import threading

        from erinix.assessment import Env, run_assessment

        def work() -> None:
            try:
                self._assess_result = run_assessment(Env(full_view=self.privileged))
            except Exception:
                pass

        self._assess_thread = threading.Thread(target=work, name="erinix-assess", daemon=True)
        self._assess_thread.start()

    # ------------------------------------------------------------ what it sees
    def sources(self) -> list[dict]:
        rows = []
        if self.processes is not None:
            rows.append({"name": self.processes.name, "state": "blind" if self.processes.error else "ok",
                         "detail": self.processes.error or "polling /proc (very short programs can slip between two looks)"})
        if self.network is not None:
            rows.append({"name": self.network.name, "state": "blind" if self.network.error else "ok",
                         "detail": self.network.error or ("all users" if self.privileged else "your own programs only (press R in the console to see all)")})
        if self.scans is not None:
            rows.append(self.scans.status())
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
        return {"at": self.clock(), "host": {**_host(), "root": self.privileged}, "processes": procs, "process_total": len(self.processes.known) if self.processes else 0,
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
        if self.scans is not None:
            self.scans.close()
        for log in self.logs:
            log.close()


def hostname() -> str:
    return socket.gethostname()
