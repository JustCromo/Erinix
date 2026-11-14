"""Runs the agent inside the program you are looking at, so one `erinix` is enough.

One agent per user at a time: a lock file decides who it is. A second `erinix` becomes a plain viewer of the same store.
"""

from __future__ import annotations

import fcntl
import os
import threading
import time
from pathlib import Path

from erinix import config as cfg
from erinix.agent import Agent
from erinix.engine import Correlator
from erinix.history import state_dir
from erinix.recorder import Recorder
from erinix.store import Store


class AgentLock:
    """flock on a private file: released by the kernel even if the process dies."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or state_dir() / "agent.lock"
        self.fd: int | None = None

    def acquire(self) -> bool:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self.fd = fd
        return True

    def release(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            finally:
                self.fd = None


class AgentRuntime:
    """Starts watching in a background thread. `role` is 'agent' (we watch) or 'viewer' (someone else already does)."""

    def __init__(self, *, ruleset, config: cfg.Config | None = None, config_path: str | None = None, db_path=None,
                 lock: AgentLock | None = None, elevate: bool = False, helper=None) -> None:
        self.ruleset, self.db_path = ruleset, db_path
        self.config, self.origin = (config, "given") if config is not None else cfg.load(config_path)
        self.lock = lock or AgentLock()
        self.elevate, self.helper = elevate, helper
        self.role = "viewer"
        self.mode = "limited"                      # 'full' once a root helper is feeding us
        self.note = ""
        self.error = ""
        self.agent: Agent | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._store: Store | None = None
        self._ready = threading.Event()

    def start(self) -> str:
        if not self.lock.acquire():
            self.role = "viewer"
            return self.role
        self.role = "agent"
        view = None
        if os.geteuid() == 0:
            self.mode = "full"
        elif self.elevate and self.helper is not None:
            if self.helper.start():
                view, self.mode = self.helper.view, "full"
                self.note = self.helper.view.note
            else:
                self.note = self.helper.error
        self._thread = threading.Thread(target=self._loop, args=(view,), name="erinix-agent", daemon=True)
        self._thread.start()
        self._ready.wait(10)
        if self.error:
            self.stop()
            self.role = "viewer"
        return self.role

    def _loop(self, view) -> None:
        """Everything that touches the store happens in this one thread (sqlite connections are per thread)."""
        try:
            store = self._store = Store(path=self.db_path) if self.db_path else Store()
            if store.get_meta("mode") != "live":
                store.reset()
            agent = self.agent = Agent(store, Recorder(store, Correlator(self.ruleset)), self.config, view=view)
            agent.privileged = self.mode == "full"
            agent.start()
        except Exception as exc:
            self.error = f"cannot start watching: {exc}"
            self._ready.set()
            return
        self._ready.set()
        while not self._stop.is_set():
            began = time.time()
            try:
                agent.step()
            except Exception as exc:
                self.error = f"watching hiccup: {type(exc).__name__}"
            self._stop.wait(max(0.05, self.config.interval - (time.time() - began)))
        agent.close()
        store.close()
        self._store = None

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
            self._thread = None
        if self.helper is not None:
            self.helper.stop()
        self.lock.release()
