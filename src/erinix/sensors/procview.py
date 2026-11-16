"""Where the sensors get their picture of /proc: here, or from a privileged helper.

Reading other users' sockets needs root. Instead of running all of Erinix as root, a tiny helper (`erinix helper`,
started through sudo) only READS /proc and sends plain snapshots down a pipe. Everything else (diffing, rules,
storage, the dashboard) keeps running as the normal user. The snapshot is data from a machine an attacker may
control (command lines!), so the receiving side checks every field's type, size and range.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import threading
import time
from typing import Callable, TextIO

from erinix import __version__
from erinix.sensors import netproc, procfs
from erinix.sensors.netproc import Socket
from erinix.sensors.procfs import ProcRecord
from erinix.ui.render import safe

MAX_LINE = 8_000_000
MAX_PROCS = 20_000
MAX_SOCKETS = 5_000
MAX_OWNERS = 20_000
OWNERS_EVERY = 2.0
STATES = ("01", "0A")                                     # established, listening: the only ones that matter


class LocalView:
    """Reads this machine's /proc with the rights of the current user."""

    def __init__(self, proc: str = "/proc") -> None:
        self.proc = proc
        self.privileged = os.geteuid() == 0
        self.note = ""

    def scan(self) -> dict[int, ProcRecord]:
        return procfs.scan(self.proc)

    def sockets(self) -> list[Socket]:
        return netproc.read_sockets(self.proc)

    def owners(self) -> dict[int, int]:
        return netproc.inode_owners(self.proc)


# ------------------------------------------------------------------ the wire format
def _int(value: object, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError("number out of range")
    return value


def _text(value: object, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError("bad text")
    return value


def encode_snapshot(procs: dict[int, ProcRecord], socks: list[Socket], owners: dict[int, int]) -> str:
    data = {"t": "snap",
            "procs": [[r.pid, r.ppid, r.start_ticks, r.uid, r.euid, r.comm, r.exe, list(r.argv)] for r in procs.values()][:MAX_PROCS],
            "socks": [[s.proto, s.local, s.lport, s.remote, s.rport, s.state, s.uid, s.inode] for s in socks if s.state in STATES][:MAX_SOCKETS],
            "owners": {str(k): v for k, v in list(owners.items())[:MAX_OWNERS]}}
    return json.dumps(data, separators=(",", ":"))


def decode_snapshot(line: str) -> tuple[dict[int, ProcRecord], list[Socket], dict[int, int]] | None:
    """Strictly validated; anything odd makes the whole snapshot count as absent (None)."""
    try:
        data = json.loads(line)
        if not isinstance(data, dict) or data.get("t") != "snap":
            return None
        procs: dict[int, ProcRecord] = {}
        for row in data["procs"][:MAX_PROCS]:
            pid, ppid, start, uid, euid, comm, exe, argv = row
            if not isinstance(argv, list) or len(argv) > procfs.MAX_ARGS_KEPT:
                raise ValueError("bad argv")
            args = tuple(_text(a, procfs.MAX_CMDLINE) for a in argv)
            procs[_int(pid, 1, 2**31)] = ProcRecord(pid, _int(ppid, 0, 2**31), _int(start, 0, 2**62), _int(uid, 0, 2**32), _int(euid, 0, 2**32),
                                                    _text(comm, 256), _text(exe, 4096), args)
        socks: list[Socket] = []
        for proto, local, lport, remote, rport, state, uid, inode in data["socks"][:MAX_SOCKETS]:
            if proto != "tcp" or state not in STATES:
                raise ValueError("bad socket")
            ipaddress.ip_address(_text(local, 64)), ipaddress.ip_address(_text(remote, 64))
            socks.append(Socket(proto, local, _int(lport, 0, 65535), remote, _int(rport, 0, 65535), state, _int(uid, 0, 2**32), _int(inode, 0, 2**63)))
        owners: dict[int, int] = {}
        for inode, pid in list(data["owners"].items())[:MAX_OWNERS]:
            owners[_int(int(inode), 0, 2**63)] = _int(pid, 1, 2**31)
        return procs, socks, owners
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def decode_scan(line: str):
    """One port scan seen by the helper. The source is a packet's address: checked like any other untrusted text."""
    from erinix.core.events import SCAN_KINDS
    from erinix.sensors.scanwatch import Detection

    try:
        d = json.loads(line)
        src = _text(d["src"], 64)
        ipaddress.ip_address(src)
        if d["kind"] not in SCAN_KINDS or not isinstance(d["ports"], list) or len(d["ports"]) > 16:
            raise ValueError("bad scan")
        return Detection(src, d["kind"], _int(d["count"], 1, 65536), tuple(_int(p, 1, 65535) for p in d["ports"]))
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


def encode_scan(found) -> str:
    return json.dumps({"t": "scan", "src": found.src, "kind": found.kind, "count": found.port_count, "ports": list(found.ports)}, separators=(",", ":"))


STATES_OK = ("ok", "warn", "fail", "unknown", "info", "na")
SEVERITIES = ("high", "medium", "low")
ASSESS_EVERY = 300.0


def encode_assessment(result: dict) -> str:
    return json.dumps({"t": "assess", "data": result}, separators=(",", ":"))


def decode_assessment(line: str) -> dict | None:
    """The posture check done with root's eyes, validated like everything else that crosses the pipe."""
    try:
        data = json.loads(line)["data"]
        checks = []
        for c in data["checks"][:60]:
            if c["state"] not in STATES_OK or c["severity"] not in SEVERITIES:
                raise ValueError("bad check")
            checks.append({"id": _text(c["id"], 60), "area": _text(c["area"], 60), "title": _text(c["title"], 120), "severity": c["severity"],
                           "state": c["state"], "detail": _text(c["detail"], 400), "fix": _text(c["fix"], 400)})
        counts = {k: _int(data["counts"][k], 0, 1000) for k in STATES_OK}
        return {"at": float(data["at"]), "score": _int(data["score"], 0, 100), "verdict": _text(data["verdict"], 120), "counts": counts,
                "checks": checks, "full_view": data["full_view"] is True}
    except (ValueError, KeyError, TypeError, AttributeError, IndexError):
        return None


def decode_result(line: str) -> dict | None:
    try:
        d = json.loads(line)
        undo = d.get("undo")
        if undo is not None:
            if not isinstance(undo, dict) or len(json.dumps(undo)) > 20_000:
                raise ValueError("bad undo")
        return {"id": _int(d["id"], 1, 2**31), "ok": d["ok"] is True, "message": _text(d["message"], 400), "undo": undo}
    except (ValueError, KeyError, TypeError, AttributeError):
        return None


class RemoteView:
    """The same picture, taken by someone else (the helper) and read from a stream of lines."""

    def __init__(self, stream, *, clock: Callable[[], float] = time.monotonic, stale_after: float = 6.0) -> None:
        self.stream, self.clock, self.stale_after = stream, clock, stale_after
        self._latest: tuple[float, dict, list, dict] | None = None
        self.privileged = False
        self.note = ""
        self.closed = False
        self.bad_lines = 0
        self.assessment: dict | None = None
        self.scan_state, self.scan_detail = "off", "waiting for the root helper"
        self._scans: list = []
        self._scans_lock = threading.Lock()
        self.results: dict[int, dict] = {}
        self.result_ready = threading.Condition()
        self.nudge: Callable[[], None] | None = None     # asks the helper to look again now
        self._thread = threading.Thread(target=self._read, name="erinix-helper-reader", daemon=True)

    def start(self) -> "RemoteView":
        self._thread.start()
        return self

    def _read(self) -> None:
        try:
            while True:
                line = self.stream.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE:                       # a line that never ends: give up on this helper
                    self.note = "the helper sent an oversized line"
                    break
                if line.startswith('{"t":"result"'):
                    got = decode_result(line)
                    if got is None:
                        self.bad_lines += 1
                    else:
                        with self.result_ready:
                            self.results[got["id"]] = got
                            self.result_ready.notify_all()
                    continue
                if line.startswith('{"t":"assess"'):
                    got = decode_assessment(line)
                    if got is None:
                        self.bad_lines += 1
                    else:
                        self.assessment = got
                    continue
                if line.startswith('{"t":"scan"'):
                    got = decode_scan(line)
                    if got is None:
                        self.bad_lines += 1
                    else:
                        with self._scans_lock:
                            if len(self._scans) < 256:
                                self._scans.append(got)
                    continue
                if line.startswith('{"t":"hello"'):
                    try:
                        hello = json.loads(line)
                        self.privileged = hello.get("uid") == 0
                        self.note = _text(hello.get("note", ""), 300)
                        if hello.get("scan") in ("ok", "blind", "off"):
                            self.scan_state, self.scan_detail = hello["scan"], _text(hello.get("scan_detail", ""), 200)
                    except (ValueError, TypeError):
                        self.bad_lines += 1
                    continue
                got = decode_snapshot(line)
                if got is None:
                    self.bad_lines += 1
                    continue
                self._latest = (self.clock(), *got)
        except (OSError, ValueError):
            pass
        finally:
            self.closed = True

    def _fresh(self):
        if self._latest is None or self.clock() - self._latest[0] > self.stale_after:
            return None
        return self._latest

    def scan(self) -> dict[int, ProcRecord]:
        got = self._fresh()
        return got[1] if got else {}

    def sockets(self) -> list[Socket]:
        got = self._fresh()
        return got[2] if got else []

    def owners(self) -> dict[int, int]:
        got = self._fresh()
        return got[3] if got else {}

    def drain_scans(self) -> list:
        with self._scans_lock:
            out, self._scans = self._scans, []
        return out

    @property
    def has_data(self) -> bool:
        return self._latest is not None

    @property
    def alive(self) -> bool:
        return not self.closed and self._fresh() is not None


# ------------------------------------------------------------------ the helper (the only part that runs as root)
def code_is_user_writable() -> bool:
    """True when the code root is about to run could be changed by a normal user (a development install)."""
    root = os.path.dirname(os.path.abspath(__file__))
    for _ in range(4):
        try:
            st = os.stat(root)
        except OSError:
            return True
        if st.st_uid != 0 or st.st_mode & 0o022:
            return True
        root = os.path.dirname(root)
    return False


def handle_action(msg: dict) -> str:
    """Run one action asked for by the unprivileged side. Only the closed list in erinix.actions exists here."""
    from erinix import actions

    ident = msg.get("id")
    if isinstance(ident, bool) or not isinstance(ident, int) or not 1 <= ident <= 2**31:
        ident = 1
    name, args = msg.get("action"), msg.get("args")
    if name not in ("kill", "block", "unblock", "fix", "restore") or not isinstance(args, dict):
        result = {"ok": False, "message": "the helper does not know that action", "undo": None}
    else:
        try:
            result = actions.execute(name, args)
        except Exception as exc:
            result = {"ok": False, "message": f"the helper could not do it ({type(exc).__name__})", "undo": None}
    return json.dumps({"t": "result", "id": ident, **result}, separators=(",", ":"))


def helper_main(out: TextIO | None = None, *, interval: float = 0.5, proc: str = "/proc", stop: Callable[[], bool] = lambda: False,
                sleep: Callable[[float], None] = time.sleep, stdin: TextIO | None = None, assess: bool = True,
                watcher=None) -> int:
    """Send a snapshot of /proc every `interval` seconds until the reader goes away."""
    out = sys.stdout if out is None else out
    view = LocalView(proc)
    note = "development install: the code root runs can be changed by a normal user" if code_is_user_writable() else ""
    gone, nudged = threading.Event(), threading.Event()
    todo: list[dict] = []                                  # actions the user's Erinix asked for; each is validated again here
    source = sys.stdin if stdin is None else stdin
    if source is not None and not source.isatty():
        def watch() -> None:                                    # a line from the parent means "look again now"; closing stdin means stop
            try:
                while True:
                    line = source.readline(20_000)
                    if not line:
                        break
                    if line.startswith('{"t":"act"'):
                        try:
                            msg = json.loads(line)
                            if isinstance(msg, dict) and len(todo) < 8:
                                todo.append(msg)
                        except ValueError:
                            pass
                    nudged.set()
            except (OSError, ValueError):
                pass
            gone.set()
        threading.Thread(target=watch, daemon=True).start()
    parent = os.getppid()
    if watcher is None and os.geteuid() == 0:                 # packets can only be listened to as root
        from erinix.sensors.scanwatch import ScanWatcher, local_addresses

        watcher = ScanWatcher(ignore=local_addresses())
    if watcher is not None:
        watcher.start()
    scan_state, scan_detail = (watcher.state, watcher.detail) if watcher is not None else ("off", "not running as root")
    try:
        out.write(json.dumps({"t": "hello", "uid": os.geteuid(), "version": __version__, "note": note, "scan": scan_state, "scan_detail": scan_detail}, separators=(",", ":")) + "\n")
        out.flush()
        owners: dict[int, int] = {}
        owners_at = assessed_at = -1e9
        while not (stop() or gone.is_set() or os.getppid() != parent):
            began = time.monotonic()
            while todo:
                out.write(handle_action(todo.pop(0)) + "\n")
            if assess and (nudged.is_set() or began - assessed_at >= ASSESS_EVERY):
                nudged.clear()
                assessed_at = began
                try:                                            # with root's eyes: the checks that need it can finally run
                    from erinix.assessment import Env, run_assessment
                    out.write(encode_assessment(run_assessment(Env(proc=proc, full_view=True))) + "\n")
                except Exception:
                    pass
            if watcher is not None:
                for found in watcher.drain():
                    out.write(encode_scan(found) + "\n")
            socks = view.sockets()
            if began - owners_at >= OWNERS_EVERY:
                owners, owners_at = view.owners(), began
            out.write(encode_snapshot(view.scan(), socks, owners) + "\n")
            out.flush()
            sleep(max(0.0, interval - (time.monotonic() - began)))
    except (BrokenPipeError, ValueError):
        pass
    finally:
        if watcher is not None:
            watcher.stop()
    return 0


# ------------------------------------------------------------------ the user's side: starting the helper
class ElevatedHelper:
    """Starts `erinix helper` through sudo and reads its snapshots. The password is asked by sudo itself, in the terminal."""

    def __init__(self, *, popen=subprocess.Popen, run=subprocess.run, argv: list[str] | None = None, require_root: bool = True) -> None:
        self.popen, self.run, self.require_root = popen, run, require_root
        self.argv = argv or ["sudo", "-n", sys.executable, "-m", "erinix", "helper"]
        self.process = None
        self.view: RemoteView | None = None
        self.error = ""

    def authenticate(self) -> bool:
        """Ask for the sudo password now, while the terminal is still a normal one."""
        try:
            done = self.run(["sudo", "-v"])
        except OSError:
            self.error = "sudo is not installed"
            return False
        if done.returncode != 0:
            self.error = "sudo did not accept the password (or you may not use sudo)"
            return False
        return True

    def start(self, *, wait: float = 3.0) -> bool:
        try:
            self.process = self.popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, close_fds=True)
        except OSError as exc:
            self.error = f"cannot start the helper: {exc.strerror}"
            return False
        self.view = RemoteView(self.process.stdout).start()
        self.view.nudge = self._nudge
        end = time.monotonic() + wait
        while time.monotonic() < end:
            if self.view.has_data:
                if self.require_root and not self.view.privileged:
                    self.error = "the helper is not running as root"
                    self.stop()
                    return False
                return True
            if self.view.closed:
                break
            time.sleep(0.05)
        self.error = "the helper did not start" + self._why()
        self.stop()
        return False

    def _why(self) -> str:
        """What the helper (or sudo) said when it stopped, so the reason is not a guess."""
        proc = self.process
        try:
            if proc is not None and proc.poll() is not None and proc.stderr is not None:
                text = " ".join(proc.stderr.read(600).split())
                return f": {safe(text)[:200]}" if text else " (sudo needs the password first, or refused)"
        except (OSError, ValueError):
            pass
        return " (it was too slow to answer)"

    @property
    def alive(self) -> bool:
        return self.view is not None and self.view.alive and self.process is not None

    def request(self, action: str, args: dict, timeout: float = 20.0) -> dict:
        """Ask the root helper to run one action and wait for its answer."""
        view, proc = self.view, self.process
        if view is None or proc is None or proc.stdin is None:
            return {"ok": False, "message": "the root helper is not running", "undo": None}
        self._ids = getattr(self, "_ids", 0) + 1
        ident = self._ids
        try:
            proc.stdin.write(json.dumps({"t": "act", "id": ident, "action": action, "args": args}, separators=(",", ":")) + "\n")
            proc.stdin.flush()
        except (OSError, ValueError):
            return {"ok": False, "message": "the root helper stopped answering", "undo": None}
        end = time.monotonic() + timeout
        with view.result_ready:
            while ident not in view.results:
                left = end - time.monotonic()
                if left <= 0 or view.closed:
                    return {"ok": False, "message": "the root helper did not answer in time", "undo": None}
                view.result_ready.wait(min(left, 0.5))
            got = view.results.pop(ident)
        return {"ok": got["ok"], "message": got["message"], "undo": got["undo"]}

    def _nudge(self) -> None:
        try:
            if self.process is not None and self.process.stdin is not None:
                self.process.stdin.write("again\n")
                self.process.stdin.flush()
        except (OSError, ValueError):
            pass

    def stop(self) -> None:
        proc, self.process = self.process, None
        if proc is None:
            return
        for step in (lambda: proc.stdin.close(), lambda: proc.terminate()):
            try:
                step()
            except (OSError, ValueError, AttributeError):
                pass
        try:
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except OSError:
                pass
