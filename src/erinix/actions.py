"""Mitigation: the few things Erinix may DO, never more than this closed list.

kill     stop one program (checked against its start time, so a reused process number is never hit by mistake)
block    drop traffic from one address for a limited time (nftables, in a table of its own; it expires by itself)
unblock  lift such a block
fix      put back safe permissions on the files the Health check flagged (the paths are found again by Erinix, never given)
undo     reverse a block or a fix from the journal

Every action is validated twice (where it is asked and where it runs), described before it runs, and written to a journal.
Nothing here runs a command built from outside text: nft is called with a fixed argument list.
"""

from __future__ import annotations

import ipaddress
import os
import signal
import stat
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable

from erinix.assessment import Env
from erinix.sensors import procfs
from erinix.ui.render import safe

MAX_MINUTES = 24 * 60
DEFAULT_MINUTES = 60
FIXABLE = ("ssh.keys", "accounts.files", "accounts.sudoers")
JOURNAL_KEY = "actions"
JOURNAL_MAX = 200
NFT_SCRIPT = """table inet erinix {
  set blocked4 { type ipv4_addr; flags timeout; }
  set blocked6 { type ipv6_addr; flags timeout; }
  chain input { type filter hook input priority -10; policy accept;
    ip saddr @blocked4 drop
    ip6 saddr @blocked6 drop
  }
}
"""


class ActionError(Exception):
    """A refusal that is explained to the person in plain words."""


@dataclass
class Plan:
    action: str
    args: dict
    title: str
    steps: list[str]
    needs_root: bool
    undoable: bool = False
    warning: str = ""


# ------------------------------------------------------------------ validation (used on both sides of the pipe)
def _local_addresses(proc: str = "/proc") -> set[str]:
    found: set[str] = set()
    try:
        last = ""
        with open(f"{proc}/net/fib_trie", "rb") as f:
            for raw in f.read(400_000).decode("utf-8", "replace").splitlines():
                text = raw.strip()
                if text.startswith(("|--", "+--")):
                    last = text.split()[-1]
                elif "/32 host LOCAL" in text and last:
                    found.add(last)
    except OSError:
        pass
    return found


def _gateways(proc: str = "/proc") -> set[str]:
    found: set[str] = set()
    try:
        with open(f"{proc}/net/route", "rb") as f:
            for raw in f.read(100_000).decode("utf-8", "replace").splitlines()[1:]:
                p = raw.split()
                if len(p) > 2 and p[1] == "00000000":
                    found.add(str(ipaddress.IPv4Address(int(p[2], 16).to_bytes(4, "little"))))
    except (OSError, ValueError):
        pass
    return found


def check_ip(text: object, proc: str = "/proc") -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(text, str) or len(text) > 45:
        raise ActionError("that is not an IP address")
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        raise ActionError("that is not an IP address") from None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise ActionError("this address cannot be blocked (it is this machine, a special range or broadcast)")
    if str(ip) in _local_addresses(proc):
        raise ActionError("that is one of this machine's own addresses")
    if str(ip) in _gateways(proc):
        raise ActionError("that is your router: blocking it would cut you off the network")
    return ip


def check_minutes(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_MINUTES:
        raise ActionError(f"the time must be between 1 and {MAX_MINUTES} minutes")
    return value


def pin_process(pid: object, proc: str = "/proc") -> procfs.ProcRecord:
    if isinstance(pid, bool) or not isinstance(pid, int) or not 2 <= pid <= 4_194_304:
        raise ActionError("that is not a valid program number")
    rec = procfs.read_process(pid, proc)
    if rec is None:
        raise ActionError("that program is gone (or is part of the kernel)")
    if pid == os.getpid() or pid == os.getppid():
        raise ActionError("Erinix will not stop itself or the program that started it")
    chain, cur = set(), os.getpid()
    for _ in range(64):                                    # the whole family above Erinix: stopping it would stop Erinix
        r = procfs.read_process(cur, proc)
        if r is None or r.ppid <= 1:
            break
        chain.add(r.ppid)
        cur = r.ppid
    if pid in chain:
        raise ActionError("that program is part of the one running Erinix")
    return rec


# ------------------------------------------------------------------ fixes: the targets are always found by Erinix itself
def fix_targets(check_id: str, env: Env | None = None) -> list[tuple[str, int, int]]:
    """(path, current mode, safe mode) for what the Health check flags."""
    env = env or Env()
    out: list[tuple[str, int, int]] = []

    def add(path: str, new: int, bad: int) -> None:
        m = env.mode(path)
        try:
            st = os.lstat(env.path(path))
        except OSError:
            return
        if m is not None and not stat.S_ISLNK(st.st_mode) and m & bad:
            out.append((path, m, new(m) if callable(new) else new))

    if check_id == "ssh.keys":
        for home in env.homes:
            ssh = home.rstrip("/") + "/.ssh"
            add(ssh, 0o700, 0o077)
            for n in env.listdir(ssh):
                p = f"{ssh}/{n}"
                if n == "authorized_keys":
                    add(p, 0o600, 0o022)
                elif n.startswith(("id_", "ssh_host_")) and not n.endswith(".pub"):
                    add(p, 0o600, 0o077)
    elif check_id == "accounts.files":
        add("/etc/passwd", lambda m: m & ~0o022, 0o022)
        add("/etc/shadow", lambda m: m & ~0o037, 0o027)
    elif check_id == "accounts.sudoers":
        for p in ["/etc/sudoers"] + env.glob("/etc/sudoers.d/*", 100):
            add(p, 0o440, 0o022)
    else:
        raise ActionError("Erinix cannot fix that one by itself (the Health panel says how to do it by hand)")
    return out


def allowed_fix_path(path: str, env: Env | None = None) -> bool:
    """Whether a path may ever be changed by a fix (also checks what comes back from the journal for an undo)."""
    env = env or Env()
    if path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers"):
        return True
    if path.startswith("/etc/sudoers.d/") and "/" not in path[len("/etc/sudoers.d/"):] and ".." not in path:
        return True
    for home in env.homes:
        ssh = home.rstrip("/") + "/.ssh"
        if path == ssh or (path.startswith(ssh + "/") and "/" not in path[len(ssh) + 1:] and ".." not in path):
            return True
    return False


def _apply_modes(items: list[tuple[str, int, int]], env: Env) -> list[list]:
    done: list[list] = []
    for path, old, new in items:
        if not allowed_fix_path(path, env):
            raise ActionError("that path is not one Erinix may change")
        real = env.path(path)
        st = os.lstat(real)
        if stat.S_ISLNK(st.st_mode) or stat.S_IMODE(st.st_mode) != old and stat.S_IMODE(st.st_mode) != new:
            continue                                       # it changed meanwhile: leave it alone
        if new & 0o7000 or new > 0o777:
            raise ActionError("refused: that mode is not a plain permission")
        os.chmod(real, new)
        done.append([path, old])
    return done


# ------------------------------------------------------------------ plan: say what would happen, change nothing
def plan(action: str, args: dict, *, env: Env | None = None, proc: str = "/proc", euid: int | None = None) -> Plan:
    euid = os.geteuid() if euid is None else euid
    if action == "kill":
        rec = pin_process(args.get("pid"), proc)
        sig = args.get("signal", "TERM")
        if sig not in ("TERM", "KILL"):
            raise ActionError("the signal must be TERM or KILL")
        name = safe(rec.comm)[:40]
        return Plan("kill", {"pid": rec.pid, "start": rec.start_ticks, "signal": sig}, f"Stop {name} (number {rec.pid})",
                    [f"Send {'a polite stop request' if sig == 'TERM' else 'a forced stop'} to {name} ({safe(rec.command)[:100]})"],
                    needs_root=rec.uid != euid and euid != 0,
                    warning="" if rec.uid == euid else f"This program belongs to user {rec.uid}.")
    if action in ("block", "unblock"):
        ip = check_ip(args.get("ip"), proc)
        if action == "block":
            minutes = check_minutes(args.get("minutes", DEFAULT_MINUTES))
            return Plan("block", {"ip": str(ip), "minutes": minutes}, f"Block {ip} for {minutes} minute{'s' if minutes != 1 else ''}",
                        [f"Drop everything that comes from {ip} (nftables, table 'erinix')", f"The block ends by itself after {minutes} minute{'s' if minutes != 1 else ''}"],
                        needs_root=euid != 0, undoable=True, warning="Connections already open from it will stop working." )
        return Plan("unblock", {"ip": str(ip)}, f"Unblock {ip}", [f"Let traffic from {ip} through again"], needs_root=euid != 0)
    if action == "fix":
        cid = args.get("check")
        if cid not in FIXABLE:
            raise ActionError("Erinix cannot fix that one by itself (the Health panel says how to do it by hand)")
        items = fix_targets(cid, env)
        if not items:
            raise ActionError("nothing to fix any more")
        return Plan("fix", {"check": cid}, "Restore safe permissions", [f"{p}: {old:04o} -> {new:04o}" for p, old, new in items],
                    needs_root=euid != 0 and any(p.startswith("/etc") for p, _, _ in items), undoable=True)
    raise ActionError("unknown action")


# ------------------------------------------------------------------ execute: where the change really happens
def execute(action: str, args: dict, *, env: Env | None = None, proc: str = "/proc", run: Callable = subprocess.run,
            kill: Callable = os.kill, euid: int | None = None) -> dict:
    """Run one action. Returns {"ok", "message", "undo"}; never raises for an ordinary refusal."""
    try:
        p = plan(action, args, env=env, proc=proc, euid=euid) if action != "restore" else None
        if action == "kill":
            rec = pin_process(p.args["pid"], proc)
            if rec.start_ticks != p.args["start"] or (isinstance(args.get("start"), int) and args["start"] != rec.start_ticks):
                raise ActionError("that number now belongs to a different program: nothing was stopped")
            try:
                kill(rec.pid, signal.SIGKILL if p.args["signal"] == "KILL" else signal.SIGTERM)
            except PermissionError:
                raise ActionError("that program belongs to another user: press R to act with root") from None
            except ProcessLookupError:
                raise ActionError("that program is already gone") from None
            return {"ok": True, "message": f"Sent the stop request to {safe(rec.comm)[:40]} ({rec.pid}).", "undo": None}
        if action == "block":
            ip = check_ip(args.get("ip"), proc)
            _nft_block(ip, p.args["minutes"], run)
            return {"ok": True, "message": f"{ip} is blocked for {p.args['minutes']} minute{'s' if p.args['minutes'] != 1 else ''}.", "undo": {"action": "unblock", "ip": str(ip)}}
        if action == "unblock":
            ip = check_ip(args.get("ip"), proc)
            _nft(["delete", "element", "inet", "erinix", _set(ip), "{ " + str(ip) + " }"], run)
            return {"ok": True, "message": f"{ip} is no longer blocked.", "undo": None}
        if action == "fix":
            env = env or Env()
            done = _apply_modes(fix_targets(p.args["check"], env), env)
            return {"ok": True, "message": f"Restored permissions on {len(done)} item(s).", "undo": {"action": "restore", "items": done}}
        if action == "restore":                              # only ever from an undo
            env = env or Env()
            items = args.get("items")
            if not isinstance(items, list) or len(items) > 200:
                raise ActionError("nothing to restore")
            clean = []
            for it in items:
                if not (isinstance(it, list) and len(it) == 2 and isinstance(it[0], str) and isinstance(it[1], int) and not isinstance(it[1], bool)) or not 0 <= it[1] <= 0o777:
                    raise ActionError("the undo record is damaged")
                clean.append((it[0], None, it[1]))
            for path, _, mode in clean:
                if not allowed_fix_path(path, env):
                    raise ActionError("that path is not one Erinix may change")
                real = env.path(path)
                if stat.S_ISLNK(os.lstat(real).st_mode):
                    continue
                os.chmod(real, mode)
            return {"ok": True, "message": f"Put back the previous permissions on {len(clean)} item(s).", "undo": None}
        raise ActionError("unknown action")
    except ActionError as exc:
        return {"ok": False, "message": str(exc), "undo": None}
    except OSError as exc:
        return {"ok": False, "message": f"it did not work: {exc.strerror or type(exc).__name__}", "undo": None}


def _set(ip) -> str:
    return "blocked4" if ip.version == 4 else "blocked6"


def _nft(argv: list[str], run: Callable, stdin: str | None = None) -> None:
    try:
        done = run(["nft", *argv], input=stdin, capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        raise ActionError("nftables is not installed (the nft command is missing)") from None
    except subprocess.TimeoutExpired:
        raise ActionError("nft did not answer in time") from None
    if done.returncode != 0:
        why = " ".join((done.stderr or "").split())[:160]
        raise ActionError(f"nft refused: {safe(why) or 'unknown reason'}")


def _nft_block(ip, minutes: int, run: Callable) -> None:
    try:
        have = run(["nft", "list", "table", "inet", "erinix"], capture_output=True, text=True, timeout=15).returncode == 0
    except FileNotFoundError:
        raise ActionError("nftables is not installed (the nft command is missing)") from None
    except subprocess.TimeoutExpired:
        raise ActionError("nft did not answer in time") from None
    if not have:
        _nft(["-f", "-"], run, NFT_SCRIPT)
    _nft(["add", "element", "inet", "erinix", _set(ip), "{ " + f"{ip} timeout {minutes}m" + " }"], run)


# ------------------------------------------------------------------ journal
class Journal:
    """What Erinix did, in order. Kept in the private store; the root side never trusts it for anything but the allowlisted undo."""

    def __init__(self, store) -> None:
        self.store = store

    def all(self) -> list[dict]:
        rows = self.store.get_meta(JOURNAL_KEY, [])
        return [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []

    def add(self, action: str, title: str, result: dict, clock: Callable[[], float] = time.time) -> int:
        rows = self.all()
        n = (rows[-1]["n"] + 1) if rows and isinstance(rows[-1].get("n"), int) else 1
        rows.append({"n": n, "time": clock(), "action": action, "title": safe(title)[:120], "ok": bool(result.get("ok")),
                     "message": safe(str(result.get("message", "")))[:300], "undo": result.get("undo"), "undone": False})
        self.store.set_meta(JOURNAL_KEY, rows[-JOURNAL_MAX:])
        return n

    def mark_undone(self, n: int) -> None:
        rows = self.all()
        for r in rows:
            if r.get("n") == n:
                r["undone"] = True
        self.store.set_meta(JOURNAL_KEY, rows)

    def active_blocks(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        out = []
        for r in self.all():
            if r.get("action") == "block" and r.get("ok") and not r.get("undone"):
                mins = r.get("minutes")
                if isinstance(mins, int) and r["time"] + mins * 60 < now:
                    continue
                out.append(r)
        return out


# ------------------------------------------------------------------ the service the interfaces use
@dataclass
class Service:
    """Chooses where an action runs: here, or in the root helper when it needs root."""
    helper: object | None = None
    euid: int | None = None
    proc: str = "/proc"
    run: Callable = subprocess.run
    kill: Callable = os.kill
    env: Env | None = None
    open_store: Callable = field(default=None)

    def _euid(self) -> int:
        return os.geteuid() if self.euid is None else self.euid

    def plan(self, action: str, args: dict) -> Plan:
        return plan(action, args, env=self.env, proc=self.proc, euid=self._euid())

    def run_action(self, action: str, args: dict, title: str = "") -> dict:
        try:
            p = self.plan(action, args) if action != "restore" else Plan("restore", args, "Undo", [], needs_root=self._euid() != 0)
        except ActionError as exc:
            return {"ok": False, "message": str(exc), "undo": None}
        sent = args if action == "restore" else {**p.args, **({"start": args["start"]} if "start" in args else {})}    # keep the start time the person was shown
        needs = p.needs_root or (action == "restore" and any(str(i[0]).startswith("/etc") for i in args.get("items", []) if isinstance(i, list) and i))
        if needs and self._euid() != 0:
            if self.helper is None or not getattr(self.helper, "alive", False):
                return {"ok": False, "message": "This needs root. Press R in the cockpit (or start with erinix --elevate) and try again.", "undo": None}
            result = self.helper.request(action, sent)
        else:
            result = execute(action, sent, env=self.env, proc=self.proc, run=self.run, kill=self.kill, euid=self._euid())
        if result.get("ok") and action == "block":
            result["minutes"] = p.args["minutes"]
        self._journal(action, title or p.title, result, p.args.get("minutes") if action == "block" else None)
        if action == "unblock" and result.get("ok"):
            self._close_blocks(p.args["ip"])
        return result

    def _close_blocks(self, ip: str) -> None:
        """A block that was lifted by hand can no longer be undone."""
        if self.open_store is None:
            return
        try:
            store = self.open_store()
            try:
                rows = Journal(store).all()
                for r in rows:
                    if r.get("action") == "block" and (r.get("undo") or {}).get("ip") == ip:
                        r["undone"] = True
                store.set_meta(JOURNAL_KEY, rows)
            finally:
                store.close()
        except Exception:
            pass

    def _journal(self, action: str, title: str, result: dict, minutes: int | None) -> None:
        if self.open_store is None:
            return
        try:
            store = self.open_store()
            try:
                n = Journal(store).add(action, title, result)
                if minutes is not None and result.get("ok"):
                    rows = Journal(store).all()
                    rows[-1]["minutes"] = minutes
                    store.set_meta(JOURNAL_KEY, rows)
                result["n"] = n
            finally:
                store.close()
        except Exception:
            pass

    def undo(self, n: int) -> dict:
        if self.open_store is None:
            return {"ok": False, "message": "there is no journal here", "undo": None}
        store = self.open_store()
        try:
            rows = Journal(store).all()
            row = next((r for r in rows if r.get("n") == n), None)
            if row is None or not row.get("undo") or row.get("undone"):
                return {"ok": False, "message": "that action cannot be undone (or already was)", "undo": None}
            undo = row["undo"]
        finally:
            store.close()
        if not isinstance(undo, dict):
            return {"ok": False, "message": "the undo record is damaged", "undo": None}
        act = undo.get("action")
        if act == "unblock":
            result = self.run_action("unblock", {"ip": undo.get("ip")}, f"Undo #{n}")
        elif act == "restore":
            result = self.run_action("restore", {"items": undo.get("items")}, f"Undo #{n}")
        else:
            return {"ok": False, "message": "the undo record is damaged", "undo": None}
        if result.get("ok"):
            store = self.open_store()
            try:
                Journal(store).mark_undone(n)
            finally:
                store.close()
        return result


_service: Service | None = None


def set_service(service: Service | None) -> None:
    global _service
    _service = service


def get_service() -> Service:
    if _service is not None:
        return _service
    from erinix.store import Store
    return Service(open_store=lambda: Store())
