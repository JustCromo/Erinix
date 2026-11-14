"""Alert store: a small private SQLite database.

The agent writes it; the console and the dashboard read it. It is the one place
where "what happened" lives, so every screen shows the same facts.

Security
- The file is 0600 inside a 0700 folder, owned by the user running Erinix. It is
  refused if it is a symlink, belongs to someone else or is readable by others.
- Everything stored may come from attacker-influenced logs: text is bounded and
  kept RAW (escaped only when displayed). Queries are always parameterized.
- Login tokens for the dashboard are stored as hashes and work once.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import time
from pathlib import Path
from urllib.parse import quote

from erinix.engine.alerts import Alert
from erinix.history import state_dir

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
STATUSES = ("open", "dismissed")
MAX_TEXT = 2000
MAX_LIST = 32
MAX_LOGIN_TOKENS = 10
ALERT_RETENTION_DAYS = 30
STATS_RETENTION_HOURS = 48
SCHEMA_VERSION = 3
MAX_EVENTS = 5000              # recent events kept for the live view (events tied to an alert are kept longer)
PRUNE_EVERY = 200              # inserts between clean-ups
EVENT_RETENTION_DAYS = 30
MAX_ID = 2**62                 # beyond any real sequence number; keeps absurd values from reaching SQLite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL, kind TEXT NOT NULL,
    title TEXT NOT NULL, why TEXT NOT NULL, next_steps TEXT NOT NULL, description TEXT NOT NULL,
    severity TEXT NOT NULL, response TEXT NOT NULL,
    steps_done INTEGER NOT NULL, steps_total INTEGER NOT NULL, step_id TEXT NOT NULL, complete INTEGER NOT NULL,
    mitre TEXT NOT NULL, remote TEXT, anchor_pid INTEGER, revision INTEGER NOT NULL,
    evidence TEXT NOT NULL, detail TEXT NOT NULL,
    first_seen REAL NOT NULL, updated REAL NOT NULL, status TEXT NOT NULL DEFAULT 'open',
    step_labels TEXT NOT NULL DEFAULT '[]',
    tag TEXT NOT NULL DEFAULT '', area TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS alerts_by_status ON alerts(status, updated DESC);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS minute_stats (minute INTEGER PRIMARY KEY, events INTEGER NOT NULL DEFAULT 0, alerts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS login_tokens (token_hash TEXT PRIMARY KEY, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL, ts REAL NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL, summary TEXT NOT NULL,
    remote TEXT, source TEXT NOT NULL DEFAULT '',
    alert_id TEXT, step TEXT, severity TEXT
);
CREATE INDEX IF NOT EXISTS events_by_alert ON events(alert_id);
CREATE INDEX IF NOT EXISTS events_by_event_id ON events(event_id);
"""


class StoreError(Exception):
    """The store cannot be used (missing, untrusted, unreadable)."""


def default_db_path() -> Path:
    return state_dir() / "erinix.db"


def _clip(value: object, limit: int = MAX_TEXT) -> str:
    return str(value)[:limit]


def _check_private(path: Path, *, directory: bool) -> None:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise StoreError(f"{path}: {exc.strerror}") from None
    kind_ok = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode)
    if not kind_ok:
        raise StoreError(f"{path}: not a regular {'folder' if directory else 'file'} (symlinks are refused)")
    if st.st_uid != os.geteuid():
        raise StoreError(f"{path}: owned by another user")
    if st.st_mode & (0o022 if directory else 0o077):
        raise StoreError(f"{path}: permissions are too open")


class Store:
    def __init__(self, path: Path | str | None = None, *, readonly: bool = False) -> None:
        self.path = Path(path) if path is not None else default_db_path()
        self.readonly = readonly
        self._inserts = 0
        if readonly:
            if not self.path.exists():
                raise StoreError("no data yet")
            _check_private(self.path.parent, directory=True)
            _check_private(self.path, directory=False)
            if self._version(self.path) < SCHEMA_VERSION:
                Store(self.path).close()                       # an older store: upgrade it in place (same user, private file)
            uri = f"file:{quote(str(self.path))}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True, timeout=5)
        else:
            os.makedirs(self.path.parent, mode=0o700, exist_ok=True)
            _check_private(self.path.parent, directory=True)
            if not os.path.lexists(self.path):
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                os.close(fd)
            _check_private(self.path, directory=False)
            self._conn = sqlite3.connect(str(self.path), timeout=5)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
            self._migrate()
            self._conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self._conn.commit()
        self._conn.row_factory = sqlite3.Row

    @staticmethod
    def _version(path: Path) -> int:
        probe = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True, timeout=5)
        try:
            return int(probe.execute("PRAGMA user_version").fetchone()[0])
        finally:
            probe.close()

    def _migrate(self) -> None:
        """Bring an older store up to date. Columns are only ever added."""
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(alerts)")}
        for name, definition in (("step_labels", "TEXT NOT NULL DEFAULT '[]'"), ("tag", "TEXT NOT NULL DEFAULT ''"),
                                 ("area", "TEXT NOT NULL DEFAULT ''")):
            if name not in columns:
                self._conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ alerts
    def upsert_alert(self, alert: Alert, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        seen = alert.wall_ns / 1e9 if alert.wall_ns else now
        values = {
            "alert_id": _clip(alert.alert_id, 64), "rule_id": _clip(alert.rule_id, 120), "kind": _clip(alert.kind, 20),
            "title": _clip(alert.title), "why": _clip(alert.why),
            "next_steps": json.dumps([_clip(s, 400) for s in alert.next_steps[:MAX_LIST]]),
            "description": _clip(alert.description), "severity": alert.severity.value, "response": alert.response.value,
            "steps_done": int(alert.steps_done), "steps_total": int(alert.steps_total), "step_id": _clip(alert.step_id, 120),
            "complete": int(alert.complete), "mitre": json.dumps([_clip(m, 20) for m in alert.mitre[:MAX_LIST]]),
            "remote": None if alert.remote_addr is None else str(alert.remote_addr),
            "anchor_pid": alert.anchor.pid if alert.anchor else None, "revision": int(alert.revision),
            "evidence": json.dumps([[_clip(step, 120), [_clip(i, 64) for i in ids[:MAX_LIST]]] for step, ids in alert.evidence[:MAX_LIST]]),
            "detail": _clip(alert.detail), "first_seen": seen, "updated": seen,
            "step_labels": json.dumps([_clip(l, 120) for l in alert.step_labels[:MAX_LIST]]),
            "tag": _clip(alert.tag, 40), "area": _clip(alert.area, 20),
        }
        with self._conn:
            existing = self._conn.execute("SELECT revision, status FROM alerts WHERE alert_id=?", (values["alert_id"],)).fetchone()
            if existing is None:
                names = ", ".join(values)
                marks = ", ".join(f":{k}" for k in values)
                self._conn.execute(f"INSERT INTO alerts ({names}, status) VALUES ({marks}, 'open')", values)
                return
            values["status"] = "open" if int(alert.revision) > existing["revision"] else existing["status"]   # it grew: show it again
            changing = [k for k in values if k not in ("alert_id", "first_seen")]
            self._conn.execute(f"UPDATE alerts SET {', '.join(f'{k}=:{k}' for k in changing)} WHERE alert_id=:alert_id", values)

    @staticmethod
    def _alert_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        data.setdefault("step_labels", "[]")
        data.setdefault("tag", "")
        data.setdefault("area", "")
        for key in ("next_steps", "mitre", "evidence", "step_labels"):
            try:
                data[key] = json.loads(data[key])
            except ValueError:
                data[key] = []
        data["complete"] = bool(data["complete"])
        return data

    def list_alerts(self, status: str = "open", *, limit: int = 50, offset: int = 0) -> list[dict]:
        if status not in (*STATUSES, "all"):
            raise StoreError("unknown status")
        limit, offset = max(1, min(int(limit), 200)), max(0, int(offset))
        order = "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC, updated DESC"
        if status == "all":
            rows = self._conn.execute(f"SELECT * FROM alerts ORDER BY {order} LIMIT ? OFFSET ?", (limit, offset))
        else:
            rows = self._conn.execute(f"SELECT * FROM alerts WHERE status=? ORDER BY {order} LIMIT ? OFFSET ?",
                                      (status, limit, offset))
        return [self._alert_dict(r) for r in rows.fetchall()]

    def get_alert(self, alert_id: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM alerts WHERE alert_id=?", (_clip(alert_id, 64),)).fetchone()
        return None if row is None else self._alert_dict(row)

    def find_alert(self, prefix: str) -> dict | None:
        """Look an alert up by id or by a unique id prefix (at least 6 characters)."""
        if len(prefix) < 6 or not prefix.isalnum():
            return None
        rows = self._conn.execute("SELECT * FROM alerts WHERE alert_id LIKE ? ESCAPE '\\' LIMIT 2",
                                  (prefix + "%",)).fetchall()
        return self._alert_dict(rows[0]) if len(rows) == 1 else None

    def set_alert_status(self, alert_id: str, status: str) -> bool:
        if status not in STATUSES:
            raise StoreError("unknown status")
        with self._conn:
            cur = self._conn.execute("UPDATE alerts SET status=? WHERE alert_id=?", (status, _clip(alert_id, 64)))
        return cur.rowcount == 1

    def counts(self) -> dict:
        open_by = {name: 0 for name in SEVERITY_RANK}
        for row in self._conn.execute("SELECT severity, COUNT(*) n FROM alerts WHERE status='open' GROUP BY severity"):
            if row["severity"] in open_by:
                open_by[row["severity"]] = row["n"]
        dismissed = self._conn.execute("SELECT COUNT(*) FROM alerts WHERE status='dismissed'").fetchone()[0]
        return {"open": sum(open_by.values()), "open_by_severity": open_by, "dismissed": dismissed}

    def prune(self, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._conn:
            self._conn.execute("DELETE FROM alerts WHERE status='dismissed' AND updated<?",
                               (now - ALERT_RETENTION_DAYS * 86400,))
            self._conn.execute("DELETE FROM minute_stats WHERE minute<?", (int(now // 60) - STATS_RETENTION_HOURS * 60,))
            self._conn.execute("DELETE FROM login_tokens WHERE expires<?", (now,))
        self.prune_events(now=now)

    def reset(self) -> None:
        with self._conn:
            for table in ("alerts", "minute_stats", "meta", "login_tokens", "events"):
                self._conn.execute(f"DELETE FROM {table}")

    # ------------------------------------------------------------------ events
    def add_event(self, *, event_id: str, ts: float, kind: str, label: str, summary: str, remote: str | None = None,
                  source: str = "", alert_id: str | None = None, step: str | None = None, severity: str | None = None) -> int:
        """Record one event for the live view. Returns its sequence number (always growing)."""
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO events (event_id, ts, kind, label, summary, remote, source, alert_id, step, severity) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (_clip(event_id, 64), float(ts), _clip(kind, 40), _clip(label, 80), _clip(summary, 400),
                 None if remote is None else _clip(remote, 64), _clip(source, 20),
                 None if alert_id is None else _clip(alert_id, 64), None if step is None else _clip(step, 120),
                 severity if severity in SEVERITY_RANK else None))
        self._inserts += 1
        if self._inserts % PRUNE_EVERY == 0:
            self.prune_events(now=ts)
        return int(cur.lastrowid)

    def link_events(self, event_ids: list[str], alert_id: str, step: str, severity: str) -> None:
        """Mark events as part of an attack (a step that needed several hits is only known once it is complete)."""
        if severity not in SEVERITY_RANK or not event_ids:
            return
        with self._conn:
            for event_id in event_ids[:MAX_LIST]:
                self._conn.execute("UPDATE events SET alert_id=?, step=?, severity=? WHERE event_id=? AND (alert_id IS NULL OR alert_id=?)",
                                   (_clip(alert_id, 64), _clip(step, 120), severity, _clip(event_id, 64), _clip(alert_id, 64)))

    @staticmethod
    def _event_dict(row: sqlite3.Row) -> dict:
        return dict(row)

    def list_events(self, *, after: int | None = None, limit: int = 100, suspicious_only: bool = False) -> list[dict]:
        """Events in order. `after` gives only newer ones; without it, the latest `limit`."""
        limit = max(1, min(int(limit), 500))
        where = "alert_id IS NOT NULL" if suspicious_only else "1=1"
        base = "SELECT e.*, a.tag AS tag, a.remote AS alert_remote FROM events e LEFT JOIN alerts a ON a.alert_id = e.alert_id"
        where = where.replace("alert_id", "e.alert_id")
        if after is None:
            rows = self._conn.execute(f"{base} WHERE {where} ORDER BY e.id DESC LIMIT ?", (limit,)).fetchall()[::-1]
        else:
            rows = self._conn.execute(f"{base} WHERE e.id>? AND {where} ORDER BY e.id ASC LIMIT ?", (min(int(after), MAX_ID), limit)).fetchall()
        return [self._event_dict(r) for r in rows]

    def last_event_id(self) -> int:
        row = self._conn.execute("SELECT MAX(id) FROM events").fetchone()
        return int(row[0] or 0)

    def events_for_alert(self, alert_id: str, *, limit: int = 60) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM events WHERE alert_id=? ORDER BY id DESC LIMIT ?",
                                  (_clip(alert_id, 64), max(1, min(int(limit), 200)))).fetchall()[::-1]
        return [self._event_dict(r) for r in rows]

    def events_by_event_id(self, event_ids: list[str]) -> dict[str, dict]:
        found: dict[str, dict] = {}
        for event_id in event_ids[:MAX_LIST * 4]:
            row = self._conn.execute("SELECT * FROM events WHERE event_id=? ORDER BY id DESC LIMIT 1", (_clip(event_id, 64),)).fetchone()
            if row is not None:
                found[event_id] = self._event_dict(row)
        return found

    def prune_events(self, *, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._conn:
            top = self._conn.execute("SELECT MAX(id) FROM events").fetchone()[0] or 0
            self._conn.execute("DELETE FROM events WHERE alert_id IS NULL AND id<=?", (top - MAX_EVENTS,))
            self._conn.execute("DELETE FROM events WHERE ts<?", (now - EVENT_RETENTION_DAYS * 86400,))

    # ------------------------------------------------------------------- stats
    def bump(self, *, events: int = 0, alerts: int = 0, now: float | None = None) -> None:
        minute = int((time.time() if now is None else now) // 60)
        with self._conn:
            self._conn.execute(
                "INSERT INTO minute_stats(minute, events, alerts) VALUES (?,?,?) "
                "ON CONFLICT(minute) DO UPDATE SET events=events+excluded.events, alerts=alerts+excluded.alerts",
                (minute, int(events), int(alerts)))

    def activity(self, *, hours: int = 24, bucket_minutes: int = 30, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        buckets = hours * 60 // bucket_minutes
        end = int(now // 60) // bucket_minutes * bucket_minutes + bucket_minutes
        start = end - buckets * bucket_minutes
        points = {start + i * bucket_minutes: [0, 0] for i in range(buckets)}
        for row in self._conn.execute("SELECT minute, events, alerts FROM minute_stats WHERE minute>=? AND minute<?",
                                      (start, end)):
            key = row["minute"] // bucket_minutes * bucket_minutes
            points[key][0] += row["events"]
            points[key][1] += row["alerts"]
        return [{"t": minute * 60, "events": e, "alerts": a} for minute, (e, a) in points.items()]

    # -------------------------------------------------------------------- meta
    def set_meta(self, key: str, value: object) -> None:
        with self._conn:
            self._conn.execute("INSERT INTO meta(key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                               (_clip(key, 64), json.dumps(value)))

    def get_meta(self, key: str, default: object = None) -> object:
        row = self._conn.execute("SELECT value FROM meta WHERE key=?", (_clip(key, 64),)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row["value"])
        except ValueError:
            return default

    # ------------------------------------------------------------ login tokens
    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8", "replace")).hexdigest()

    def create_login_token(self, *, ttl: float = 120.0, now: float | None = None) -> str:
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        with self._conn:
            self._conn.execute("DELETE FROM login_tokens WHERE expires<?", (now,))
            self._conn.execute("DELETE FROM login_tokens WHERE token_hash IN (SELECT token_hash FROM login_tokens "
                               "ORDER BY expires ASC LIMIT max(0, (SELECT COUNT(*) FROM login_tokens) - ?))",
                               (MAX_LOGIN_TOKENS - 1,))
            self._conn.execute("INSERT INTO login_tokens VALUES (?,?)", (self._hash(token), now + ttl))
        return token

    def redeem_login_token(self, token: object, *, now: float | None = None) -> str:
        """'ok' once for a valid token; otherwise 'invalid' (unknown or already used) or 'expired'.

        The token is destroyed either way.
        """
        now = time.time() if now is None else now
        if not isinstance(token, str) or not 20 <= len(token) <= 100:
            return "invalid"
        digest = self._hash(token)
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute("SELECT expires FROM login_tokens WHERE token_hash=?", (digest,)).fetchone()
            if row is None:
                return "invalid"
            self._conn.execute("DELETE FROM login_tokens WHERE token_hash=?", (digest,))
            return "ok" if row["expires"] > now else "expired"

    def consume_login_token(self, token: object, *, now: float | None = None) -> bool:
        return self.redeem_login_token(token, now=now) == "ok"
