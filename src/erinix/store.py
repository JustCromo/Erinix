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
SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL, kind TEXT NOT NULL,
    title TEXT NOT NULL, why TEXT NOT NULL, next_steps TEXT NOT NULL, description TEXT NOT NULL,
    severity TEXT NOT NULL, response TEXT NOT NULL,
    steps_done INTEGER NOT NULL, steps_total INTEGER NOT NULL, step_id TEXT NOT NULL, complete INTEGER NOT NULL,
    mitre TEXT NOT NULL, remote TEXT, anchor_pid INTEGER, revision INTEGER NOT NULL,
    evidence TEXT NOT NULL, detail TEXT NOT NULL,
    first_seen REAL NOT NULL, updated REAL NOT NULL, status TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS alerts_by_status ON alerts(status, updated DESC);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS minute_stats (minute INTEGER PRIMARY KEY, events INTEGER NOT NULL DEFAULT 0, alerts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS login_tokens (token_hash TEXT PRIMARY KEY, expires REAL NOT NULL);
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
        if readonly:
            if not self.path.exists():
                raise StoreError("no data yet")
            _check_private(self.path.parent, directory=True)
            _check_private(self.path, directory=False)
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
            self._conn.executescript(_SCHEMA)
            self._conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self._conn.commit()
        self._conn.row_factory = sqlite3.Row

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
        row = (
            _clip(alert.alert_id, 64), _clip(alert.rule_id, 120), _clip(alert.kind, 20),
            _clip(alert.title), _clip(alert.why), json.dumps([_clip(s, 400) for s in alert.next_steps[:MAX_LIST]]),
            _clip(alert.description), alert.severity.value, alert.response.value,
            int(alert.steps_done), int(alert.steps_total), _clip(alert.step_id, 120), int(alert.complete),
            json.dumps([_clip(m, 20) for m in alert.mitre[:MAX_LIST]]),
            None if alert.remote_addr is None else str(alert.remote_addr),
            alert.anchor.pid if alert.anchor else None, int(alert.revision),
            json.dumps([[_clip(step, 120), [_clip(i, 64) for i in ids[:MAX_LIST]]] for step, ids in alert.evidence[:MAX_LIST]]),
            _clip(alert.detail), seen, seen,
        )
        with self._conn:
            existing = self._conn.execute("SELECT revision, status, first_seen FROM alerts WHERE alert_id=?",
                                          (row[0],)).fetchone()
            if existing is None:
                self._conn.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open')", row)
                return
            status = "open" if int(alert.revision) > existing["revision"] else existing["status"]   # it grew: show it again
            self._conn.execute(
                """UPDATE alerts SET rule_id=?, kind=?, title=?, why=?, next_steps=?, description=?, severity=?,
                   response=?, steps_done=?, steps_total=?, step_id=?, complete=?, mitre=?, remote=?, anchor_pid=?,
                   revision=?, evidence=?, detail=?, updated=?, status=? WHERE alert_id=?""",
                (*row[1:17], row[17], row[18], row[20], status, row[0]))

    @staticmethod
    def _alert_dict(row: sqlite3.Row) -> dict:
        data = dict(row)
        for key in ("next_steps", "mitre", "evidence"):
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

    def reset(self) -> None:
        with self._conn:
            for table in ("alerts", "minute_stats", "meta", "login_tokens"):
                self._conn.execute(f"DELETE FROM {table}")

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

    def consume_login_token(self, token: str, *, now: float | None = None) -> bool:
        """True once for a valid, unexpired token; the token is destroyed either way."""
        now = time.time() if now is None else now
        if not isinstance(token, str) or not 20 <= len(token) <= 100:
            return False
        digest = self._hash(token)
        with self._conn:
            self._conn.execute("BEGIN IMMEDIATE")
            row = self._conn.execute("SELECT expires FROM login_tokens WHERE token_hash=?", (digest,)).fetchone()
            if row is None:
                return False
            self._conn.execute("DELETE FROM login_tokens WHERE token_hash=?", (digest,))
            return row["expires"] > now
