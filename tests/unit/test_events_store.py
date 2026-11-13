import os
import sqlite3

import pytest

from erinix.store import MAX_EVENTS, PRUNE_EVERY, Store, StoreError

NOW = 1_700_000_000.0


@pytest.fixture()
def store(tmp_path):
    with Store(tmp_path / "state" / "erinix.db") as s:
        yield s


def add(store, n=1, **over):
    ids = []
    for i in range(n):
        args = dict(event_id=f"e{i:04d}", ts=NOW + i, kind="web.request", label="Web request", summary=f"GET /{i} → 200", remote="10.0.0.1", source="log")
        args.update(over)
        ids.append(store.add_event(**args))
    return ids


def test_events_come_back_in_order_with_growing_numbers(store):
    ids = add(store, 5)
    assert ids == sorted(ids) and len(set(ids)) == 5
    rows = store.list_events()
    assert [r["id"] for r in rows] == ids and rows[0]["summary"] == "GET /0 → 200" and store.last_event_id() == ids[-1]


def test_after_returns_only_newer_events_and_without_it_the_latest(store):
    ids = add(store, 10)
    assert [r["id"] for r in store.list_events(after=ids[6])] == ids[7:]
    assert store.list_events(after=ids[-1]) == []
    assert [r["id"] for r in store.list_events(limit=3)] == ids[-3:]          # first call: the latest few, oldest first
    assert [r["id"] for r in store.list_events(after=0, limit=4)] == ids[:4]


def test_limits_are_clamped_and_inputs_validated(store):
    add(store, 3)
    assert len(store.list_events(limit=0)) == 1 and len(store.list_events(limit=10**9)) == 3 and len(store.list_events(limit=-9)) == 1
    with pytest.raises((TypeError, ValueError)):
        store.list_events(after="1; DROP TABLE events")
    assert len(store.list_events()) == 3


def test_suspicious_filter_and_linking(store):
    add(store, 4)
    store.link_events(["e0001", "e0002"], "a" * 32, "step-one", "high")
    rows = store.list_events(suspicious_only=True)
    assert [r["event_id"] for r in rows] == ["e0001", "e0002"] and rows[0]["alert_id"] == "a" * 32 and rows[0]["severity"] == "high"
    assert [r["event_id"] for r in store.events_for_alert("a" * 32)] == ["e0001", "e0002"]
    store.link_events(["e0001"], "b" * 32, "other", "critical")                       # an event belongs to one alert
    assert store.list_events(suspicious_only=True)[0]["alert_id"] == "a" * 32
    store.link_events(["e0003"], "c" * 32, "s", "nonsense")                           # bad severity: ignored
    store.link_events([], "c" * 32, "s", "low")
    assert len(store.list_events(suspicious_only=True)) == 2


def test_event_text_is_bounded_and_raw_and_never_executed(store):
    evil = "x'); DROP TABLE events; --\x1b[31m<script>" + "A" * 5000
    add(store, 1, summary=evil, label="L" * 500, remote="R" * 500, event_id="E" * 500, kind="K" * 500)
    row = store.list_events()[0]
    assert row["summary"].startswith("x'); DROP TABLE events;") and len(row["summary"]) == 400 and len(row["label"]) == 80
    assert len(row["remote"]) == 64 and len(row["event_id"]) == 64 and len(row["kind"]) == 40
    assert len(store.list_events()) == 1
    assert store.events_by_event_id(["' OR 1=1 --"]) == {}


def test_events_by_event_id(store):
    add(store, 3)
    found = store.events_by_event_id(["e0001", "e0002", "missing"])
    assert set(found) == {"e0001", "e0002"} and found["e0002"]["summary"] == "GET /2 → 200"


def test_old_events_are_pruned_but_those_tied_to_alerts_are_kept(store):
    add(store, 5, ts=NOW - 40 * 86400)
    store.link_events(["e0000"], "a" * 32, "s", "low")
    add(store, 3, event_id="recent", ts=NOW)
    store.prune_events(now=NOW)
    assert [r["event_id"] for r in store.list_events()] == ["recent"] * 3                   # month-old events are gone, even the linked one


def test_the_ring_buffer_keeps_events_of_attacks(store, monkeypatch):
    monkeypatch.setattr("erinix.store.MAX_EVENTS", 20)
    add(store, 5, event_id="attack")
    store.link_events(["attack"], "a" * 32, "s", "high")
    add(store, 60, ts=NOW + 100)
    store.prune_events(now=NOW + 200)
    rows = store.list_events(limit=500)
    assert len(rows) <= 20 + 5 and sum(1 for r in rows if r["event_id"] == "attack") == 5


def test_pruning_runs_by_itself_while_events_arrive(tmp_path, monkeypatch):
    monkeypatch.setattr("erinix.store.MAX_EVENTS", 50)
    monkeypatch.setattr("erinix.store.PRUNE_EVERY", 10)
    with Store(tmp_path / "s" / "e.db") as s:
        add(s, 300, ts=NOW)
        assert len(s.list_events(limit=500)) <= 50 + 10


def test_reset_clears_events_too(store):
    add(store, 3)
    store.reset()
    assert store.list_events() == [] and store.last_event_id() == 0


def test_readonly_cannot_add_events(tmp_path):
    path = tmp_path / "s" / "e.db"
    with Store(path) as w:
        add(w, 2)
    with Store(path, readonly=True) as r:
        assert len(r.list_events()) == 2
        with pytest.raises(Exception):
            add(r, 1)


# ------------------------------------------------------------ old stores
def make_v1(path):
    os.makedirs(path.parent, mode=0o700, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript("""
    CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL, why TEXT NOT NULL,
      next_steps TEXT NOT NULL, description TEXT NOT NULL, severity TEXT NOT NULL, response TEXT NOT NULL, steps_done INTEGER NOT NULL,
      steps_total INTEGER NOT NULL, step_id TEXT NOT NULL, complete INTEGER NOT NULL, mitre TEXT NOT NULL, remote TEXT, anchor_pid INTEGER,
      revision INTEGER NOT NULL, evidence TEXT NOT NULL, detail TEXT NOT NULL, first_seen REAL NOT NULL, updated REAL NOT NULL,
      status TEXT NOT NULL DEFAULT 'open');
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE minute_stats (minute INTEGER PRIMARY KEY, events INTEGER NOT NULL DEFAULT 0, alerts INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE login_tokens (token_hash TEXT PRIMARY KEY, expires REAL NOT NULL);
    INSERT INTO alerts VALUES ('old1', 'r', 'chain', 'T', 'W', '[]', 'D', 'high', 'report_only', 1, 2, 's', 0, '[]', '1.2.3.4', NULL, 1, '[]', '', 1.0, 2.0, 'open');
    PRAGMA user_version=1;
    """)
    conn.commit()
    conn.close()
    path.chmod(0o600)


def test_an_old_store_is_upgraded_and_keeps_its_data(tmp_path):
    path = tmp_path / "state" / "erinix.db"
    make_v1(path)
    with Store(path) as s:
        row = s.get_alert("old1")
        assert row["title"] == "T" and row["step_labels"] == [] and row["remote"] == "1.2.3.4"
        add(s, 2)
        assert len(s.list_events()) == 2


def test_reading_an_old_store_upgrades_it_first(tmp_path):
    path = tmp_path / "state" / "erinix.db"
    make_v1(path)
    with Store(path, readonly=True) as r:                              # the dashboard and the console only read
        assert r.get_alert("old1")["step_labels"] == [] and r.list_events() == [] and r.last_event_id() == 0
    from erinix.summary import build_overview
    with Store(path, readonly=True) as r:
        assert build_overview(r)["open"]["total"] == 1


def test_upgrading_twice_is_harmless(tmp_path):
    path = tmp_path / "state" / "erinix.db"
    make_v1(path)
    for _ in range(3):
        Store(path).close()
    with Store(path) as s:
        assert s.get_alert("old1") is not None


def test_an_untrusted_old_store_is_still_refused(tmp_path):
    path = tmp_path / "state" / "erinix.db"
    make_v1(path)
    path.chmod(0o644)
    with pytest.raises(StoreError, match="too open"):
        Store(path, readonly=True)


def test_step_labels_roundtrip(tmp_path):
    import ipaddress

    from erinix.engine.alerts import Alert
    from erinix.rules import Response, Severity

    with Store(tmp_path / "s" / "e.db") as s:
        s.upsert_alert(Alert(alert_id="a" * 32, revision=1, rule_id="r", kind="chain", severity=Severity.HIGH, response=Response.REPORT_ONLY,
                             steps_done=1, steps_total=2, step_id="one", complete=False, mitre=(), description="d", evidence=(("one", ("e1",)),),
                             process=None, anchor=None, remote_addr=ipaddress.ip_address("10.0.0.1"), mono_ns=0, wall_ns=int(NOW * 1e9),
                             step_labels=("First thing", "Second thing")))
        assert s.get_alert("a" * 32)["step_labels"] == ["First thing", "Second thing"]
