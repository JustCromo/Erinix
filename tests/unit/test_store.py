import os
import stat

import pytest

from erinix.engine.alerts import Alert
from erinix.rules import Response, Severity
from erinix.store import Store, StoreError
from erinix.summary import build_overview, expand, humanize

NOW = 1_700_000_000.0


def alert(aid="a" * 32, *, severity=Severity.HIGH, revision=1, remote="203.0.113.50", title="Bad thing from {remote}",
          steps=(1, 1), kind="indicator", wall=NOW):
    import ipaddress
    return Alert(alert_id=aid, revision=revision, rule_id="web-sqli-attempt", kind=kind, severity=severity,
                 response=Response.REPORT_ONLY, steps_done=steps[0], steps_total=steps[1], step_id="s", complete=steps[0] == steps[1],
                 mitre=("T1190",), description="desc", evidence=(("s", ("e1", "e2")),), process=None, anchor=None,
                 remote_addr=ipaddress.ip_address(remote) if remote else None, mono_ns=0, wall_ns=int(wall * 1e9),
                 title=title, why="Because {remote}.", next_steps=("Block {remote}", "Look around"))


@pytest.fixture()
def store(tmp_path):
    with Store(tmp_path / "state" / "erinix.db") as s:
        yield s


# ------------------------------------------------------------------ files
def test_store_is_private(tmp_path):
    path = tmp_path / "state" / "erinix.db"
    Store(path).close()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600 and stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700


def test_untrusted_files_are_refused(tmp_path):
    path = tmp_path / "state" / "erinix.db"
    Store(path).close()
    path.chmod(0o644)
    for readonly in (False, True):
        with pytest.raises(StoreError, match="too open"):
            Store(path, readonly=readonly)
    path.chmod(0o600)
    link = tmp_path / "state" / "link.db"
    link.symlink_to(path)
    with pytest.raises(StoreError, match="symlink|not a regular"):
        Store(link)
    open_dir = tmp_path / "open"
    open_dir.mkdir()
    open_dir.chmod(0o777)
    with pytest.raises(StoreError, match="too open"):
        Store(open_dir / "x.db")


def test_readonly_needs_an_existing_store_and_cannot_write(tmp_path):
    with pytest.raises(StoreError, match="no data yet"):
        Store(tmp_path / "nope.db", readonly=True)
    path = tmp_path / "state" / "erinix.db"
    with Store(path) as w:
        w.upsert_alert(alert())
    with Store(path, readonly=True) as r:
        assert len(r.list_alerts()) == 1
        with pytest.raises(Exception):
            r.upsert_alert(alert("b" * 32))


# ----------------------------------------------------------------- alerts
def test_alert_roundtrip_and_ordering(store):
    store.upsert_alert(alert("a" * 32, severity=Severity.LOW, wall=NOW + 5))
    store.upsert_alert(alert("b" * 32, severity=Severity.CRITICAL, wall=NOW))
    store.upsert_alert(alert("c" * 32, severity=Severity.HIGH, wall=NOW + 9))
    rows = store.list_alerts()
    assert [r["severity"] for r in rows] == ["critical", "high", "low"]
    r = rows[0]
    assert r["mitre"] == ["T1190"] and r["evidence"] == [["s", ["e1", "e2"]]] and r["remote"] == "203.0.113.50" and r["complete"] is True


def test_updates_keep_first_seen_and_reopen_when_the_attack_grows(store):
    store.upsert_alert(alert(revision=1, steps=(1, 3), kind="chain", wall=NOW))
    assert store.set_alert_status("a" * 32, "dismissed")
    store.upsert_alert(alert(revision=1, steps=(1, 3), kind="chain", wall=NOW + 10))      # same revision: stays dismissed
    row = store.get_alert("a" * 32)
    assert row["status"] == "dismissed" and row["first_seen"] == NOW and row["updated"] == NOW + 10
    store.upsert_alert(alert(revision=2, steps=(2, 3), kind="chain", severity=Severity.CRITICAL, wall=NOW + 20))
    row = store.get_alert("a" * 32)
    assert row["status"] == "open" and row["severity"] == "critical" and row["steps_done"] == 2


def test_status_filters_counts_and_validation(store):
    store.upsert_alert(alert("a" * 32))
    store.upsert_alert(alert("b" * 32, severity=Severity.MEDIUM))
    store.set_alert_status("b" * 32, "dismissed")
    assert [r["alert_id"] for r in store.list_alerts("open")] == ["a" * 32]
    assert len(store.list_alerts("dismissed")) == 1 and len(store.list_alerts("all")) == 2
    assert store.counts() == {"open": 1, "open_by_severity": {"low": 0, "medium": 0, "high": 1, "critical": 0}, "dismissed": 1}
    for bad in ("DROP TABLE alerts", "", "open; --"):
        with pytest.raises(StoreError):
            store.list_alerts(bad)
        with pytest.raises(StoreError):
            store.set_alert_status("a" * 32, bad)
    assert not store.set_alert_status("f" * 32, "dismissed")


def test_hostile_text_is_stored_bounded_and_raw_and_never_executed(store):
    evil = "x'); DROP TABLE alerts; --<script>alert(1)</script>" + "A" * 5000
    store.upsert_alert(alert(title=evil))
    row = store.list_alerts()[0]
    assert row["title"].startswith("x'); DROP TABLE alerts;") and len(row["title"]) == 2000
    assert len(store.list_alerts()) == 1
    assert store.find_alert("a" * 6)["alert_id"] == "a" * 32
    for bad in ("", "abc", "a%", "a_a_a_", "'; --", "a" * 5 + "%"):
        assert store.find_alert(bad) is None
    assert store.get_alert("' OR 1=1 --") is None


def test_find_alert_by_prefix_must_be_unique(store):
    store.upsert_alert(alert("abcdef" + "0" * 26))
    store.upsert_alert(alert("abcdef" + "1" * 26))
    assert store.find_alert("abcdef") is None
    assert store.find_alert("abcdef0")["alert_id"].endswith("0")


def test_limits_are_clamped(store):
    for i in range(5):
        store.upsert_alert(alert(f"{i}" * 32))
    assert len(store.list_alerts(limit=2)) == 2 and len(store.list_alerts(limit=-5)) == 1 and len(store.list_alerts(limit=10**9)) == 5


# ------------------------------------------------------------ stats and meta
def test_activity_buckets(store):
    store.bump(events=10, now=NOW)
    store.bump(events=5, alerts=1, now=NOW + 30)
    store.bump(events=7, now=NOW - 3 * 3600)
    store.bump(events=99, now=NOW - 30 * 3600)                    # outside the 24 h window
    act = store.activity(now=NOW + 60)
    assert len(act) == 48 and sum(p["events"] for p in act) == 22 and sum(p["alerts"] for p in act) == 1
    assert act == sorted(act, key=lambda p: p["t"])


def test_meta_roundtrip_and_prune(store):
    store.set_meta("sources", [{"name": "x"}])
    assert store.get_meta("sources") == [{"name": "x"}] and store.get_meta("missing", 5) == 5
    store.bump(events=1, now=NOW - 100 * 3600)
    store.upsert_alert(alert(wall=NOW - 40 * 86400))
    store.set_alert_status("a" * 32, "dismissed")
    store.prune(now=NOW)
    assert store.list_alerts("all") == [] and store.activity(now=NOW - 100 * 3600 + 60)[0]["events"] == 0


def test_reset_clears_everything(store):
    store.upsert_alert(alert())
    store.set_meta("mode", "demo")
    store.reset()
    assert store.list_alerts("all") == [] and store.get_meta("mode") is None


# ------------------------------------------------------------ login tokens
def test_login_tokens_work_once_and_expire(store):
    token = store.create_login_token(now=NOW)
    assert store.consume_login_token(token, now=NOW + 1) is True
    assert store.consume_login_token(token, now=NOW + 2) is False                # one-time
    old = store.create_login_token(ttl=10, now=NOW)
    assert store.consume_login_token(old, now=NOW + 11) is False                 # expired
    for junk in ("", "x", "a" * 200, None, 5, "' OR '1'='1' --" + "a" * 10):
        assert store.consume_login_token(junk) is False


def test_tokens_are_stored_hashed_and_limited(store):
    token = store.create_login_token()
    raw = [r[0] for r in store._conn.execute("SELECT token_hash FROM login_tokens")]
    assert token not in raw and len(raw[0]) == 64
    for _ in range(30):
        store.create_login_token()
    assert store._conn.execute("SELECT COUNT(*) FROM login_tokens").fetchone()[0] <= 10


# ----------------------------------------------------------------- overview
def test_expand_and_humanize(store):
    assert expand("Block {remote}", "1.2.3.4") == "Block 1.2.3.4" and expand("From {remote}", None) == "From an unknown address"
    store.upsert_alert(alert(kind="chain", steps=(1, 3)))
    h = humanize(store.list_alerts()[0])
    assert h["headline"] == "Bad thing from 203.0.113.50" and h["next_steps"] == ["Block 203.0.113.50", "Look around"]
    assert h["progress"] == {"done": 1, "total": 3, "complete": False} and h["technical"]["rule"] == "web-sqli-attempt"
    store.upsert_alert(alert("b" * 32, title="", remote=None))
    plain = [humanize(r) for r in store.list_alerts() if r["alert_id"] == "b" * 32][0]
    assert plain["headline"] == "desc" and plain["progress"] is None


def test_overview_states(store):
    o = build_overview(store, now=NOW)
    assert o["state"] == "stopped" and o["headline"] == "Erinix is not running" and o["blind_spots"]
    store.set_meta("mode", "live")
    store.set_meta("heartbeat", NOW)
    store.set_meta("sources", [{"name": "SSH logins", "state": "ok"}, {"name": "Caddy log", "state": "missing", "detail": "not set up"}])
    o = build_overview(store, now=NOW + 5)
    assert o["state"] == "protected" and o["blind_spots"] == ["Caddy log: not set up"]
    assert build_overview(store, now=NOW + 60)["state"] == "stopped"             # heartbeat too old
    store.upsert_alert(alert(severity=Severity.MEDIUM))
    o = build_overview(store, now=NOW + 5)
    assert o["state"] == "attention" and o["headline"] == "1 thing needs attention" and o["open"]["medium"] == 1
    store.upsert_alert(alert("b" * 32, severity=Severity.HIGH))
    assert build_overview(store, now=NOW + 5)["headline"] == "2 things need attention"
    store.upsert_alert(alert("c" * 32, severity=Severity.CRITICAL))
    o = build_overview(store, now=NOW + 5)
    assert o["state"] == "critical" and o["attention"][0]["severity"] == "critical" and len(o["attention"]) == 3


def test_demo_mode_counts_as_running(store):
    store.set_meta("mode", "demo")
    o = build_overview(store, now=NOW)
    assert o["demo"] and o["state"] == "protected" and "Demo" in o["headline"] and o["blind_spots"] == []
