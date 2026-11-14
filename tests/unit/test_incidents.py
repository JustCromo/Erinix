import ipaddress
from pathlib import Path

import pytest

from erinix import incidents as inc
from erinix.demo import live as live_demo
from erinix.engine import Correlator
from erinix.engine.alerts import Alert
from erinix.recorder import Recorder
from erinix.rules import Response, Severity, load_rules
from erinix.store import Store

NOW = 1_700_000_000.0
RULES = Path(__file__).resolve().parents[2] / "rules"


def alert(aid, remote="203.0.113.50", severity=Severity.HIGH, tag="SQL injection", area="website", title="Thing from {remote}", wall=NOW, steps=None):
    return Alert(alert_id=aid * 32, revision=1, rule_id="r-" + aid, kind="indicator", severity=severity, response=Response.REPORT_ONLY,
                 steps_done=1, steps_total=1, step_id="s", complete=True, mitre=(), description="d", evidence=(("s", (f"e{aid}",)),),
                 process=None, anchor=None, remote_addr=ipaddress.ip_address(remote) if remote else None, mono_ns=0, wall_ns=int(wall * 1e9),
                 title=title, why="Why {remote}.", next_steps=(f"Do {aid}", "Block {remote}"), tag=tag, area=area)


@pytest.fixture()
def store(tmp_path):
    with Store(tmp_path / "s" / "e.db") as s:
        yield s


def test_one_attacker_is_one_incident(store):
    for i, tag in enumerate(("SQL injection", "Scanning", "SQL injection")):
        store.upsert_alert(alert("abc"[i], tag=tag, wall=NOW + i))
    store.upsert_alert(alert("d", remote="198.51.100.7", tag="Attack tool", wall=NOW + 9))
    out = inc.build_incidents(store)
    assert len(out) == 2
    many = next(i for i in out if i["who"] == "203.0.113.50")
    assert many["alert_count"] == 3 and many["tags"] == ["SQL injection", "Scanning"] and many["area"] == "website"       # tags are distinct
    assert many["headline"] == "Someone at 203.0.113.50 tried 3 different attacks on your website"
    assert many["summary"].startswith("Most serious: Thing from 203.0.113.50.") and many["status"] == "open" and many["first_seen"] == NOW
    one = next(i for i in out if i["who"] == "198.51.100.7")
    assert one["headline"] == "Thing from 198.51.100.7" and one["summary"] == "Why 198.51.100.7."


def test_alerts_without_an_address_form_this_machine(store):
    store.upsert_alert(alert("a", remote=None, tag="Password file change", area="this machine", title="The password file changed"))
    store.upsert_alert(alert("b", remote=None, tag="Remote control", area="this machine", title="x", wall=NOW + 1))
    (only,) = inc.build_incidents(store)
    assert only["who"] == "This machine" and only["local"] and only["headline"] == "2 suspicious things happened on this machine"


def test_the_headline_names_the_area_or_says_system(store):
    store.upsert_alert(alert("a", area="logins"))
    store.upsert_alert(alert("b", area="logins", wall=NOW + 1))
    assert inc.build_incidents(store)[0]["headline"].endswith("on your logins")
    store.upsert_alert(alert("c", area="website", wall=NOW + 2))
    assert inc.build_incidents(store)[0]["headline"].endswith("on your system")


def test_most_serious_first_then_most_recent(store):
    store.upsert_alert(alert("a", remote="10.0.0.1", severity=Severity.LOW, wall=NOW + 50))
    store.upsert_alert(alert("b", remote="10.0.0.2", severity=Severity.CRITICAL, wall=NOW))
    store.upsert_alert(alert("c", remote="10.0.0.3", severity=Severity.HIGH, wall=NOW + 10))
    store.upsert_alert(alert("d", remote="10.0.0.4", severity=Severity.HIGH, wall=NOW + 20))
    assert [i["who"] for i in inc.build_incidents(store)] == ["10.0.0.2", "10.0.0.4", "10.0.0.3", "10.0.0.1"]


def test_ids_are_stable_short_and_safe(store):
    a, b = inc.incident_id("ip:1.2.3.4"), inc.incident_id("ip:1.2.3.5")
    assert a == inc.incident_id("ip:1.2.3.4") and a != b and len(a) == 11 and a.isalnum() and inc.incident_id("local") != a
    store.upsert_alert(alert("a"))
    assert inc.build_incidents(store)[0]["id"] == inc.incident_id("ip:203.0.113.50")


def test_status_open_closed_and_filters(store):
    store.upsert_alert(alert("a", remote="10.0.0.1"))
    store.upsert_alert(alert("b", remote="10.0.0.2"))
    store.set_alert_status("a" * 32, "dismissed")
    assert [i["who"] for i in inc.build_incidents(store, "open")] == ["10.0.0.2"]
    assert [i["who"] for i in inc.build_incidents(store, "closed")] == ["10.0.0.1"] and len(inc.build_incidents(store, "all")) == 2
    for bad in ("", "OPEN", "dismissed", "all; drop"):
        with pytest.raises(ValueError):
            inc.build_incidents(store, bad)


def test_an_incident_with_one_closed_attack_stays_open_and_counts_only_open_ones(store):
    store.upsert_alert(alert("a", severity=Severity.CRITICAL))
    store.upsert_alert(alert("b", severity=Severity.LOW, wall=NOW + 1))
    store.set_alert_status("a" * 32, "dismissed")
    (i,) = inc.build_incidents(store)
    assert i["status"] == "open" and i["open_alerts"] == 1 and i["alert_count"] == 2 and i["severity"] == "low"      # judged by what is still open


def test_closing_and_reopening_an_incident(store):
    for k in "abc":
        store.upsert_alert(alert(k))
    store.upsert_alert(alert("d", remote="9.9.9.9"))
    iid = inc.incident_id("ip:203.0.113.50")
    assert inc.set_incident_status(store, iid, "closed") == 3
    assert inc.set_incident_status(store, iid, "closed") == 0                     # nothing left to change
    assert [i["who"] for i in inc.build_incidents(store, "open")] == ["9.9.9.9"]
    assert inc.set_incident_status(store, iid, "open") == 3 and len(inc.build_incidents(store, "open")) == 2
    assert inc.set_incident_status(store, "inope", "closed") == 0
    for bad in ("dismissed", "", None, "closed;"):
        with pytest.raises(ValueError):
            inc.set_incident_status(store, iid, bad)


def test_detail_merges_attacks_events_and_advice(store):
    store.upsert_alert(alert("a", tag="SQL injection", wall=NOW))
    store.upsert_alert(alert("b", tag="Scanning", severity=Severity.CRITICAL, wall=NOW + 5))
    store.add_event(event_id="ea", ts=NOW + 1, kind="web.request", label="Web request", summary="GET /a", remote="203.0.113.50", alert_id="a" * 32, step="s", severity="high")
    store.add_event(event_id="eb", ts=NOW + 0.5, kind="web.request", label="Web request", summary="GET /b", remote="203.0.113.50", alert_id="b" * 32, step="s", severity="critical")
    d = inc.incident_detail(store, inc.incident_id("ip:203.0.113.50"))
    assert [a["id"][0] for a in d["alerts"]] == ["a", "b"]                                  # attacks in the order they started
    assert [(e["summary"], e["tag"]) for e in d["timeline"]] == [("GET /b", "Scanning"), ("GET /a", "SQL injection")]   # events in time order
    assert d["next_steps"] == ["Do b", "Block 203.0.113.50", "Do a"]                        # most serious attack's advice first, no repeats
    assert inc.incident_detail(store, "inope") is None and inc.incident_detail(store, "' OR 1=1 --") is None


def test_advice_is_capped_and_the_timeline_is_bounded(store):
    for k in "abcdefghij":
        store.upsert_alert(alert(k, wall=NOW + ord(k)))
    assert len(inc.incident_detail(store, inc.incident_id("ip:203.0.113.50"))["next_steps"]) == inc.MAX_NEXT
    for i in range(300):
        store.add_event(event_id=f"x{i}", ts=NOW + i, kind="k", label="L", summary="S", alert_id="a" * 32, step="s", severity="low")
    assert len(inc.incident_detail(store, inc.incident_id("ip:203.0.113.50"))["timeline"]) <= inc.MAX_TIMELINE


def test_hostile_text_comes_back_raw_and_bounded(store):
    evil = "<script>alert(1)</script>'; DROP TABLE alerts; --" + "A" * 3000
    store.upsert_alert(alert("a", tag=evil, title=evil))
    (i,) = inc.build_incidents(store)
    assert "<script>" in i["headline"] and len(i["tags"][0]) <= 40 and len(inc.build_incidents(store)) == 1


def test_the_staged_story_becomes_five_incidents(store):
    rec = Recorder(store, Correlator(load_rules(RULES)))
    for _, event in live_demo.story():
        rec.feed(live_demo.stamp(event))
    out = inc.build_incidents(store)
    whos = {i["who"] for i in out}
    assert {"192.168.50.31", "203.0.113.50", "192.168.50.44", "This machine"} <= whos
    big = next(i for i in out if i["who"] == "192.168.50.31")
    assert big["alert_count"] >= 5 and {"SQL injection", "Scanning"} <= set(big["tags"]) and "different attacks on your website" in big["headline"]
    detail = inc.incident_detail(store, big["id"])
    assert len(detail["alerts"]) == big["alert_count"] and detail["timeline"] and all(e["tag"] for e in detail["timeline"])
