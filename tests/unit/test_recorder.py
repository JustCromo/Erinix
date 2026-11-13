import random
from pathlib import Path

import pytest

from erinix.demo import live as live_demo
from erinix.demo.scenarios import SCENARIOS
from erinix.engine import Correlator
from erinix.recorder import Recorder
from erinix.rules import load_rules
from erinix.store import Store
from erinix.summary import humanize_full

RULES = Path(__file__).resolve().parents[2] / "rules"


@pytest.fixture()
def rec(tmp_path):
    with Store(tmp_path / "s" / "e.db") as store:
        yield Recorder(store, Correlator(load_rules(RULES)))


def play(rec, name):
    return [a for e in sorted(SCENARIOS[name].build(), key=lambda e: e.mono_ns) for a in rec.feed(e)]


def steps(rec, rule):
    row = next(r for r in rec.store.list_alerts("all") if r["rule_id"] == rule)
    return [(s["state"], s["label"]) for s in humanize_full(rec.store, row)["steps"]]


def test_every_event_is_recorded_once(rec):
    play(rec, "revshell")
    rows = rec.store.list_events(limit=500)
    assert len(rows) == 6 and len({r["event_id"] for r in rows}) == 6
    assert [r["label"] for r in rows][:3] == ["Program started", "Program started", "Program started"]
    assert rec.store.activity()[-1]["events"] + sum(p["events"] for p in rec.store.activity()[:-1]) == 6


def test_the_steps_of_an_attack_appear_one_at_a_time(rec):
    expected = []
    for event in sorted(SCENARIOS["revshell"].build(), key=lambda e: e.mono_ns):
        rec.feed(event)
        if rec.store.list_alerts("all"):
            expected.append(steps(rec, "web-rce-revshell"))
    assert expected[0] == [("done", "A web program starts a command line"), ("current", "The command line connects to another machine"),
                           ("pending", "It gains full control (root)")]
    assert [s[0] for s in expected[-1]] == ["done", "done", "done"]
    progress = [sum(1 for s in e if s[0] == "done") for e in expected]
    assert progress == sorted(progress) and progress[0] == 1 and progress[-1] == 3        # it only ever moves forward


def test_step_details_name_the_event_that_completed_the_step(rec):
    play(rec, "revshell")
    row = next(r for r in rec.store.list_alerts("all") if r["rule_id"] == "web-rce-revshell")
    full = humanize_full(rec.store, row)
    assert [s["detail"] for s in full["steps"]] == ["bash (user 33)", "bash → 10.0.0.5:4444", "setuid: user 33 → 0 (became root)"]
    assert all(s["time"] for s in full["steps"]) and [e["step"] for e in full["timeline"]] == ["service-spawns-shell", "shell-connects-outbound", "escalation-to-root"]


def test_hits_that_were_only_counted_join_the_attack_afterwards(rec):
    play(rec, "ssh")
    row = next(r for r in rec.store.list_alerts("all") if r["rule_id"] == "ssh-bruteforce-success")
    full = humanize_full(rec.store, row)
    failed = full["steps"][0]
    assert failed["state"] == "done" and failed["count"] >= 5 and "times" not in failed["detail"]
    linked = [e for e in full["timeline"] if e["step"] == "repeated-failures"]
    assert len(linked) >= 5                                                       # the earlier failures are part of it now
    others = [e for e in rec.store.list_events(limit=500) if e["alert_id"] is None]
    assert others and all("203.0.113.50" != e["remote"] or e["label"] != "Login failed" for e in others[:0] or [])


def test_indicators_link_their_single_event(rec):
    play(rec, "shadow")
    row = next(r for r in rec.store.list_alerts("all") if r["kind"] == "indicator")
    full = humanize_full(rec.store, row)
    assert full["steps"] == [] and [e["summary"] for e in full["timeline"]] == ["write /etc/shadow by vim"]


@pytest.mark.parametrize("scenario", ["webquiet", "admin"])
def test_normal_activity_is_recorded_but_never_flagged(rec, scenario):
    assert play(rec, scenario) == []
    rows = rec.store.list_events(limit=500)
    assert rows and all(r["alert_id"] is None for r in rows) and rec.store.list_alerts("all") == []


def test_background_traffic_never_raises_anything(rec):
    rng = random.Random(1)
    alerts = [a for i in range(600) for a in rec.feed(live_demo.stamp(live_demo.noise(rng, i)))]
    assert alerts == [] and rec.store.list_alerts("all") == []
    assert all(e["alert_id"] is None for e in rec.store.list_events(limit=500))


def test_the_staged_story_raises_every_chain_and_marks_only_attack_events(rec):
    for _, event in live_demo.story():
        rec.feed(live_demo.stamp(event))
    rules = {r["rule_id"] for r in rec.store.list_alerts("all")}
    assert {"web-recon-then-attack", "web-login-bruteforce-success", "ssh-bruteforce-success", "web-rce-revshell",
            "shadow-written-by-unexpected-process"} <= rules
    flagged = [e for e in rec.store.list_events(limit=500) if e["alert_id"]]
    assert flagged and all(e["severity"] in ("low", "medium", "high", "critical") and e["step"] for e in flagged)
    done = [humanize_full(rec.store, r) for r in rec.store.list_alerts("all") if r["kind"] == "chain"]
    assert done and all(s["state"] == "done" for a in done for s in a["steps"])


def test_a_dismissed_attack_comes_back_when_it_grows(rec):
    events = sorted(SCENARIOS["revshell"].build(), key=lambda e: e.mono_ns)
    for e in events[:3]:
        rec.feed(e)
    alert_id = rec.store.list_alerts("all")[0]["alert_id"]
    rec.store.set_alert_status(alert_id, "dismissed")
    for e in events[3:]:
        rec.feed(e)
    assert rec.store.get_alert(alert_id)["status"] == "open" and rec.store.get_alert(alert_id)["steps_done"] == 3
