import json
import random
import threading
import time

import pytest

from erinix.cli import main
from erinix.commands import store_cmds
from erinix.core.events import Event
from erinix.demo import live as live_demo
from erinix.store import Store


class FakeTime:
    def __init__(self):
        self.now = 0.0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


@pytest.fixture(autouse=True)
def private_state(tmp_path, monkeypatch):
    monkeypatch.setattr("erinix.history._running_as_root", lambda: False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()


def run_cli(capsys, *argv):
    code = main(["--no-color", *argv])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


# ------------------------------------------------------------------ the story
def test_the_story_is_ordered_fresh_and_covers_every_stage():
    first, second = live_demo.story(), live_demo.story()
    times = [t for t, _ in first]
    assert times == sorted(times) and 0 < times[0] < 10 and times[-1] <= live_demo.STORY_SECONDS
    assert not ({e.id for _, e in first} & {e.id for _, e in second})                  # new events every time, never reused ids
    kinds = {e.type.value for _, e in first}
    assert {"web.request", "auth.failure", "auth.success", "process.exec", "net.connect", "priv.uid_change", "file.access"} <= kinds


def test_noise_is_harmless_looking_and_varied():
    rng = random.Random(3)
    events = [live_demo.noise(rng, i) for i in range(400)]
    assert {e.type.value for e in events} >= {"web.request", "auth.success", "process.exec"}
    statuses = {e.payload.status for e in events if e.type.value == "web.request"}
    assert statuses == {200, 404}


def test_stamping_gives_the_current_time_and_keeps_the_event_valid():
    _, original = live_demo.story()[0]
    before = time.time_ns()
    stamped = live_demo.stamp(original)
    assert isinstance(stamped, Event) and stamped.id == original.id and stamped.wall_ns >= before and stamped.type is original.type


# --------------------------------------------------------------------- run()
def test_run_feeds_noise_and_the_story_as_time_passes():
    ft, fed = FakeTime(), []
    result = live_demo.run(fed.append, rng=random.Random(1), clock=ft.clock, sleep=ft.sleep, duration=live_demo.STORY_SECONDS + 2)
    assert result["story_finished"] and result["events"] == len(fed)
    expected_story = len(live_demo.story())
    assert expected_story + 40 < len(fed) < expected_story + 400                          # the story plus background traffic


def test_run_does_not_play_the_story_early():
    ft, fed = FakeTime(), []
    result = live_demo.run(fed.append, rng=random.Random(1), clock=ft.clock, sleep=ft.sleep, duration=5)
    assert not result["story_finished"] and all(e.type.value in ("web.request", "auth.success", "process.exec") for e in fed)
    assert not any(e.payload is not None and getattr(e.payload, "status", 0) == 404 and "python-requests" in getattr(e.payload, "agent", "") for e in fed)


def test_speed_makes_the_story_faster_and_is_validated():
    for speed in (0, 0.1, 11, -1, float("nan")):
        with pytest.raises(ValueError):
            live_demo.run(lambda e: None, speed=speed, clock=lambda: 0.0, sleep=lambda s: None, duration=0)
    slow, fast = FakeTime(), FakeTime()
    a = live_demo.run(lambda e: None, rng=random.Random(1), clock=slow.clock, sleep=slow.sleep, speed=1, duration=30)
    b = live_demo.run(lambda e: None, rng=random.Random(1), clock=fast.clock, sleep=fast.sleep, speed=4, duration=30)
    assert b["events"] > a["events"]


def test_run_stops_on_request_and_ticks_once_a_second():
    ft, ticks, fed = FakeTime(), [], []
    stop = lambda: ft.now >= 7.5
    live_demo.run(fed.append, rng=random.Random(1), clock=ft.clock, sleep=ft.sleep, stop=stop, tick=lambda: ticks.append(ft.now))
    assert ft.now >= 7.5 and 6 <= len(ticks) <= 8


# ----------------------------------------------------------- erinix demo --live
def test_demo_live_command_fills_the_store_in_real_time(capsys):
    code, out, _ = run_cli(capsys, "demo", "--live", "--for", "1", "--speed", "10")
    assert code == 0 and "Live demo running" in out and "Stopped after" in out
    with Store(readonly=True) as s:
        assert s.get_meta("mode") == "demo" and s.get_meta("sources") and s.last_event_id() > 0
        assert s.get_meta("heartbeat") is None or s.get_meta("heartbeat") > 0


def test_demo_live_validates_its_options(capsys):
    for argv in (["--speed", "0"], ["--speed", "abc"], ["--speed", "99"], ["--for", "-1"], ["--for", "x"]):
        assert run_cli(capsys, "demo", "--live", *argv)[0] == 2


def test_demo_live_never_erases_real_monitoring_data(capsys):
    with Store() as s:
        s.set_meta("mode", "live")
        s.set_meta("keep", "me")
    code, _, err = run_cli(capsys, "demo", "--live", "--for", "1")
    assert code == 1 and "real monitoring data" in err
    with Store(readonly=True) as s:
        assert s.get_meta("keep") == "me"


def test_demo_live_and_live_refuse_to_run_inside_the_full_screen_console():
    from erinix.ui.theme import Theme
    from erinix.commands.registry import Context

    out = []
    sink = type("W", (), {"write": lambda self, t: out.append(t) or len(t), "flush": lambda self: None})()
    ctx = Context(Theme(0, True, 100), Theme(0, True, 100), sink, sink, lambda r: None)
    assert store_cmds.cmd_demo(ctx, ["--live"]) == 2 and store_cmds.cmd_live(ctx, []) == 2
    assert "normal terminal" in "".join(out)


# ------------------------------------------------------------------ erinix live
def seed_events(*, flagged=True):
    from erinix.demo.scenarios import SCENARIOS
    from erinix.engine import Correlator
    from erinix.recorder import Recorder
    from erinix.rules import load_rules
    from pathlib import Path

    with Store() as s:
        rec = Recorder(s, Correlator(load_rules(Path(__file__).resolve().parents[2] / "rules")))
        for name in ("webquiet", "revshell"):
            for e in sorted(SCENARIOS[name].build(), key=lambda e: e.mono_ns):
                rec.feed(e)


def test_live_shows_recent_events_and_marks_the_suspicious_ones(capsys):
    seed_events()
    code, out, _ = run_cli(capsys, "live", "--for", "0.5")
    assert code == 0 and "Web request" in out and "Program started" in out
    flagged = [l for l in out.splitlines() if l.startswith("!")]
    assert flagged and all(any(w in l for w in ("bash", "10.0.0.5", "setuid")) for l in flagged)
    only = run_cli(capsys, "live", "--suspicious", "--for", "0.5")[1]
    assert only.strip() and all(l.startswith("!") for l in only.splitlines() if l.strip())


def test_live_follows_new_events(capsys):
    from erinix.demo.scenarios import _caddy
    from erinix.describe import describe
    from erinix.store import Store as S

    seed_events()
    holder = {}

    def writer():
        time.sleep(0.5)
        with S() as s:
            e = _caddy("192.168.50.99", "GET", "/arrived-later", 200, 0)
            label, summary, remote = describe(e)
            s.add_event(event_id="late", ts=time.time(), kind="web.request", label=label, summary=summary, remote=remote)

    t = threading.Thread(target=writer)
    t.start()
    code, out, _ = run_cli(capsys, "live", "--for", "1.6")
    t.join()
    assert code == 0 and "/arrived-later" in out and out.index("/arrived-later") > out.index("Program started")


def test_live_without_data_or_with_bad_options_is_clear(capsys):
    code, _, err = run_cli(capsys, "live", "--for", "0.2")
    assert code == 1 and "no data yet" in err
    assert run_cli(capsys, "live", "--for", "-3")[0] == 2 and run_cli(capsys, "live", "--bogus")[0] == 2


def test_hostile_event_text_cannot_inject_into_the_terminal(capsys):
    with Store() as s:
        s.add_event(event_id="x", ts=time.time(), kind="web.request", label="Web request", summary="GET /\x1b[2J\x1b]0;pwned\x07 → 200", remote="1.2.3.4")
    out = run_cli(capsys, "live", "--for", "0.3")[1]
    assert "\x1b" not in out and "\x07" not in out


def test_alert_detail_json_carries_the_steps(capsys):
    seed_events()
    data = json.loads(run_cli(capsys, "alerts", "--json")[1])
    chain = next(a for a in data if a["technical"]["kind"] == "chain")
    assert [s["state"] for s in chain["steps"]] == ["done", "done", "done"] and chain["timeline"]
    out = run_cli(capsys, "alert", "1")[1]
    assert "WHAT HAPPENED" in out and "bash (user 33)" in out and "became root" in out
