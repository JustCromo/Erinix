import dataclasses
import re
import time

import pytest

from erinix.commands.builtin import build_registry, default_rules_path
from erinix.demo.scenarios import SCENARIOS
from erinix.engine import Correlator
from erinix.recorder import Recorder
from erinix.rules import load_rules
from erinix.store import Store
from erinix.tui import cockpit as ck
from erinix.tui.terminal import visible_width
from erinix.ui.theme import Theme


@pytest.fixture()
def store_path(tmp_path):
    path = tmp_path / "e.db"
    store = Store(path)
    rec = Recorder(store, Correlator(load_rules(default_rules_path(None))))
    now = time.time()
    for ev in sorted(SCENARIOS["web"].build(), key=lambda e: e.mono_ns):
        rec.feed(dataclasses.replace(ev, wall_ns=int((now - 60 + ev.mono_ns / 1e9) * 1e9)))
    store.set_meta("mode", "live")
    store.set_meta("heartbeat", now)
    store.set_meta("sources", [{"name": "Programs", "state": "ok", "detail": ""}])
    store.set_meta("inventory", {"host": {}, "processes": [{"pid": 7, "ppid": 1, "uid": 0, "name": "evil\x1b[31m", "command": "nc -l 4444"}],
                                 "process_total": 1,
                                 "listening": [{"local": "0.0.0.0:22", "port": 22, "pid": None, "program": "", "uid": 0, "exposed": True}],
                                 "connections": [{"local": "1.1.1.1:5", "port": 5, "pid": 7, "program": "curl", "uid": 1, "remote": "9.9.9.9:443", "external": True}]})
    store.close()
    return path


def make(store_path, size=(140, 40)):
    th = Theme(0, True, width=size[0])
    return ck.Cockpit(th, None, open_store=lambda: Store(store_path, readonly=True), registry=build_registry(), size_fn=lambda: size)


@pytest.mark.parametrize("size", [(140, 40), (100, 30), (60, 20), (20, 8), (200, 60)])
def test_every_line_fits_the_terminal(store_path, size):
    c = make(store_path, size)
    c.refresh(True)
    for line in c.render():
        assert visible_width(line) <= size[0]
    assert len(c.render()) == max(8, size[1])


def test_wide_layout_shows_all_panels(store_path):
    c = make(store_path)
    c.refresh(True)
    text = "\n".join(c.render())
    for title in ("Incidents", "Live", "Open ports", "Connections", "Programs"):
        assert title in text
    assert "unknown program" in text and ":22" in text


def test_control_characters_from_the_machine_are_not_printed(store_path):
    c = make(store_path)
    c.refresh(True)
    c.focus = 4
    assert "\x1b[31m" not in "\n".join(c.render()).replace("\x1b[H", "")


def test_keys_move_focus_search_and_quit(store_path):
    c = make(store_path)
    c.refresh(True)
    c.handle("\t")
    assert c.focus == 1
    c.handle("3")
    assert c.focus == 2
    c.handle("/"); c.handle("2"); c.handle("2"); c.handle("\r")
    assert c.query["ports"] == "22"
    c.handle("/"); c.handle("z"); c.handle("z"); c.handle("z"); c.handle("\r")
    assert "nothing matches" in "\n".join(c.render())
    c.handle("/"); c.handle("\x1b")
    assert c.query["ports"] == ""
    c.handle("q")
    assert c.done


def test_enter_opens_incident_and_x_closes_it(store_path, monkeypatch):
    monkeypatch.setattr("erinix.store.default_db_path", lambda: store_path)
    c = make(store_path)
    c.refresh(True)
    assert c.data.incidents
    c.handle("\r")
    assert c.zoom and c.mode == "normal"              # first Enter: the panel fills the screen
    c.handle("\r")
    assert c.mode == "overlay" and "What happened" in "\n".join(c.overlay)
    c.handle("q")
    assert c.mode == "normal"


def test_command_runs_in_an_overlay_and_blocks_watch(store_path, monkeypatch):
    monkeypatch.setattr("erinix.store.default_db_path", lambda: store_path)
    c = make(store_path)
    c.refresh(True)
    c.handle(":")
    for ch in "status":
        c.handle(ch)
    c.handle("\r")
    assert c.mode == "overlay" and c.overlay
    c.handle("q")
    c.run_command("watch")
    assert "already watching" in c.flash
    c.run_command("nonsense-command")
    assert "unknown command" in "\n".join(c.overlay)


def test_missing_store_is_a_message_not_a_crash(tmp_path):
    th = Theme(0, True, width=100)
    c = ck.Cockpit(th, None, open_store=lambda: Store(tmp_path / "none.db", readonly=True), size_fn=lambda: (100, 30))
    c.refresh(True)
    assert "no data yet" in "\n".join(c.render())


def test_routine_toggle_and_pause(store_path):
    c = make(store_path)
    c.refresh(True)
    c.handle("r")
    assert c.routine
    c.handle("p")
    assert c.paused_at is not None
    c.handle("p")
    assert c.paused_at is None


def test_sparkline_and_helpers():
    assert ck.sparkline([0, 0, 5, 10], 4)[-1] == "█"
    assert ck.sparkline([], 5) == ""
    assert ck.ago(time.time() - 120, time.time()) == "2m"
    assert re.fullmatch(r"\d\d:\d\d:\d\d", ck.clock(time.time()))
    assert ck.clock("junk") == "--:--:--"


def test_enter_goes_in_and_esc_goes_back(store_path):
    c = make(store_path)
    c.refresh(True)
    c.handle("3")
    c.handle("\r"); c.handle("\r")
    text = "\n".join(c.overlay)
    assert c.mode == "overlay" and "Port 22" in c.overlay_title and "unknown" in text
    c.handle("\x1b")
    assert c.mode == "normal" and c.zoom
    c.handle("q")
    assert not c.zoom and not c.done
    c.handle("q")
    assert c.done


def test_unchanged_screen_is_not_repainted(store_path):
    import io
    c = make(store_path)
    c.out = io.StringIO()
    c.refresh(True)
    c.draw()
    first = c.out.getvalue()
    c.draw()
    assert c.out.getvalue() == first
