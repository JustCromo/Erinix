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
    from erinix.assessment import Env, run_assessment
    store.set_meta("assessment", {"at": now, "score": 62, "verdict": "x", "counts": {}, "full_view": False, "checks": [
        {"id": "ssh.root_login", "area": "Remote access", "title": "Root cannot log in over SSH", "severity": "high", "state": "fail",
         "detail": "SSH lets root log in directly.\x1b[31m", "fix": "Set PermitRootLogin to no."},
        {"id": "x", "area": "System", "title": "Fine thing", "severity": "low", "state": "ok", "detail": "ok", "fix": ""}]})
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
    for title in ("Incidents", "Live", "Open ports", "Connections", "Programs", "Health"):
        assert title in text
    assert "unknown program" in text and ":22" in text


def test_control_characters_from_the_machine_are_not_printed(store_path):
    c = make(store_path)
    c.refresh(True)
    c.focus = 5
    assert "\x1b[31m" not in "\n".join(c.render()).replace("\x1b[H", "")


def test_keys_move_focus_search_and_quit(store_path):
    c = make(store_path)
    c.refresh(True)
    c.handle("\t")
    assert c.focus == 1
    c.handle("4")
    assert c.focus == 3 and ck.PANELS[c.focus] == "ports"
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
    c.handle("4")
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


def test_health_panel_lists_only_what_needs_attention_and_shows_the_fix(store_path):
    c = make(store_path)
    c.refresh(True)
    rows = c.rows("posture")
    assert len(rows) == 1 and "Root cannot log in" in rows[0][1]
    assert "62/100" in "\n".join(c.render())
    c.handle("3")
    c.handle("\r"); c.handle("\r")
    text = "\n".join(c.overlay)
    assert "How to fix" in text and "PermitRootLogin" in text and "\x1b" not in text


def test_tab_order_follows_the_screen(store_path):
    assert ck.PANELS == ("incidents", "live", "posture", "ports", "connections", "programs")
    c = make(store_path)
    c.refresh(True)
    lines = c.render()
    first_row = "\n".join(lines)
    # the Health box sits above the ports box in the right column, matching the Tab order
    assert first_row.index("3 Health") < first_row.index("4 Open ports") < first_row.index("5 Connections") < first_row.index("6 Programs")


# ------------------------------------------------------------------ mitigation keys
class FakeService:
    helper = None

    def __init__(self):
        from erinix import actions
        self.actions, self.ran = actions, []

    def plan(self, action, args):
        if args.get("ip") == "127.0.0.1":
            raise self.actions.ActionError("this address cannot be blocked")
        return self.actions.Plan(action, args, f"{action} {args}", ["step one"], needs_root=False)

    def run_action(self, action, args, title=""):
        self.ran.append((action, args))
        return {"ok": True, "message": "did it", "undo": {"action": "unblock"}, "n": 3}


def with_service(store_path):
    c = make(store_path)
    c.service = FakeService()
    c.refresh(True)
    return c


def test_nothing_is_done_without_a_y(store_path):
    c = with_service(store_path)
    c.handle("1")
    c.handle("b")
    assert c.mode == "confirm" and "Press y" in "\n".join(c.overlay) and not c.service.ran
    c.handle("n")
    assert c.mode == "normal" and not c.service.ran and "cancelled" in c.flash
    c.handle("b"); c.handle("\r")                        # Enter is not a yes either
    assert not c.service.ran
    c.handle("b"); c.handle("y")
    assert c.service.ran and c.service.ran[0][0] == "block" and "Undo with" in "\n".join(c.overlay)


def test_block_uses_the_incident_address_and_refuses_this_machine(store_path):
    c = with_service(store_path)
    c.handle("1")
    c.handle("b")
    assert c.pending[1]["ip"] == c.data.incidents[0]["who"]
    c.handle("n")
    c.data.incidents[0]["local"] = True
    c.handle("b")
    assert c.mode == "normal" and "comes from an address" in c.flash


def test_kill_and_fix_need_the_right_panel(store_path):
    c = with_service(store_path)
    c.handle("k")
    assert "select a program" in c.flash
    c.handle("6"); c.handle("k")
    assert c.mode == "confirm" and c.pending[0] == "kill" and c.pending[1]["pid"] == 7
    c.handle("n")
    c.handle("f")
    assert "Health panel" in c.flash
    c.handle("3"); c.handle("f")
    assert c.pending[0] == "fix" and c.pending[1]["check"] == "ssh.root_login"


def test_refused_plans_explain_themselves(store_path):
    c = with_service(store_path)
    c.ask("block", {"ip": "127.0.0.1"})
    assert c.mode == "normal" and "cannot be blocked" in c.flash
    c.service = None
    c.ask("block", {"ip": "1.2.3.4"})
    assert "not available" in c.flash


def test_every_line_still_fits_in_confirm_mode(store_path):
    c = with_service(store_path)
    c.handle("1"); c.handle("b")
    from erinix.tui.terminal import visible_width
    assert all(visible_width(l) <= 140 for l in c.render())


def test_footer_shows_the_keys_of_the_focused_panel(store_path):
    c = make(store_path)
    c.refresh(True)
    assert "block its address" in c.render()[-1]
    c.handle("3")
    assert "how to fix" in c.render()[-1] and "fix it" in c.render()[-1]
    c.handle("6")
    assert "stop it" in c.render()[-1]
    assert "guide" in c.render()[-1]


def test_typing_a_command_suggests_commands_and_shows_usage(store_path):
    c = make(store_path)
    c.refresh(True)
    c.handle(":")
    assert "assess" in c.render()[-1] and "block" in c.render()[-1]
    for ch in "bl":
        c.handle(ch)
    last = c.render()[-1]
    assert "block" in last and "alerts" not in last
    for ch in "ock ":
        c.handle(ch)
    assert "block <ip>" in c.render()[-1] and "--minutes" in c.render()[-1]
    c.handle("\x1b")
    assert "guide" in c.render()[-1]


def test_the_guide_explains_where_to_type(store_path):
    c = make(store_path)
    c.refresh(True)
    c.handle("?")
    text = "\n".join(c.overlay)
    assert "WHERE DO I TYPE" in text and "Press  :" in text and "block 203.0.113.50" in text and "assess" in text
    assert "Esc" in c.render()[-1]


def test_the_status_line_points_to_the_guide(store_path):
    c = make(store_path)
    c.refresh(True)
    assert "? for the guide" in c.render()[-2]
