import http.client
import json
import os
import threading
import time

import pytest

from erinix.cli import main
from erinix.commands import store_cmds
from erinix.commands.registry import Context
from erinix.store import Store
from erinix.web import server as web


@pytest.fixture(autouse=True)
def private_state(tmp_path, monkeypatch):
    monkeypatch.setattr("erinix.history._running_as_root", lambda: False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    return tmp_path


def run(capsys, *argv):
    code = main(["--no-color", *argv])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def demo(capsys):
    assert run(capsys, "demo")[0] == 0


# ------------------------------------------------------------------- no data
def test_everything_works_before_any_data_exists(capsys):
    code, out, _ = run(capsys, "status")
    assert code == 0 and "Erinix is not running" in out and "erinix demo" in out
    status = json.loads(run(capsys, "status", "--json")[1])
    assert status["state"] == "stopped" and status["open"]["total"] == 0
    assert "Nothing needs your attention" in run(capsys, "alerts")[1]
    assert json.loads(run(capsys, "alerts", "--json")[1]) == []
    assert run(capsys, "alert", "1")[0] == 1 and run(capsys, "sources")[0] == 0
    assert not (private_state_path() / "erinix.db").exists()          # reading never creates a store


def private_state_path():
    from erinix.history import state_dir
    return state_dir()


# ---------------------------------------------------------------------- demo
def test_demo_fills_the_store_and_reads_back_in_plain_language(capsys):
    code, out, _ = run(capsys, "demo")
    assert code == 0 and "Demo data loaded" in out
    code, out, _ = run(capsys, "status")
    assert "Needs your attention now" in out and "NEEDS ATTENTION" in out and "Demo data" in out and "Kernel-level events" in out
    assert "web-rce-revshell" not in out                              # the first screen has no technical names
    status = json.loads(run(capsys, "status", "--json")[1])
    assert status["state"] == "critical" and status["open"]["total"] >= 8 and status["demo"] is True
    assert status["events_24h"] > 1000 and len(status["activity"]) == 48


def test_demo_is_repeatable_and_reset_clears(capsys):
    demo(capsys)
    first = json.loads(run(capsys, "status", "--json")[1])["open"]["total"]
    demo(capsys)
    assert json.loads(run(capsys, "status", "--json")[1])["open"]["total"] == first
    assert run(capsys, "demo", "--reset")[0] == 0
    assert json.loads(run(capsys, "status", "--json")[1])["open"]["total"] == 0


def test_demo_refuses_to_erase_real_monitoring_data(capsys):
    demo(capsys)
    with Store() as s:
        s.set_meta("mode", "live")
    code, _, err = run(capsys, "demo")
    assert code == 1 and "real monitoring data" in err
    assert run(capsys, "demo", "--force")[0] == 0


# -------------------------------------------------------------------- alerts
def test_alert_list_and_detail(capsys):
    demo(capsys)
    out = run(capsys, "alerts")[1]
    assert "What happened" in out and "CRITICAL" in out and "Someone is guessing SSH passwords from 203.0.113.50" in out
    rows = json.loads(run(capsys, "alerts", "--json")[1])
    assert rows[0]["severity"] == "critical" and all("technical" in r for r in rows)
    code, out, _ = run(capsys, "alert", "1")
    assert code == 0 and "WHAT TO DO" in out and "1. " in out and "--tech" in out and "TECHNICAL DETAILS" not in out
    code, out, _ = run(capsys, "alert", "1", "--tech")
    assert "TECHNICAL DETAILS" in out and "Rule" in out and "MITRE ATT&CK" in out and "Evidence" in out
    detail = json.loads(run(capsys, "alert", "1", "--json")[1])
    assert detail["id"] == rows[0]["id"]
    assert run(capsys, "alert", rows[0]["id"][:8], "--json")[0] == 0                 # an id prefix works too


def test_alert_errors_are_clear_and_safe(capsys):
    demo(capsys)
    assert run(capsys, "alert")[0] == 2
    code, _, err = run(capsys, "alert", "999")
    assert code == 1 and "no alert number 999" in err
    for ref in ("abc", "'; DROP TABLE alerts; --", "%", "0", "-1", "a" * 500):
        code, _, err = run(capsys, "alert", ref)
        assert code in (1, 2) and "Traceback" not in err
    assert run(capsys, "alerts")[0] == 0                                              # nothing was damaged


def test_dismiss_and_reopen_by_number(capsys):
    demo(capsys)
    before = len(json.loads(run(capsys, "alerts", "--json")[1]))
    code, out, _ = run(capsys, "dismiss", "1")
    assert code == 0 and "dismissed" in out
    assert len(json.loads(run(capsys, "alerts", "--json")[1])) == before - 1
    assert len(json.loads(run(capsys, "alerts", "--dismissed", "--json")[1])) == 1
    assert len(json.loads(run(capsys, "alerts", "--all", "--json")[1])) == before
    code, out, _ = run(capsys, "reopen", "1")
    assert code == 0 and "reopened" in out and len(json.loads(run(capsys, "alerts", "--json")[1])) == before
    assert run(capsys, "dismiss")[0] == 2 and run(capsys, "dismiss", "500")[0] == 1


def test_sources_and_blind_spots(capsys):
    demo(capsys)
    out = run(capsys, "sources")[1]
    assert "Watching" in out and "Blind" in out and "Kernel-level events" in out
    data = json.loads(run(capsys, "sources", "--json")[1])
    assert any(s["state"] != "ok" for s in data["sources"]) and data["blind_spots"]


def test_console_output_blocks_follow_the_terminal_width(capsys, monkeypatch):
    demo(capsys)
    widths = []
    for width in (70, 110):
        monkeypatch.setattr("erinix.ui.theme.Theme.width", property(lambda self, w=width: w))
        lines = run(capsys, "status")[1].splitlines()
        widths.append(max(len(line) for line in lines))
    assert widths[0] <= 70 and widths[1] > widths[0]


# ------------------------------------------------------------------ dashboard
@pytest.fixture()
def running_dashboard(private_state):
    from erinix.history import state_dir
    from erinix.store import default_db_path

    with Store() as s:                                    # create the real store the commands use
        s.set_meta("mode", "demo")
    server = web.DashboardServer(0, default_db_path())
    threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True).start()
    info = state_dir() / "server.json"
    info.write_text(json.dumps({"pid": os.getpid(), "port": server.port, "started": time.time()}))
    info.chmod(0o600)
    yield server
    server.shutdown()
    server.server_close()


def test_ui_prints_a_one_time_link_that_signs_in(capsys, running_dashboard):
    code, out, _ = run(capsys, "ui", "--no-browser")
    assert code == 0 and "works once" in out
    url = next(line for line in out.splitlines() if line.startswith("http://127.0.0.1:"))
    assert f":{running_dashboard.port}/login?t=" in url
    path = url.split(str(running_dashboard.port), 1)[1]
    conn = http.client.HTTPConnection("127.0.0.1", running_dashboard.port, timeout=5)
    conn.request("GET", path, headers={"Host": f"127.0.0.1:{running_dashboard.port}"})
    assert conn.getresponse().status == 303
    conn = http.client.HTTPConnection("127.0.0.1", running_dashboard.port, timeout=5)
    conn.request("GET", path, headers={"Host": f"127.0.0.1:{running_dashboard.port}"})
    assert conn.getresponse().status == 403                                              # the link worked once


def test_ui_port_validation(capsys):
    for bad in ("abc", "80", "70000", "-5"):
        assert run(capsys, "ui", "--no-browser", "--port", bad)[0] == 2


def test_serve_is_refused_inside_the_full_screen_console(capsys):
    from erinix.ui.theme import Theme

    out = []
    theme = Theme(0, True, 100)
    ctx = Context(theme, theme, type("W", (), {"write": lambda self, t: out.append(t) or len(t), "flush": lambda self: None})(),
                  type("W", (), {"write": lambda self, t: out.append(t) or len(t), "flush": lambda self: None})(), lambda r: None)
    assert store_cmds.cmd_serve(ctx, []) == 2 and "normal terminal" in "".join(out)


def test_stop_never_touches_a_process_that_is_not_ours(capsys, running_dashboard):
    code, _, err = run(capsys, "stop")                    # server.json points at this test process
    assert code == 1 and "not an Erinix dashboard" in err
    os.remove(__import__("erinix.history", fromlist=["state_dir"]).state_dir() / "server.json")
    assert "not running" in run(capsys, "stop")[1]


def test_untrusted_server_info_is_ignored(capsys, private_state):
    from erinix.history import state_dir

    state_dir().mkdir(parents=True, exist_ok=True)
    info = state_dir() / "server.json"
    info.write_text(json.dumps({"pid": 1, "port": 9}))
    info.chmod(0o644)
    assert store_cmds._read_server_info() is None
    info.chmod(0o600)
    info.write_text("not json")
    assert store_cmds._read_server_info() is None


# --------------------------------------------------------------- app install
def test_install_app_command(capsys, private_state):
    code, out, _ = run(capsys, "install-app")
    assert code == 0 and "installed as an app" in out
    launcher = private_state / "home" / ".local" / "bin" / "erinix"
    assert launcher.exists() and os.access(launcher, os.X_OK)
    assert run(capsys, "install-app", "--terminal", "nonexistent-term")[0] == 1
    assert run(capsys, "uninstall-app")[0] == 0 and not launcher.exists()


def test_a_long_run_of_digits_is_an_id_prefix_not_a_list_number(capsys, private_state):
    import ipaddress

    from erinix.engine.alerts import Alert
    from erinix.rules import Response, Severity

    with Store() as store:
        store.upsert_alert(Alert(alert_id="123456" + "a" * 26, revision=1, rule_id="r", kind="indicator", severity=Severity.HIGH,
                                 response=Response.REPORT_ONLY, steps_done=1, steps_total=1, step_id="r", complete=True, mitre=(),
                                 description="d", evidence=(), process=None, anchor=None, remote_addr=ipaddress.ip_address("10.0.0.1"),
                                 mono_ns=0, wall_ns=int(time.time() * 1e9), title="Numeric id"))
    code, out, _ = run(capsys, "alert", "123456", "--json")
    assert code == 0 and json.loads(out)["headline"] == "Numeric id"
    assert run(capsys, "alert", "1")[0] == 0                                           # and 1 is still the first alert
