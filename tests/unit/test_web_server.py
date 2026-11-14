import http.client
import json
import threading
import time
from urllib.parse import quote

import pytest

from erinix.engine.alerts import Alert
from erinix.rules import Response, Severity
from erinix.store import Store
from erinix.web import server as web
from erinix.web.server import COOKIE, DashboardServer

NOW = time.time()


def make_alert(aid="a" * 32, title="Bad thing from {remote}", severity=Severity.HIGH, remote="203.0.113.50", revision=1):
    import ipaddress
    return Alert(alert_id=aid, revision=revision, rule_id="web-sqli-attempt", kind="indicator", severity=severity,
                 response=Response.REPORT_ONLY, steps_done=1, steps_total=1, step_id="s", complete=True, mitre=("T1190",),
                 description="desc", evidence=(("s", ("e1",)),), process=None, anchor=None,
                 remote_addr=ipaddress.ip_address(remote), mono_ns=0, wall_ns=int(NOW * 1e9), title=title, why="Why {remote}",
                 next_steps=("Do this",))


@pytest.fixture()
def dash(tmp_path):
    db = tmp_path / "state" / "erinix.db"
    with Store(db) as s:
        s.upsert_alert(make_alert())
        s.set_meta("mode", "demo")
    server = DashboardServer(0, db)
    thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def call(server, method, path, *, headers=None, body=None, host="default", raw_host=False):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    h = dict(headers or {})
    if host == "default":
        host = f"127.0.0.1:{server.port}"
    if host is None:
        conn.putrequest(method, path, skip_host=True)
        for k, v in h.items():
            conn.putheader(k, v)
        if body is not None:
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
    else:
        conn.request(method, path, body=body, headers={"Host": host, **h})
    r = conn.getresponse()
    data = r.read()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, data


def login(server, token, **over):
    headers = {"Content-Type": "application/json", **over}
    return call(server, "POST", "/api/login", headers={k: v for k, v in headers.items() if v is not None},
                body=token if isinstance(token, bytes) else json.dumps({"token": token}).encode())


def sign_in(server):
    with Store(server.db_path) as s:
        token = s.create_login_token()
    status, headers, _ = login(server, token)
    assert status == 200
    cookie = headers["set-cookie"].split(";")[0]
    _, _, data = call(server, "GET", "/api/session", headers={"Cookie": cookie})
    return cookie, json.loads(data)["csrf"]


def post(server, path, cookie, csrf, payload, **over):
    headers = {"Cookie": cookie, "X-Erinix-CSRF": csrf, "Content-Type": "application/json"}
    headers.update(over)
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return call(server, "POST", path, headers={k: v for k, v in headers.items() if v is not None}, body=body)


# --------------------------------------------------------------- binding
@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "192.168.1.5", "8.8.8.8"])
def test_only_loopback_addresses_are_allowed(tmp_path, bind):
    with pytest.raises(ValueError, match="loopback"):
        DashboardServer(0, tmp_path / "x.db", bind=bind)


def test_it_listens_on_loopback(dash):
    assert dash.server_address[0] == "127.0.0.1"


# ----------------------------------------------------------- public pages
def test_the_page_is_public_with_strict_headers(dash):
    status, h, body = call(dash, "GET", "/")
    assert status == 200 and h["content-type"].startswith("text/html") and b"Erinix" in body
    csp = h["content-security-policy"]
    for part in ("default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "connect-src 'self'"):
        assert part in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "*" not in csp
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY" and h["referrer-policy"] == "no-referrer"
    assert h["cache-control"] == "no-store" and "python" not in h.get("server", "").lower()
    for path, kind in (("/static/app.js", "javascript"), ("/static/style.css", "css"), ("/static/logo.svg", "svg"), ("/static/hedgehog.svg", "svg"), ("/favicon.svg", "svg")):
        s, hh, b = call(dash, "GET", path)
        assert s == 200 and kind in hh["content-type"] and b


def test_healthz_and_unknown_paths(dash):
    assert call(dash, "GET", "/healthz")[0] == 200
    for path in ("/nope", "/static/secret.txt", "/static/", "/api", "/admin", "/favicon.ico"):
        assert call(dash, "GET", path)[0] in (404, 401)


@pytest.mark.parametrize("path", ["/static/../../etc/passwd", "/static/%2e%2e/%2e%2e/etc/passwd", "//etc/passwd", "/static/..%2fapp.js",
                                  "/static/app.js/../../../x", "/%00", "/static/app.js%00.png", "/." * 3])
def test_no_path_traversal(dash, path):
    status, _, body = call(dash, "GET", path)
    assert status in (400, 404) and b"root:" not in body


def test_overlong_requests_are_refused(dash):
    assert call(dash, "GET", "/" + "a" * 5000)[0] == 400


def test_methods_other_than_get_post_are_refused(dash):
    for m in ("PUT", "DELETE", "PATCH", "OPTIONS"):
        assert call(dash, m, "/")[0] == 405
    status, _, body = call(dash, "HEAD", "/")
    assert status == 200 and body == b""
    assert call(dash, "POST", "/")[0] == 405


# ---------------------------------------------------------- host checking
@pytest.mark.parametrize("host", ["evil.example.com", "evil.example.com:80", "127.0.0.1", "127.0.0.1:1", "localhost", "0.0.0.0:80", "", "127.0.0.1.evil.com:80"])
def test_wrong_host_headers_are_refused(dash, host):
    assert call(dash, "GET", "/", host=host)[0] == 400
    assert call(dash, "GET", "/api/overview", host=host)[0] == 400


def test_missing_host_is_refused_and_localhost_is_accepted(dash):
    assert call(dash, "GET", "/", host=None)[0] == 400
    assert call(dash, "GET", "/healthz", host=f"localhost:{dash.port}")[0] == 200


# -------------------------------------------------------------------- login
def test_api_needs_a_session(dash):
    for path in ("/api/overview", "/api/alerts", "/api/session", "/api/alerts/" + "a" * 32):
        assert call(dash, "GET", path)[0] == 401
    for cookie in (f"{COOKIE}=", f"{COOKIE}=forged", f"{COOKIE}=" + "x" * 500, "other=1", f"{COOKIE}='; DROP TABLE alerts"):
        assert call(dash, "GET", "/api/overview", headers={"Cookie": cookie})[0] == 401


def test_login_is_one_time_with_safe_cookie_flags(dash):
    with Store(dash.db_path) as s:
        token = s.create_login_token()
    status, h, body = login(dash, token)
    assert status == 200 and json.loads(body) == {"ok": True}
    cookie = h["set-cookie"]
    assert cookie.startswith(COOKIE + "=") and "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    assert token not in cookie and token not in body.decode()
    status, _, body = login(dash, token)                                          # a token works once
    assert status == 403 and json.loads(body) == {"error": "invalid"}


def test_opening_the_link_never_uses_the_token_up(dash):
    """The token travels in the address fragment: a browser opening or pre-loading the page cannot burn it."""
    with Store(dash.db_path) as s:
        token = s.create_login_token()
    for path in (f"/?t={token}", f"/#login={token}", f"/login?t={token}", "/"):
        call(dash, "GET", path)
    assert login(dash, token)[0] == 200


def test_the_old_get_login_address_is_gone(dash):
    with Store(dash.db_path) as s:
        token = s.create_login_token()
    assert call(dash, "GET", f"/login?t={token}")[0] == 404
    assert login(dash, token)[0] == 200                                           # and it did not touch the token


@pytest.mark.parametrize("token", ["", "abc", "a" * 300, None, 5, ["x"], {"a": 1}, "' OR '1'='1' --" + "a" * 10, "%00" * 12, "\x00" * 30])
def test_bad_login_attempts_are_refused(dash, token):
    status, _, body = login(dash, token)
    assert status == 403 and json.loads(body) == {"error": "invalid"}


@pytest.mark.parametrize("body,code", [(b"not json", 400), (b"[1]", 403), (b"{}", 403), (b"[" * 300 + b"]" * 300, 403)])
def test_login_input_validation(dash, body, code):
    assert login(dash, body)[0] == code


def test_login_needs_json_and_a_local_origin(dash):
    with Store(dash.db_path) as s:
        token = s.create_login_token()
    assert login(dash, token, **{"Content-Type": "text/plain"})[0] == 415
    assert login(dash, token, Origin="http://evil.example.com")[0] == 403
    assert login(dash, token, Origin="null")[0] == 403
    assert login(dash, b"{" + b" " * 3000 + b"}")[0] == 413
    assert login(dash, token, Origin=f"http://127.0.0.1:{dash.port}")[0] == 200   # still unused after all the refusals


def test_expired_links_say_so(dash):
    with Store(dash.db_path) as s:
        token = s.create_login_token(ttl=-1)
    status, _, body = login(dash, token)
    assert status == 403 and json.loads(body) == {"error": "expired"}


def test_repeated_failures_are_rate_limited(dash):
    codes = [login(dash, "z" * 30)[0] for _ in range(14)]
    assert codes[:10] == [403] * 10 and 429 in codes[10:]
    with Store(dash.db_path) as s:
        token = s.create_login_token()
    assert login(dash, token)[0] == 429                                           # even a good link waits


def test_unreadable_store_is_reported_as_unavailable(dash):
    dash.db_path.chmod(0o644)
    status, _, body = login(dash, "a" * 43)
    assert status == 503 and json.loads(body) == {"error": "unavailable"}
    assert "store could not be opened" in (dash.db_path.parent / "server.log").read_text()


def test_the_server_log_never_contains_secrets(dash):
    with Store(dash.db_path) as s:
        token = s.create_login_token()
    login(dash, token)
    login(dash, token)
    log = (dash.db_path.parent / "server.log").read_text()
    assert "login ok" in log and "login refused: invalid" in log and token not in log
    assert oct((dash.db_path.parent / "server.log").stat().st_mode & 0o777) == "0o600"


def test_sessions_expire_and_are_limited(dash):
    sid, csrf = dash.new_session(now=1000)
    assert dash.session_csrf(sid, now=1000 + 60) == csrf
    assert dash.session_csrf(sid, now=1000 + web.SESSION_TTL + 1) is None
    for _ in range(web.MAX_SESSIONS + 5):
        dash.new_session()
    assert len(dash.sessions) <= web.MAX_SESSIONS
    assert dash.session_csrf(None) is None and dash.session_csrf("x" * 200) is None


# ---------------------------------------------------------------------- API
def test_overview_alerts_and_detail(dash):
    cookie, _ = sign_in(dash)
    s, h, body = call(dash, "GET", "/api/overview", headers={"Cookie": cookie})
    o = json.loads(body)
    assert s == 200 and h["content-type"].startswith("application/json") and o["state"] == "attention" and o["demo"] is True
    assert o["attention"][0]["headline"] == "Bad thing from 203.0.113.50"
    _, _, body = call(dash, "GET", "/api/alerts?status=all&limit=10", headers={"Cookie": cookie})
    rows = json.loads(body)["alerts"]
    assert len(rows) == 1 and rows[0]["next_steps"] == ["Do this"] and rows[0]["technical"]["rule"] == "web-sqli-attempt"
    _, _, body = call(dash, "GET", "/api/alerts/" + "a" * 32, headers={"Cookie": cookie})
    assert json.loads(body)["remote"] == "203.0.113.50"


@pytest.mark.parametrize("path,code", [("/api/alerts?status=evil", 400), ("/api/alerts?limit=abc", 400), ("/api/alerts?status=open%27", 400),
                                       ("/api/alerts/" + "f" * 32, 404), ("/api/alerts/' OR 1=1 --", 404), ("/api/unknown", 404)])
def test_bad_api_requests(dash, path, code):
    cookie, _ = sign_in(dash)
    assert call(dash, "GET", quote(path, safe="/?=&"), headers={"Cookie": cookie})[0] == code


def test_hostile_alert_text_is_data_not_markup(dash):
    evil = "</script><img src=x onerror=alert(1)>" + "\u202e\x1b[31m"
    with Store(dash.db_path) as s:
        s.upsert_alert(make_alert("b" * 32, title=evil))
    cookie, _ = sign_in(dash)
    status, h, body = call(dash, "GET", "/api/alerts", headers={"Cookie": cookie})
    assert h["content-type"].startswith("application/json") and h["x-content-type-options"] == "nosniff"
    assert evil in [a["headline"] for a in json.loads(body)["alerts"]]
    assert all(b < 128 for b in body)                                            # pure ASCII JSON


def test_missing_store_gives_empty_data_not_errors(tmp_path):
    server = DashboardServer(0, tmp_path / "none" / "erinix.db")
    threading.Thread(target=lambda: server.serve_forever(poll_interval=0.02), daemon=True).start()
    try:
        sid, _ = server.new_session()
        h = {"Cookie": f"{COOKIE}={sid}"}
        o = json.loads(call(server, "GET", "/api/overview", headers=h)[2])
        assert o["state"] == "stopped" and json.loads(call(server, "GET", "/api/alerts", headers=h)[2]) == {"alerts": []}
    finally:
        server.shutdown()
        server.server_close()


# ------------------------------------------------------------------- changes
def test_dismiss_and_reopen(dash):
    cookie, csrf = sign_in(dash)
    s, _, _ = post(dash, "/api/alerts/" + "a" * 32 + "/status", cookie, csrf, {"status": "dismissed"})
    assert s == 200
    rows = json.loads(call(dash, "GET", "/api/alerts?status=open", headers={"Cookie": cookie})[2])["alerts"]
    assert rows == []
    assert post(dash, "/api/alerts/" + "a" * 32 + "/status", cookie, csrf, {"status": "open"})[0] == 200
    assert len(json.loads(call(dash, "GET", "/api/alerts?status=open", headers={"Cookie": cookie})[2])["alerts"]) == 1


def test_changes_need_session_csrf_and_a_matching_origin(dash):
    cookie, csrf = sign_in(dash)
    path = "/api/alerts/" + "a" * 32 + "/status"
    body = {"status": "dismissed"}
    assert post(dash, path, "", csrf, body)[0] == 401
    assert post(dash, path, cookie, "", body)[0] == 403
    assert post(dash, path, cookie, "wrong-token", body)[0] == 403
    assert post(dash, path, cookie, csrf, body, **{"X-Erinix-CSRF": None})[0] == 403
    assert post(dash, path, cookie, csrf, body, Origin="http://evil.example.com")[0] == 403
    assert post(dash, path, cookie, csrf, body, Origin="null")[0] == 403
    assert post(dash, path, cookie, csrf, body, Origin=f"http://127.0.0.1:{dash.port}")[0] == 200
    other_cookie, other_csrf = sign_in(dash)
    assert post(dash, path, cookie, other_csrf, body)[0] == 403                     # another session's token is no good


def test_post_input_validation(dash):
    cookie, csrf = sign_in(dash)
    path = "/api/alerts/" + "a" * 32 + "/status"
    assert post(dash, path, cookie, csrf, {"status": "deleted"})[0] == 400
    assert post(dash, path, cookie, csrf, {"status": ["open"]})[0] == 400
    assert post(dash, path, cookie, csrf, {"status": {"$ne": 1}})[0] == 400
    assert post(dash, path, cookie, csrf, [1, 2])[0] == 400
    assert post(dash, path, cookie, csrf, b"not json")[0] == 400
    assert post(dash, path, cookie, csrf, b"[" * 300 + b"]" * 300)[0] == 400
    assert post(dash, path, cookie, csrf, b"{" + b" " * 2000 + b"}")[0] == 413
    assert post(dash, path, cookie, csrf, {"status": "open"}, **{"Content-Type": "text/plain"})[0] == 415
    assert post(dash, "/api/alerts/" + "f" * 32 + "/status", cookie, csrf, {"status": "open"})[0] == 404
    assert post(dash, "/api/alerts/x/delete", cookie, csrf, {"status": "open"})[0] == 404
    assert post(dash, "/api/overview", cookie, csrf, {"status": "open"})[0] == 404
    assert len(json.loads(call(dash, "GET", "/api/alerts?status=all", headers={"Cookie": cookie})[2])["alerts"]) == 1


def test_nothing_is_printed(dash, capsys):
    with Store(dash.db_path) as s:
        token = s.create_login_token()
    login(dash, token)
    out = capsys.readouterr()
    assert token not in out.out + out.err


def test_server_info_file_is_private(tmp_path, monkeypatch):
    import os
    import stat

    monkeypatch.setattr("erinix.history._running_as_root", lambda: False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    seen = {}

    def ready(server):
        seen["info"] = web.server_info_path().read_text()
        seen["mode"] = stat.S_IMODE(os.stat(web.server_info_path()).st_mode)
        threading.Timer(0.2, server.shutdown).start()

    web.serve(0, tmp_path / "erinix.db", ready=ready)
    assert json.loads(seen["info"])["port"] > 0 and seen["mode"] == 0o600
    assert not web.server_info_path().exists()                                      # removed on exit


# ------------------------------------------------------------ live events
def seed_events(server, n=5):
    with Store(server.db_path) as s:
        for i in range(n):
            s.add_event(event_id=f"ev{i}", ts=NOW + i, kind="web.request", label="Web request", summary=f"GET /{i} → 200", remote="10.0.0.1", source="log")
        s.link_events(["ev3"], "a" * 32, "step", "high")


def get_json(server, path, cookie):
    status, h, body = call(server, "GET", path, headers={"Cookie": cookie})
    return status, (json.loads(body) if body else None), h


def test_events_need_a_session(dash):
    seed_events(dash)
    assert call(dash, "GET", "/api/events")[0] == 401
    assert call(dash, "GET", "/api/events", headers={"Cookie": f"{COOKIE}=forged"})[0] == 401


def test_events_first_call_gives_the_latest_then_only_newer(dash):
    cookie, _ = sign_in(dash)
    status, data, _ = get_json(dash, "/api/events", cookie)
    assert status == 200 and data == {"events": [], "last_id": 0}
    seed_events(dash)
    _, data, _ = get_json(dash, "/api/events?limit=3", cookie)
    assert [e["summary"] for e in data["events"]] == ["GET /2 → 200", "GET /3 → 200", "GET /4 → 200"] and data["last_id"] == data["events"][-1]["id"]
    last = data["last_id"]
    assert get_json(dash, f"/api/events?after={last}", cookie)[1] == {"events": [], "last_id": last}
    with Store(dash.db_path) as s:
        s.add_event(event_id="new", ts=NOW + 99, kind="auth.failure", label="Login failed", summary="root via sshd", remote="1.2.3.4")
    _, data, _ = get_json(dash, f"/api/events?after={last}", cookie)
    assert [e["label"] for e in data["events"]] == ["Login failed"] and data["last_id"] == last + 1


def test_events_carry_the_attack_link_and_can_be_filtered(dash):
    seed_events(dash)
    cookie, _ = sign_in(dash)
    _, data, _ = get_json(dash, "/api/events?after=0", cookie)
    flagged = [e for e in data["events"] if e["alert"]]
    assert len(data["events"]) == 5 and len(flagged) == 1 and flagged[0]["severity"] == "high" and flagged[0]["step"] == "step"
    _, only, _ = get_json(dash, "/api/events?after=0&suspicious=1", cookie)
    assert [e["alert"] for e in only["events"]] == ["a" * 32]


@pytest.mark.parametrize("query", ["after=abc", "after=-1", "after=1.5", "limit=abc", "suspicious=2", "suspicious=yes", "after=" + "9" * 400,
                                   "after=1;DROP%20TABLE%20events", "limit=%00"])
def test_bad_event_requests_are_refused_cleanly(dash, query):
    seed_events(dash)
    cookie, _ = sign_in(dash)
    status, data, _ = get_json(dash, "/api/events?" + query, cookie)
    assert status == 400 and "error" in data
    assert len(get_json(dash, "/api/events?after=0", cookie)[1]["events"]) == 5                   # nothing was damaged


def test_event_limits_are_clamped(dash):
    seed_events(dash, 12)
    cookie, _ = sign_in(dash)
    assert len(get_json(dash, "/api/events?after=0&limit=0", cookie)[1]["events"]) == 1
    assert len(get_json(dash, "/api/events?after=0&limit=999999", cookie)[1]["events"]) == 12


def test_hostile_event_text_is_data_not_markup(dash):
    evil = "</script><img src=x onerror=alert(1)>\u202e\x1b[31m"
    with Store(dash.db_path) as s:
        s.add_event(event_id="x", ts=NOW, kind="web.request", label=evil, summary=evil, remote=None)
    cookie, _ = sign_in(dash)
    status, h, body = call(dash, "GET", "/api/events", headers={"Cookie": cookie})
    assert h["content-type"].startswith("application/json") and h["x-content-type-options"] == "nosniff" and all(b < 128 for b in body)
    assert json.loads(body)["events"][0]["summary"] == evil


def test_events_cannot_be_written_through_the_api(dash):
    cookie, csrf = sign_in(dash)
    assert post(dash, "/api/events", cookie, csrf, {"summary": "x"})[0] == 404
    assert call(dash, "POST", "/api/events", headers={"Cookie": cookie, "X-Erinix-CSRF": csrf, "Content-Type": "application/json"}, body=b"{}")[0] == 404


def test_alerts_come_with_their_steps_and_timeline(dash):
    from pathlib import Path

    from erinix.demo.scenarios import SCENARIOS
    from erinix.engine import Correlator
    from erinix.recorder import Recorder
    from erinix.rules import load_rules

    with Store(dash.db_path) as s:
        rec = Recorder(s, Correlator(load_rules(Path(__file__).resolve().parents[2] / "rules")))
        for e in sorted(SCENARIOS["revshell"].build(), key=lambda e: e.mono_ns):
            rec.feed(e)
    cookie, _ = sign_in(dash)
    chain = next(a for a in get_json(dash, "/api/alerts?status=all", cookie)[1]["alerts"] if a["technical"]["kind"] == "chain")
    assert [s["state"] for s in chain["steps"]] == ["done", "done", "done"] and chain["steps"][1]["detail"] == "bash → 10.0.0.5:4444"
    assert len(chain["timeline"]) == 3
    detail = get_json(dash, "/api/alerts/" + chain["id"], cookie)[1]
    assert detail["steps"] == chain["steps"]
    overview = get_json(dash, "/api/overview", cookie)[1]
    assert overview["attention"][0]["steps"] and "events_24h" in overview


# ------------------------------------------------- incidents, settings, palettes
def seed_attacks(server):
    from pathlib import Path

    from erinix.demo import live as live_demo
    from erinix.engine import Correlator
    from erinix.recorder import Recorder
    from erinix.rules import load_rules

    with Store(server.db_path) as s:
        rec = Recorder(s, Correlator(load_rules(Path(__file__).resolve().parents[2] / "rules")))
        for _, event in live_demo.story():
            rec.feed(live_demo.stamp(event))


def test_palette_stylesheet_is_served_and_complete(dash):
    from erinix import palettes

    status, h, body = call(dash, "GET", "/static/palettes.css")
    assert status == 200 and h["content-type"].startswith("text/css") and body.decode() == palettes.css()
    assert b"@import" not in body and b"url(" not in body


def test_overview_carries_incidents_and_the_palette_choice(dash):
    seed_attacks(dash)
    cookie, _ = sign_in(dash)
    o = get_json(dash, "/api/overview", cookie)[1]
    assert o["incidents"]["open"] >= 4 and len(o["incidents"]["top"]) == 3 and o["palette"] == "cacao" and len(o["palettes"]) == 7
    assert o["incidents"]["top"][0]["severity"] == "critical" and o["incidents"]["top"][0]["tags"]


def test_incidents_api(dash):
    seed_attacks(dash)
    assert call(dash, "GET", "/api/incidents")[0] == 401 and call(dash, "GET", "/api/incidents/i123")[0] == 401
    cookie, _ = sign_in(dash)
    _, data, _ = get_json(dash, "/api/incidents?status=open", cookie)
    big = next(i for i in data["incidents"] if i["who"] == "192.168.50.31")
    assert big["alert_count"] >= 5 and "alerts" not in big                                  # the list is light
    _, detail, _ = get_json(dash, "/api/incidents/" + big["id"], cookie)
    assert len(detail["alerts"]) == big["alert_count"] and detail["timeline"] and detail["next_steps"] and detail["alerts"][0]["steps"] is not None
    assert get_json(dash, "/api/incidents?status=closed", cookie)[1] == {"incidents": []}
    for bad in ("?status=evil", "?status=OPEN", "?status=closed;x"):
        assert call(dash, "GET", "/api/incidents" + bad, headers={"Cookie": cookie})[0] == 400


@pytest.mark.parametrize("path", ["/api/incidents/inope", "/api/incidents/" + "a" * 500, "/api/incidents/..%2f..%2fetc", "/api/incidents/%27%20OR%201%3D1%20--",
                                  "/api/incidents/%00", "/api/incidents/"])
def test_unknown_or_hostile_incident_ids(dash, path):
    seed_attacks(dash)
    cookie, _ = sign_in(dash)
    assert call(dash, "GET", path, headers={"Cookie": cookie})[0] == 404
    assert len(get_json(dash, "/api/incidents", cookie)[1]["incidents"]) >= 4              # nothing was damaged


def test_closing_and_reopening_an_incident_through_the_api(dash):
    seed_attacks(dash)
    cookie, csrf = sign_in(dash)
    big = next(i for i in get_json(dash, "/api/incidents", cookie)[1]["incidents"] if i["who"] == "192.168.50.31")
    path = f"/api/incidents/{big['id']}/status"
    status, _, body = post(dash, path, cookie, csrf, {"status": "closed"})
    assert status == 200 and json.loads(body)["changed"] == big["alert_count"]
    assert all(i["who"] != "192.168.50.31" for i in get_json(dash, "/api/incidents", cookie)[1]["incidents"])
    assert get_json(dash, "/api/incidents?status=closed", cookie)[1]["incidents"][0]["who"] == "192.168.50.31"
    assert post(dash, path, cookie, csrf, {"status": "open"})[0] == 200
    assert any(i["who"] == "192.168.50.31" for i in get_json(dash, "/api/incidents", cookie)[1]["incidents"])
    assert post(dash, path, cookie, csrf, {"status": "open"})[0] == 200                      # already open: still fine, changes nothing


def test_incident_changes_need_the_same_protections_and_valid_input(dash):
    seed_attacks(dash)
    cookie, csrf = sign_in(dash)
    iid = get_json(dash, "/api/incidents", cookie)[1]["incidents"][0]["id"]
    path = f"/api/incidents/{iid}/status"
    assert post(dash, path, "", csrf, {"status": "closed"})[0] == 401
    assert post(dash, path, cookie, "", {"status": "closed"})[0] == 403
    assert post(dash, path, cookie, csrf, {"status": "closed"}, Origin="http://evil.example.com")[0] == 403
    for bad in ({"status": "dismissed"}, {"status": ["closed"]}, {"status": None}, {}, [1], b"nope"):
        assert post(dash, path, cookie, csrf, bad)[0] == 400
    assert post(dash, "/api/incidents/inope/status", cookie, csrf, {"status": "closed"})[0] == 404
    assert post(dash, "/api/incidents/%27%3B%20--/status", cookie, csrf, {"status": "closed"})[0] == 404
    assert call(dash, "POST", f"/api/incidents/{iid}/status", headers={"Cookie": cookie, "X-Erinix-CSRF": csrf, "Content-Type": "text/plain"}, body=b"x")[0] == 415
    assert all(i["status"] == "open" for i in get_json(dash, "/api/incidents", cookie)[1]["incidents"])


def test_choosing_a_palette(dash):
    cookie, csrf = sign_in(dash)
    status, _, _ = post(dash, "/api/settings", cookie, csrf, {"palette": "nebbia"})
    assert status == 200
    assert get_json(dash, "/api/overview", cookie)[1]["palette"] == "nebbia"
    with Store(dash.db_path, readonly=True) as s:
        assert s.get_meta("palette") == "nebbia"                                            # the console reads the same setting


@pytest.mark.parametrize("body", [{"palette": "nope"}, {"palette": "cacao\"; } body { display:none"}, {"palette": ["cacao"]}, {"palette": None},
                                  {"palette": "cacao", "other": 1}, {"theme": "cacao"}, {}, ["cacao"], "cacao", b"not json", {"palette": "../cacao"},
                                  {"palette": "CACAO"}, {"palette": "a" * 400}])
def test_bad_palette_requests_change_nothing(dash, body):
    cookie, csrf = sign_in(dash)
    assert post(dash, "/api/settings", cookie, csrf, body)[0] == 400
    assert get_json(dash, "/api/overview", cookie)[1]["palette"] == "cacao"


def test_settings_need_a_session_csrf_and_a_local_origin(dash):
    cookie, csrf = sign_in(dash)
    assert post(dash, "/api/settings", "", csrf, {"palette": "latte"})[0] == 401
    assert post(dash, "/api/settings", cookie, "", {"palette": "latte"})[0] == 403
    assert post(dash, "/api/settings", cookie, csrf, {"palette": "latte"}, Origin="http://evil.example.com")[0] == 403
    assert call(dash, "GET", "/api/settings", headers={"Cookie": cookie})[0] == 404
    assert get_json(dash, "/api/overview", cookie)[1]["palette"] == "cacao"


def test_events_know_their_attack_type_and_incident(dash):
    seed_attacks(dash)
    cookie, _ = sign_in(dash)
    incidents = {i["id"] for i in get_json(dash, "/api/incidents?status=all", cookie)[1]["incidents"]}
    events = get_json(dash, "/api/events?after=0&limit=500", cookie)[1]["events"]
    flagged = [e for e in events if e["alert"]]
    assert flagged and all(e["tag"] and e["incident"] in incidents for e in flagged)
    plain = [e for e in events if not e["alert"]]
    assert plain and all(e["incident"] is None and e["tag"] == "" for e in plain)
