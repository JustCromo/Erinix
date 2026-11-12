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


def sign_in(server):
    with Store(server.db_path) as s:
        token = s.create_login_token()
    status, headers, _ = call(server, "GET", f"/login?t={token}")
    assert status == 303 and headers["location"] == "/"
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
    for path, kind in (("/static/app.js", "javascript"), ("/static/style.css", "css"), ("/static/logo.svg", "svg"), ("/favicon.svg", "svg")):
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
    status, h, _ = call(dash, "GET", f"/login?t={token}")
    assert status == 303 and h["location"] == "/"
    cookie = h["set-cookie"]
    assert cookie.startswith(COOKIE + "=") and "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    assert call(dash, "GET", f"/login?t={token}")[0] == 403                     # a link works once
    assert token not in cookie and "t=" not in h["location"]


@pytest.mark.parametrize("query", ["", "?t=", "?t=abc", "?t=" + "a" * 300, "?token=x", "?t=%00", "?t=' OR 1=1 --", "?t=a&t=b"])
def test_bad_login_attempts_are_refused(dash, query):
    assert call(dash, "GET", "/login" + quote(query, safe="?=&"))[0] in (403, 429)


def test_expired_links_do_not_work(dash):
    with Store(dash.db_path) as s:
        token = s.create_login_token(ttl=-1)
    assert call(dash, "GET", f"/login?t={token}")[0] == 403


def test_repeated_failures_are_rate_limited(dash):
    codes = [call(dash, "GET", "/login?t=" + "z" * 30)[0] for _ in range(14)]
    assert codes[:10] == [403] * 10 and 429 in codes[10:]
    with Store(dash.db_path) as s:
        token = s.create_login_token()
    assert call(dash, "GET", f"/login?t={token}")[0] == 429                      # even a good link waits


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


def test_nothing_is_logged(dash, capsys):
    with Store(dash.db_path) as s:
        token = s.create_login_token()
    call(dash, "GET", f"/login?t={token}")
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
