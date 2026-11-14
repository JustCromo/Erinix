"""The dashboard server.

Security model (see SECURITY.md)
- Binds to loopback only; any other address is refused.
- The page itself is public; ALL data needs a session. A session starts from a one-time,
  short-lived link created by `erinix ui` (the token is stored hashed and works once).
- Every request must carry a Host header for this server (defeats DNS rebinding).
- Changing anything (POST) needs the session cookie, a CSRF header and a matching Origin.
- Strict headers: no inline script or style, nothing loaded from other sites, no framing.
- Request sizes are small and bounded; errors never reveal internals; nothing is logged
  (URLs can carry login tokens).
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import signal
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from erinix import __version__, assets, palettes
from erinix.incidents import build_incidents, incident_detail, incident_id, set_incident_status
from erinix.history import state_dir
from erinix.store import STATUSES, Store, StoreError, default_db_path
from erinix.summary import build_overview, empty_overview, humanize_full

DEFAULT_PORT = 8421
SESSION_TTL = 8 * 3600
MAX_SESSIONS = 20
MAX_PATH = 2048
MAX_BODY = 1024
LOGIN_FAILURES = 10          # failed logins allowed per minute
COOKIE = "erinix_session"
STATIC_FILES = ("style.css", "app.js")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def server_info_path() -> Path:
    return state_dir() / "server.json"


def build_id() -> str:
    """A short fingerprint of the dashboard code and pages. A server started from older code has another one,
    so `erinix ui` can tell it must be replaced instead of reusing it."""
    digest = hashlib.sha256()
    root = resources.files("erinix.web").joinpath("static")
    for name in ("index.html", "app.js", "style.css", "icons.svg"):
        digest.update(root.joinpath(name).read_bytes())
    digest.update(Path(__file__).read_bytes())
    digest.update(palettes.css().encode("utf-8"))
    return digest.hexdigest()[:12]


def _load_static() -> dict[str, tuple[bytes, str]]:
    root = resources.files("erinix.web").joinpath("static")
    files = {
        "/": (root.joinpath("index.html").read_bytes(), "text/html; charset=utf-8"),
        "/static/style.css": (root.joinpath("style.css").read_bytes(), "text/css; charset=utf-8"),
        "/static/app.js": (root.joinpath("app.js").read_bytes(), "text/javascript; charset=utf-8"),
        "/static/icons.svg": (root.joinpath("icons.svg").read_bytes(), "image/svg+xml"),
        "/static/fonts/nunito-latin.woff2": (root.joinpath("fonts").joinpath("nunito-latin.woff2").read_bytes(), "font/woff2"),
    }
    svg = assets.logo_svg().encode("utf-8")
    files["/static/palettes.css"] = (palettes.css().encode("utf-8"), "text/css; charset=utf-8")
    files["/static/logo.svg"] = (svg, "image/svg+xml")
    files["/static/hedgehog.svg"] = (assets.hedgehog_svg().encode("utf-8"), "image/svg+xml")
    files["/favicon.svg"] = (svg, "image/svg+xml")
    return files


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int = DEFAULT_PORT, db_path: Path | str | None = None, *, bind: str = "127.0.0.1") -> None:
        if not ipaddress.ip_address(bind).is_loopback:
            raise ValueError("the dashboard only listens on loopback addresses")
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self.static = _load_static()
        self.build = build_id()
        self.sessions: dict[str, tuple[float, str]] = {}      # sha256(session id) -> (expires, csrf token)
        self.lock = threading.Lock()
        self.failures: list[float] = []
        super().__init__((bind, port), _Handler)
        self.port = self.server_address[1]
        self.allowed_hosts = {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"}
        self.allowed_origins = {f"http://{h}" for h in self.allowed_hosts}

    # ---------------------------------------------------------------- sessions
    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()

    def new_session(self, now: float | None = None) -> tuple[str, str]:
        now = time.time() if now is None else now
        sid, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        with self.lock:
            self.sessions = {k: v for k, v in self.sessions.items() if v[0] > now}
            while len(self.sessions) >= MAX_SESSIONS:
                self.sessions.pop(min(self.sessions, key=lambda k: self.sessions[k][0]))
            self.sessions[self._digest(sid)] = (now + SESSION_TTL, csrf)
        return sid, csrf

    def session_csrf(self, sid: str | None, now: float | None = None) -> str | None:
        if not sid or len(sid) > 100:
            return None
        now = time.time() if now is None else now
        with self.lock:
            entry = self.sessions.get(self._digest(sid))
        return entry[1] if entry and entry[0] > now else None

    def too_many_failures(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self.lock:
            self.failures = [t for t in self.failures if now - t < 60]
            return len(self.failures) >= LOGIN_FAILURES

    def note(self, message: str) -> None:
        """One line in server.log (private file). Never carries tokens, addresses or alert text."""
        path = self.db_path.parent / "server.log"
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            flags |= os.O_TRUNC if path.exists() and path.stat().st_size > 65536 else os.O_APPEND
            fd = os.open(path, flags, 0o600)
            try:
                os.write(fd, f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n".encode())
            finally:
                os.close(fd)
        except OSError:
            pass

    def note_failure(self, now: float | None = None) -> None:
        with self.lock:
            self.failures.append(time.time() if now is None else now)


class _Handler(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "Erinix"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def log_message(self, *args: object) -> None:       # never log: URLs may contain login tokens
        pass

    # ------------------------------------------------------------------ output
    def _send(self, status: int, body: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        for key, value in {**HEADERS, **(extra or {})}.items():
            self.send_header(key, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode("ascii"), "application/json; charset=utf-8")

    def _error(self, status: int, message: str | None = None) -> None:
        text = message or HTTPStatus(status).phrase
        if self.path.startswith("/api/"):
            self._json(status, {"error": text})
        else:
            self._send(status, text.encode("utf-8"), "text/plain; charset=utf-8")

    # ------------------------------------------------------------------ checks
    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _session_id(self) -> str | None:
        for part in self.headers.get("Cookie", "")[:1024].split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return value
        return None

    def _csrf(self) -> str | None:
        return self.server.session_csrf(self._session_id())

    # ------------------------------------------------------------------ routing
    def _route(self) -> None:
        if len(self.path) > MAX_PATH or not self.path.startswith("/"):
            return self._error(400)
        if not self._host_ok():
            return self._error(400, "Bad request")
        url = urlsplit(self.path)
        path, query = url.path, parse_qs(url.query, max_num_fields=8)
        if self.command in ("GET", "HEAD"):
            if path in self.server.static:
                body, kind = self.server.static[path]
                return self._send(200, body, kind)
            if path == "/healthz":
                return self._send(200, b"ok " + self.server.build.encode(), "text/plain; charset=utf-8")
            if path.startswith("/api/"):
                return self._api_get(path, query)
            return self._error(404)
        if self.command == "POST" and path == "/api/login":
            return self._login()
        if self.command == "POST" and path.startswith("/api/"):
            return self._api_post(path)
        self._error(405)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _route

    def _read_json(self) -> object | None:
        """The JSON body of a POST, or None after an error answer has been sent."""
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self._error(415)
            return None
        if self.headers.get("Transfer-Encoding"):
            self._error(400)
            return None
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BODY:
            self._error(413 if length > MAX_BODY else 400)
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (ValueError, RecursionError):
            self._error(400, "Invalid JSON")
            return None

    def _login(self) -> None:
        """Sign in with the one-time token. The page (not the address) sends it, so merely
        opening a link twice, or a browser pre-loading it, can never use the token up."""
        if self.server.too_many_failures():
            return self._error(429, "Too many attempts. Try again in a minute.")
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.allowed_origins:
            return self._error(403, "Request refused")
        body = self._read_json()
        if body is None:
            return
        token = body.get("token") if isinstance(body, dict) else None
        try:
            with Store(self.server.db_path) as store:
                outcome = store.redeem_login_token(token)
        except StoreError:
            self.server.note("login: the store could not be opened")
            return self._json(503, {"error": "unavailable"})
        if outcome != "ok":
            self.server.note_failure()
            self.server.note(f"login refused: {outcome}")
            return self._json(403, {"error": outcome})
        sid, _ = self.server.new_session()
        self.server.note("login ok")
        cookie = f"{COOKIE}={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_TTL}"
        self._send(200, b'{"ok": true}', "application/json; charset=utf-8", {"Set-Cookie": cookie})

    # --------------------------------------------------------------------- API
    def _open(self, *, write: bool = False) -> Store | None:
        try:
            return Store(self.server.db_path, readonly=not write)
        except StoreError:
            return None

    def _api_get(self, path: str, query: dict[str, list[str]]) -> None:
        csrf = self._csrf()
        if csrf is None:
            return self._error(401, "Sign in with: erinix ui")
        if path == "/api/session":
            return self._json(200, {"csrf": csrf, "version": __version__})
        store = self._open()
        try:
            if path == "/api/overview":
                if store is None:
                    return self._json(200, empty_overview())
                return self._json(200, build_overview(store))
            if path == "/api/alerts":
                status = (query.get("status") or ["open"])[0]
                if status not in (*STATUSES, "all"):
                    return self._error(400, "Unknown status")
                try:
                    limit = int((query.get("limit") or ["50"])[0])
                except ValueError:
                    return self._error(400, "Invalid limit")
                rows = [] if store is None else store.list_alerts(status, limit=limit)
                return self._json(200, {"alerts": [humanize_full(store, r) for r in rows]})
            if path.startswith("/api/alerts/"):
                row = None if store is None else store.get_alert(path[len("/api/alerts/"):])
                return self._json(200, humanize_full(store, row)) if row else self._error(404)
            if path == "/api/events":
                return self._events(store, query)
            if path == "/api/incidents":
                status = (query.get("status") or ["open"])[0]
                if status not in ("open", "closed", "all"):
                    return self._error(400, "Unknown status")
                return self._json(200, {"incidents": [] if store is None else build_incidents(store, status)})
            if path.startswith("/api/incidents/"):
                data = None if store is None else incident_detail(store, path[len("/api/incidents/"):])
                return self._json(200, data) if data else self._error(404)
            return self._error(404)
        finally:
            if store is not None:
                store.close()

    def _settings(self) -> None:
        """The one setting for now: light, dark or automatic, shared with the console."""
        body = self._read_json()
        if body is None:
            return
        name = body.get("theme") if isinstance(body, dict) and set(body) == {"theme"} else None
        if not palettes.is_known(name):
            return self._error(400, "Unknown appearance")
        store = self._open(write=True)
        if store is None:
            return self._error(404)
        with store:
            store.set_meta("theme", name)
        self._json(200, {"ok": True})

    def _incident_status(self, wanted: str) -> None:
        body = self._read_json()
        if body is None:
            return
        status = body.get("status") if isinstance(body, dict) else None
        if status not in ("open", "closed"):
            return self._error(400, "Unknown status")
        store = self._open(write=True)
        if store is None:
            return self._error(404)
        with store:
            changed = set_incident_status(store, wanted, status)
            found = changed or any(i["id"] == wanted for i in build_incidents(store, "all"))
        return self._json(200, {"ok": True, "changed": changed}) if found else self._error(404)

    def _events(self, store: Store | None, query: dict[str, list[str]]) -> None:
        """The live stream: events newer than `after`, or the latest ones on the first call."""
        try:
            after = None if "after" not in query else int(query["after"][0])
            limit = int((query.get("limit") or ["100"])[0])
        except ValueError:
            return self._error(400, "Invalid number")
        if (after is not None and not 0 <= after < 2**62) or not -(2**62) < limit < 2**62 \
                or (query.get("suspicious") or ["0"])[0] not in ("0", "1"):
            return self._error(400, "Invalid request")
        if store is None:
            return self._json(200, {"events": [], "last_id": 0})
        rows = store.list_events(after=after, limit=limit, suspicious_only=(query.get("suspicious") or ["0"])[0] == "1")
        events = [{"id": r["id"], "time": r["ts"], "kind": r["kind"], "label": r["label"], "summary": r["summary"], "remote": r["remote"],
                   "alert": r["alert_id"], "step": r["step"], "severity": r["severity"], "tag": r["tag"] or "",
                   "incident": incident_id("ip:" + r["alert_remote"] if r["alert_remote"] else "local") if r["alert_id"] else None}
                  for r in rows]
        return self._json(200, {"events": events, "last_id": store.last_event_id()})

    def _api_post(self, path: str) -> None:
        csrf = self._csrf()
        if csrf is None:
            return self._error(401, "Sign in with: erinix ui")
        sent = self.headers.get("X-Erinix-CSRF", "")
        origin = self.headers.get("Origin")
        if not hmac.compare_digest(sent.encode("utf-8", "replace"), csrf.encode("utf-8")) or \
                (origin is not None and origin not in self.server.allowed_origins):
            return self._error(403, "Request refused")
        if path == "/api/settings":
            return self._settings()
        if path.startswith("/api/incidents/") and path.endswith("/status"):
            return self._incident_status(path[len("/api/incidents/"):-len("/status")])
        prefix, suffix = "/api/alerts/", "/status"
        if not (path.startswith(prefix) and path.endswith(suffix)):
            return self._error(404)
        alert_id = path[len(prefix):-len(suffix)]
        body = self._read_json()
        if body is None:
            return
        status = body.get("status") if isinstance(body, dict) else None
        if status not in STATUSES:
            return self._error(400, "Unknown status")
        store = self._open(write=True)
        if store is None:
            return self._error(404)
        with store:
            changed = store.set_alert_status(alert_id, status)
        return self._json(200, {"ok": True}) if changed else self._error(404)


def serve(port: int = DEFAULT_PORT, db_path: Path | str | None = None, *, ready=None) -> None:
    """Run the dashboard until stopped (Ctrl-C or SIGTERM)."""
    server = DashboardServer(port, db_path)
    info = server_info_path()
    os.makedirs(info.parent, mode=0o700, exist_ok=True)
    fd = os.open(info, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump({"pid": os.getpid(), "port": server.port, "started": time.time(), "build": server.build}, handle)
    stopper = threading.Thread(target=server.shutdown, daemon=True)
    signal.signal(signal.SIGTERM, lambda *_: stopper.start())
    if ready:
        ready(server)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        try:
            info.unlink()
        except OSError:
            pass
