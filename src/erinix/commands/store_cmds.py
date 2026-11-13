"""Commands that show what Erinix found: status, alerts, sources, the dashboard, demo data.

All of them read the same store as the dashboard, so every screen tells the same story.
Every command that prints information also has --json, for scripts and desktop widgets.
"""

from __future__ import annotations

import dataclasses
import http.client
import json
import math
import os
import re
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

from erinix.browser import open_url
from erinix.commands.registry import Context, UsageError, parse_args
from erinix.rules import Severity
from erinix.store import Store, StoreError
from erinix.summary import ago, build_overview, empty_overview, humanize
from erinix.ui.render import Seg, box, paint_segs, safe
from erinix.ui.views import severity_badge
from erinix.web.server import DEFAULT_PORT, build_id, server_info_path

STATE_ROLE = {"critical": "bad", "attention": "warn", "protected": "ok", "stopped": "dim"}
BOX_WIDTH = 104            # one width for every console box, so they line up


# ---------------------------------------------------------------------- helpers
def _glyph(ctx: Context, state: str) -> str:
    g = ctx.theme.glyph
    return {"critical": g("bad"), "attention": g("warn"), "protected": g("ok")}.get(state, g("dot"))


def _wrap(text: str, width: int, role: str | None = None, bold: bool = False, indent: str = "") -> list[list[Seg]]:
    inner = max(20, width - 4)
    lines = textwrap.wrap(str(text), inner - len(indent)) or [""]
    return [[Seg(indent + line, role, bold)] for line in lines]


def _open(ctx: Context, *, write: bool = False) -> Store | None:
    try:
        return Store(readonly=not write)
    except StoreError as exc:
        if write:
            ctx.error(str(exc))
            return None
        return None


def _numbered(store: Store, status: str = "open") -> list[dict]:
    return store.list_alerts(status, limit=200)


def _resolve(ctx: Context, store: Store, ref: str, status: str) -> dict | None:
    """'3' is the third alert of the list you see; an id prefix (6+ characters) also works."""
    if ref.isdigit() and len(ref) < 6:                  # numbers have at most 3 digits; 6+ digits can only be an id prefix
        rows = _numbered(store, status)
        if 1 <= int(ref) <= len(rows):
            return rows[int(ref) - 1]
        ctx.error(f"there is no alert number {ref} (use 'alerts' to see the list)")
        return None
    row = store.find_alert(ref)
    if row is None:
        ctx.error("no alert matches that id")
    return row


def _wrap_segs(parts: list[Seg], width: int) -> list[list[Seg]]:
    """Word-wrap a line made of coloured pieces; spaces and colours are kept, nothing is cut off."""
    lines: list[list[Seg]] = [[]]
    used = 0
    for seg in parts:
        for token in re.findall(r"\s*\S+|\s+", seg.text):
            if used and used + len(token) > width:
                lines.append([])
                used = 0
                token = token.lstrip()
                if not token:
                    continue
            lines[-1].append(Seg(safe(token), seg.role, seg.bold))
            used += len(token)
    return lines


def _hint(ctx: Context, *parts: Seg) -> None:
    """A line of advice that wraps at word boundaries instead of running past the terminal edge."""
    ctx.emit(lambda width: "\n".join(paint_segs(ctx.theme, line) for line in _wrap_segs(list(parts), width)))


BADGE_WIDTH = 10
AGE_WIDTH = 12
ROW_PREFIX = 3 + BADGE_WIDTH + 2 + AGE_WIDTH      # number, level, gap, age


def _badge(severity: str) -> Seg:
    """The severity label, padded to one width and starting in one column, so lists line up."""
    seg = severity_badge(Severity(severity))
    return Seg((" " + seg.text.strip() + " ").ljust(BADGE_WIDTH), seg.role, seg.bold)


def _alert_rows(alerts: list[dict], inner: int) -> list[list[Seg]]:
    """One block per alert: number, level, age, then the WHOLE sentence, wrapped under its own column."""
    rows: list[list[Seg]] = []
    for i, a in enumerate(alerts, 1):
        head = [Seg(str(i).ljust(2) + " ", "accent", True), _badge(a["severity"]), Seg("  "),
                Seg(ago(a["updated"]).ljust(AGE_WIDTH), "dim")]
        column = inner - ROW_PREFIX
        if column >= 24:
            lines = textwrap.wrap(a["headline"], column) or [""]
            rows.append(head + [Seg(safe(lines[0]))])
            rows += [[Seg(" " * ROW_PREFIX), Seg(safe(line))] for line in lines[1:]]
        else:                                          # too narrow for two columns: the sentence goes below
            rows.append(head)
            rows += [[Seg("   " + safe(line))] for line in textwrap.wrap(a["headline"], max(10, inner - 3)) or [""]]
    return rows


def _json(ctx: Context, payload: object) -> None:
    ctx.say(json.dumps(payload, indent=2))


# ----------------------------------------------------------------------- status
def home_sections(ctx: Context, o: dict, width: int) -> list:
    theme = ctx.theme
    inner = max(20, width - 4)

    def wrapped(rows: list[list[Seg]]) -> list[list[Seg]]:
        return [line for row in rows for line in _wrap_segs(row, inner)]

    role = STATE_ROLE.get(o["state"], "dim")
    n = o["open"]["total"]
    top = [[Seg(f"{_glyph(ctx, o['state'])} {o['headline']}", role, True)],
           [Seg(f"{n} open {'alert' if n == 1 else 'alerts'} {theme.glyph('dot')} {o['events_24h']:,} events checked in 24 h", "brown")]]
    if o["demo"]:
        top.append([Seg("Demo data: simulated attacks, not real monitoring", "warn")])
    watching: list[list[Seg]] = []
    for s in o["sources"]:
        ok = s.get("state") == "ok"
        text = s.get("name", "?") + ("" if ok else f" {theme.glyph('dot')} {s.get('detail') or s.get('state')}")
        watching.append([Seg(theme.glyph("ok" if ok else "warn") + " ", "ok" if ok else "warn", True), Seg(text)])
    named = [s.get("name", "") + ":" for s in o["sources"]]
    for blind in o["blind_spots"]:
        if not any(blind.startswith(prefix) for prefix in named):
            watching.append([Seg(theme.glyph("warn") + " ", "warn", True), Seg("Blind spot: " + blind)])
    if not watching:
        watching.append([Seg("Nothing yet", "dim")])
    attention = _alert_rows(o["attention"], inner)
    if not attention:
        attention.append([Seg("Nothing needs your attention.", "ok")])
    hints = [[Seg("alert 1", "accent"), Seg(" details  ", "dim"), Seg("alerts", "accent"), Seg(" the full list  ", "dim"),
              Seg("ui", "accent"), Seg(" web dashboard", "dim")]]
    return [(None, wrapped(top)), ([Seg(f"{theme.glyph('star')} WATCHING", "accent", True)], wrapped(watching)),
            ([Seg(f"{theme.glyph('star')} NEEDS ATTENTION ({n})", "accent", True)], attention),
            ([Seg(f"{theme.glyph('star')} NEXT", "accent", True)], wrapped(hints))]


def cmd_status(ctx: Context, args: list[str]) -> int:
    _, flags, _ = parse_args(args, flags=("--json",), max_positional=0)
    store = _open(ctx)
    try:
        overview = build_overview(store) if store else empty_overview()
    finally:
        if store:
            store.close()
    if "--json" in flags:
        _json(ctx, overview)
        return 0
    title = [Seg(f"{ctx.theme.glyph('star')} ERINIX {ctx.theme.glyph('dot')} STATUS", "accent", True)]
    ctx.emit(lambda w: "\n".join(box(ctx.theme, title, home_sections(ctx, overview, min(w, BOX_WIDTH)), width=min(w, BOX_WIDTH), border="brown")))
    return 0


# ----------------------------------------------------------------------- alerts
def cmd_alerts(ctx: Context, args: list[str]) -> int:
    _, flags, _ = parse_args(args, flags=("--all", "--dismissed", "--json"), max_positional=0)
    status = "all" if "--all" in flags else "dismissed" if "--dismissed" in flags else "open"
    store = _open(ctx)
    rows = [humanize(r) for r in _numbered(store, status)] if store else []
    if store:
        store.close()
    if "--json" in flags:
        _json(ctx, rows)
        return 0
    if not rows:
        _hint(ctx, Seg(ctx.theme.glyph("ok") + " ", "ok", True), Seg("Nothing needs your attention." if status == "open" else "No alerts here."))
        return 0
    def build(width: int) -> str:
        inner = min(width, BOX_WIDTH)
        lines: list[list[Seg]] = []
        if inner - ROW_PREFIX >= 24:
            lines.append([Seg("#".ljust(2) + " ", "dim"), Seg(" " + "Level".ljust(BADGE_WIDTH - 1), "dim"), Seg("  "),
                          Seg("When".ljust(AGE_WIDTH), "dim"), Seg("What happened", "dim")])
        lines += _alert_rows(rows, inner)
        return "\n".join(paint_segs(ctx.theme, line) for line in lines)

    ctx.emit(build)
    _hint(ctx, Seg("alert 1", "accent"), Seg(" shows the details; add ", "dim"), Seg("--tech", "accent"), Seg(" for the technical side.", "dim"))
    return 0


def alert_sections(ctx: Context, a: dict, width: int, tech: bool) -> list:
    g = ctx.theme.glyph
    steps: list[list[Seg]] = []
    for i, step in enumerate(a["next_steps"], 1):
        wrapped = _wrap(step, width, indent="   ")
        wrapped[0][0] = Seg(f"{i}. " + wrapped[0][0].text.lstrip(), None)
        steps += wrapped
    sections = [(None, _wrap(a["why"], width))]
    if steps:
        sections.append(([Seg(f"{g('star')} WHAT TO DO", "accent", True)], steps))
    if a["progress"]:
        p = a["progress"]
        sections[0][1].append([Seg(("Completed all " + str(p["total"]) + " steps") if p["complete"]
                                   else f"Step {p['done']} of {p['total']}", "brown")])
    if tech:
        t = a["technical"]
        rows = [("Rule", t["rule"]), ("Type", t["kind"]), ("Source address", a["remote"]), ("Latest step", t["step"]),
                ("Response mode", t["response"]), ("MITRE ATT&CK", ", ".join(t["mitre"])),
                ("Process", f"pid {t['anchor_pid']}" if t["anchor_pid"] else None),
                ("First seen", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a["first_seen"]))),
                ("Last update", f"{time.strftime('%H:%M:%S', time.localtime(a['updated']))} (revision {t['revision']})"),
                ("Evidence", " | ".join(f"{s}: {', '.join(ids)}" for s, ids in t["evidence"])), ("Details", t["detail"])]
        lines: list[list[Seg]] = []
        for label, value in rows:
            if value:
                chunks = textwrap.wrap(str(value), max(20, width - 4 - 16)) or [""]
                lines.append([Seg(label.ljust(16), "brown"), Seg(chunks[0])])
                lines += [[Seg(" " * 16), Seg(c)] for c in chunks[1:]]
        sections.append(([Seg(f"{g('star')} TECHNICAL DETAILS", "accent", True)], lines))
    return sections


def cmd_alert(ctx: Context, args: list[str]) -> int:
    pos, flags, _ = parse_args(args, flags=("--tech", "--json", "--dismissed"), max_positional=1)
    if not pos:
        raise UsageError("which alert? Use its number from 'alerts' (for example: alert 1)")
    store = _open(ctx)
    if store is None:
        ctx.error("no alerts yet (try: demo)")
        return 1
    try:
        row = _resolve(ctx, store, pos[0], "dismissed" if "--dismissed" in flags else "open")
    finally:
        store.close()
    if row is None:
        return 1
    a = humanize(row)
    if "--json" in flags:
        _json(ctx, a)
        return 0
    tech = "--tech" in flags
    title = [severity_badge(Severity(a["severity"])), Seg("  " + a["headline"], "accent", True)]
    ctx.emit(lambda w: "\n".join(box(ctx.theme, title, alert_sections(ctx, a, min(w, BOX_WIDTH), tech), width=min(w, BOX_WIDTH), border="brown")))
    if not tech:
        _hint(ctx, Seg("Add ", "dim"), Seg("--tech", "accent"), Seg(" for the technical details, or ", "dim"),
              Seg(f"dismiss {pos[0]}", "accent"), Seg(" to hide it.", "dim"))
    return 0


def _set_status(ctx: Context, args: list[str], status: str) -> int:
    pos, _, _ = parse_args(args, max_positional=1)
    if not pos:
        raise UsageError("which alert? Use its number (for example: dismiss 1)")
    store = _open(ctx, write=True)
    if store is None:
        return 1
    try:
        row = _resolve(ctx, store, pos[0], "open" if status == "dismissed" else "dismissed")
        if row is None:
            return 1
        store.set_alert_status(row["alert_id"], status)
    finally:
        store.close()
    verb = "dismissed" if status == "dismissed" else "reopened"
    _hint(ctx, Seg(ctx.theme.glyph("ok") + " ", "ok", True), Seg(f"Alert {verb}: {humanize(row)['headline']}"))
    return 0


def cmd_dismiss(ctx: Context, args: list[str]) -> int:
    return _set_status(ctx, args, "dismissed")


def cmd_reopen(ctx: Context, args: list[str]) -> int:
    return _set_status(ctx, args, "open")


def cmd_sources(ctx: Context, args: list[str]) -> int:
    _, flags, _ = parse_args(args, flags=("--json",), max_positional=0)
    store = _open(ctx)
    overview = build_overview(store) if store else empty_overview()
    if store:
        store.close()
    if "--json" in flags:
        _json(ctx, {"sources": overview["sources"], "blind_spots": overview["blind_spots"]})
        return 0
    g = ctx.theme.glyph
    if overview["sources"]:
        ctx.table(["Source", "Status", "Details"],
                  [[s.get("name", "?"), Seg(g("ok") + " Watching", "ok") if s.get("state") == "ok" else Seg(g("warn") + " Blind", "warn"),
                    s.get("detail", "")] for s in overview["sources"]])
    for blind in overview["blind_spots"]:
        _hint(ctx, Seg(g("warn") + " ", "warn", True), Seg("Blind spot: " + blind))
    return 0


# --------------------------------------------------------------- demo and dashboard
def cmd_demo(ctx: Context, args: list[str]) -> int:
    from erinix.commands.builtin import default_rules_path
    from erinix.demo.scenarios import SCENARIOS
    from erinix.engine import Correlator
    from erinix.rules import RuleError, load_rules

    _, flags, _ = parse_args(args, flags=("--reset", "--force"), max_positional=0)
    store = _open(ctx, write=True)
    if store is None:
        return 1
    with store:
        if store.get_meta("mode") == "live" and "--force" not in flags:
            ctx.error("this store holds real monitoring data: demo would erase it (use --force if you are sure)")
            return 1
        store.reset()
        if "--reset" in flags:
            _hint(ctx, Seg(ctx.theme.glyph("ok") + " ", "ok", True), Seg("Store cleared."))
            return 0
        try:
            ruleset = load_rules(default_rules_path(None))
        except RuleError as exc:
            ctx.error(str(exc))
            return 2
        now = time.time()
        total_events = total_alerts = 0
        for name, minutes_ago in (("web", 14), ("ssh", 9), ("revshell", 5), ("shadow", 2)):
            events = sorted(SCENARIOS[name].build(), key=lambda e: e.mono_ns)
            correlator = Correlator(ruleset)
            start = now - minutes_ago * 60
            count = 0
            for ev in events:
                for alert in correlator.process(ev):
                    store.upsert_alert(dataclasses.replace(alert, wall_ns=int((start + ev.mono_ns / 1e9) * 1e9)), now=now)
                    count += 1
            total_events += len(events)
            total_alerts += count
            store.bump(events=len(events), alerts=count, now=start)
        for i in range(48):                                  # a believable day of normal activity for the chart
            store.bump(events=int(60 + 45 * math.sin(i / 5.0) + (i * 7) % 23), now=now - i * 1800)
        store.set_meta("mode", "demo")
        store.set_meta("started", now - 3 * 3600)
        store.set_meta("sources", [
            {"name": "Web server log (Caddy)", "state": "ok", "detail": "demo"},
            {"name": "SSH logins", "state": "ok", "detail": "demo"},
            {"name": "Programs and commands", "state": "ok", "detail": "demo"},
            {"name": "Kernel-level events", "state": "blind", "detail": "need root"},
        ])
    _hint(ctx, Seg(ctx.theme.glyph("ok") + " ", "ok", True), Seg(f"Demo data loaded: {total_alerts} alert updates from {total_events} simulated events."))
    _hint(ctx, Seg("Try ", "dim"), Seg("status", "accent"), Seg(", ", "dim"), Seg("alerts", "accent"), Seg(" or ", "dim"), Seg("ui", "accent"),
          Seg(" (the web dashboard).", "dim"))
    return 0


def _read_server_info() -> dict | None:
    path = server_info_path()
    try:
        st = os.lstat(path)
        if st.st_uid != os.geteuid() or st.st_mode & 0o077:
            return None
        data = json.loads(path.read_text())
        return data if isinstance(data.get("port"), int) and isinstance(data.get("pid"), int) else None
    except (OSError, ValueError):
        return None


def _health(port: int) -> str | None:
    """What a dashboard on this port answers to /healthz ('ok <build>'), or None if nothing answers."""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
        conn.request("GET", "/healthz", headers={"Host": f"127.0.0.1:{port}"})
        response = conn.getresponse()
        body = response.read(100).decode("ascii", "replace").strip()
        return body if response.status == 200 and body.startswith("ok") else None
    except (OSError, http.client.HTTPException):
        return None


def _stop_server(ctx: Context, info: dict) -> bool:
    """Stop the recorded dashboard, but only if that process really is an Erinix dashboard."""
    pid = info["pid"]
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        cmdline = []
    if not (b"serve" in cmdline and any(b"erinix" in part for part in cmdline)):
        ctx.error("the recorded process is not an Erinix dashboard: not touching it")
        return False
    os.kill(pid, signal.SIGTERM)
    for _ in range(30):
        time.sleep(0.1)
        if not Path(f"/proc/{pid}").exists():
            break
    return True


def _parse_port(opts: dict[str, str]) -> int:
    try:
        port = int(opts.get("--port", DEFAULT_PORT))
    except ValueError:
        raise UsageError("--port needs a number") from None
    if not 1024 <= port <= 65535:
        raise UsageError("--port must be between 1024 and 65535")
    return port


def cmd_ui(ctx: Context, args: list[str]) -> int:
    _, flags, opts = parse_args(args, flags=("--no-browser",), options=("--port",), max_positional=0)
    port = _parse_port(opts)
    store = _open(ctx, write=True)
    if store is None:
        return 1
    with store:
        token = store.create_login_token()
    info = _read_server_info()
    answer = _health(info["port"]) if info else None
    if answer is not None and answer != f"ok {build_id()}":
        _hint(ctx, Seg("An older dashboard is still running: replacing it with the current one.", "dim"))
        if not _stop_server(ctx, info):
            ctx.error("could not replace the old dashboard: run 'erinix stop' from a normal terminal")
            return 1
        answer = None
    if answer is not None:
        port = info["port"]
    else:
        subprocess.Popen([sys.executable, "-m", "erinix.cli", "serve", "--port", str(port)], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        for _ in range(50):
            time.sleep(0.1)
            if _health(port) is not None:
                break
        else:
            ctx.error(f"the dashboard did not start on port {port} (is it in use? try --port)")
            return 1
    url = f"http://127.0.0.1:{port}/#login={token}"
    _hint(ctx, Seg(ctx.theme.glyph("ok") + " ", "ok", True), Seg("Dashboard ready. This private link works once, for two minutes:"))
    ctx.line(Seg(url, "accent"))
    if "--no-browser" not in flags and not open_url(url):
        _hint(ctx, Seg("Could not open a browser: copy the link above into one.", "dim"))
    return 0


def cmd_serve(ctx: Context, args: list[str]) -> int:
    _, _, opts = parse_args(args, options=("--port",), max_positional=0)
    if ctx.emitter is not None:
        ctx.error("'serve' keeps running: start it from a normal terminal (or just use 'ui')")
        return 2
    from erinix.web.server import serve

    port = _parse_port(opts)
    print(f"Dashboard on http://127.0.0.1:{port}  (Ctrl-C to stop)", file=sys.stderr)
    try:
        serve(port)
    except OSError as exc:
        ctx.error(f"cannot listen on port {port}: {exc.strerror}")
        return 1
    return 0


def cmd_stop(ctx: Context, args: list[str]) -> int:
    parse_args(args, max_positional=0)
    info = _read_server_info()
    if not info:
        _hint(ctx, Seg("The dashboard is not running."))
        return 0
    if not _stop_server(ctx, info):
        return 1
    _hint(ctx, Seg(ctx.theme.glyph("ok") + " ", "ok", True), Seg("Dashboard stopped."))
    return 0


# ------------------------------------------------------------------- install app
def cmd_install_app(ctx: Context, args: list[str]) -> int:
    from erinix.install import InstallError, install_app

    _, flags, opts = parse_args(args, flags=("--force",), options=("--terminal",), max_positional=0)
    try:
        result = install_app(Path.home(), python=sys.executable, terminal=opts.get("--terminal"), force="--force" in flags)
    except InstallError as exc:
        ctx.error(str(exc))
        return 1
    _hint(ctx, Seg(ctx.theme.glyph("ok") + " ", "ok", True), Seg("Erinix is installed as an app."))
    for path in result.written:
        ctx.line(Seg("  " + str(path), "dim"))
    _hint(ctx, Seg("Terminal used by the menu entry: ", "brown"), Seg(result.terminal or "your desktop's default"))
    for note in result.notes:
        _hint(ctx, Seg(ctx.theme.glyph("warn") + " ", "warn", True), Seg(note))
    return 0


def cmd_uninstall_app(ctx: Context, args: list[str]) -> int:
    from erinix.install import uninstall_app

    parse_args(args, max_positional=0)
    removed = uninstall_app(Path.home())
    _hint(ctx, Seg(f"Removed {len(removed)} file(s)." if removed else "Nothing to remove."))
    for path in removed:
        ctx.line(Seg("  " + str(path), "dim"))
    return 0
