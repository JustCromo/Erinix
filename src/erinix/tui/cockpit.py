"""The full-screen cockpit: everything Erinix sees, live, in one terminal.

`render()` turns the current data and state into lines of text (testable without a terminal); `Cockpit.run()` is the
thin loop that reads keys and repaints. All text that comes from the machine goes through `safe()` and `fit()`.
"""

from __future__ import annotations

import contextlib
import io
import os
import time
from dataclasses import dataclass, field
from typing import Callable

from erinix.tui import terminal as term
from erinix.ui.render import Seg, display_width, fit, paint_segs, safe, seg_width
from erinix.ui.theme import Theme

# in the order they are laid out (left column top to bottom, then right column), so Tab and the numbers follow the screen
PANELS = ("incidents", "live", "posture", "ports", "connections", "programs")
TITLES = {"incidents": "Incidents", "live": "Live", "ports": "Open ports", "connections": "Connections", "programs": "Programs", "posture": "Health"}
BLOCKS = " ▁▂▃▄▅▆▇█"
ROUTINE = ("process.exec", "net.connect", "net.accept", "net.listen")
REFRESH = 1.0
SEV_ROLE = {"critical": "bad", "high": "bad", "medium": "warn", "low": "dim"}
HELP = [
    "WHERE DO I TYPE?",
    "  Press  :  then type a command and press Enter. Examples:",
    "      assess              check how hard this machine is to attack",
    "      block 203.0.113.50  block an address for an hour (asks first)",
    "      kill 4242           stop a program (numbers are in panel 6)",
    "      actions             what Erinix has done      undo 3   reverse it",
    "      help                every command",
    "  You rarely need to type: select a row and use the keys below.",
    "",
    "MOVING",
    "  Tab / Shift-Tab or 1-6   change panel      Up / Down (j)   select a row     PgUp / PgDn   faster",
    "  Enter   panel full screen, then open the row      Esc or q   go back      /   search in the panel",
    "",
    "A TYPICAL CHECK",
    "  1. Press 3 (Health): the list of things to look at, with the score.",
    "  2. Enter twice on a row: what was found and how to fix it.",
    "  3. If it says Erinix can fix it, press f on the row: you see the exact changes, and y confirms.",
    "  4. Press a to check again.",
    "",
    "WHEN AN ATTACK SHOWS UP",
    "  1. Panel 1 (Incidents): Enter twice to read what happened and what to do.",
    "  2. b  block the attacker's address (an hour, then it lifts by itself)     x  close the incident when done.",
    "  3. Panel 6 (Programs): k stops a program you do not trust.",
    "  Nothing is ever done without a box showing what will happen and you pressing y.",
    "",
    "OTHER KEYS",
    "  r  routine activity on/off     p  pause the live feed     s  what Erinix is watching",
    "  w  web dashboard (opens the browser)     R  see every program (asks for your sudo password)     q  quit",
]

# the keys that matter in each panel, shown at the bottom of the screen
CONTEXT_KEYS = {
    "incidents": [("Enter", "read it"), ("b", "block its address"), ("x", "close it")],
    "live": [("Enter", "details"), ("b", "block address"), ("r", "routine"), ("p", "pause")],
    "posture": [("Enter", "how to fix"), ("f", "fix it"), ("a", "check again")],
    "ports": [("Enter", "details"), ("k", "stop its program")],
    "connections": [("Enter", "details"), ("b", "block address"), ("k", "stop program")],
    "programs": [("Enter", "details"), ("k", "stop it"), ("/", "search")],
}


@dataclass
class Data:
    overview: dict = field(default_factory=dict)
    inventory: dict = field(default_factory=dict)
    assessment: dict = field(default_factory=dict)
    incidents: list = field(default_factory=list)
    events: list = field(default_factory=list)
    error: str = ""
    at: float = 0.0


def load_data(open_store: Callable[[], object], now: float | None = None) -> Data:
    """One consistent look at the store (read-only). Never raises: a missing store is a message."""
    from erinix.incidents import build_incidents
    from erinix.store import StoreError
    from erinix.assessment import empty_assessment
    from erinix.summary import build_assessment, build_inventory, build_overview, empty_inventory, empty_overview

    now = time.time() if now is None else now
    try:
        store = open_store()
    except StoreError:
        return Data(empty_overview(), empty_inventory(), empty_assessment(), [], [], "no data yet: the agent is starting", now)
    except Exception as exc:
        return Data(empty_overview(), empty_inventory(), empty_assessment(), [], [], f"cannot read the store: {type(exc).__name__}", now)
    try:
        return Data(build_overview(store), build_inventory(store), build_assessment(store), build_incidents(store, "open"), store.list_events(limit=300), "", now)
    except Exception as exc:
        return Data(empty_overview(), empty_inventory(), empty_assessment(), [], [], f"cannot read the store: {type(exc).__name__}", now)
    finally:
        store.close()


def _clean(parts: list[Seg]) -> list[Seg]:
    """Whatever comes from the machine or the store is printed with control characters escaped."""
    return [Seg(safe(p.text), p.role, p.bold) for p in parts]


def clock(ts: object) -> str:
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError, OverflowError, OSError):
        return "--:--:--"


def ago(ts: object, now: float) -> str:
    try:
        sec = max(0, int(now - float(ts)))
    except (TypeError, ValueError):
        return ""
    return f"{sec}s" if sec < 60 else f"{sec // 60}m" if sec < 3600 else f"{sec // 3600}h" if sec < 86400 else f"{sec // 86400}d"


def sparkline(values: list[int], width: int) -> str:
    if width <= 0 or not values:
        return ""
    step = max(1, -(-len(values) // width))
    pooled = [sum(values[i:i + step]) for i in range(0, len(values), step)][-width:]
    top = max(pooled) or 1
    return "".join(BLOCKS[0 if v == 0 else 1 + min(7, v * 7 // top)] for v in pooled)


class Cockpit:
    def __init__(self, theme: Theme, out, *, open_store: Callable[[], object], registry=None, runtime=None,
                 size_fn: Callable[[], tuple[int, int]] = term.terminal_size, clock_fn: Callable[[], float] = time.time,
                 elevate_fn: Callable[[], str] | None = None, service=None) -> None:
        self.theme, self.out, self.open_store, self.registry, self.runtime = theme, out, open_store, registry, runtime
        self.size_fn, self.now, self.elevate_fn = size_fn, clock_fn, elevate_fn
        self.service = service                      # what Erinix may DO (block, kill, fix); None: view only
        self.pending: tuple[str, dict, str] | None = None
        self.data = Data()
        self.focus = 0
        self.sel = {p: 0 for p in PANELS}
        self.query = {p: "" for p in PANELS}
        self.routine = False
        self.paused_at: int | None = None
        self.zoom = False
        self.mode = "normal"            # normal | search | command | overlay
        self.buffer = ""
        self.overlay: list[str] = []
        self.overlay_title = ""
        self.overlay_scroll = 0
        self.flash = ""
        self.done = False
        self._loaded = -1e9
        self._last: list[str] | None = None

    # ------------------------------------------------------------------ data
    def refresh(self, force: bool = False) -> bool:
        if not force and self.now() - self._loaded < REFRESH:
            return False
        self._loaded = self.now()
        self.data = load_data(self.open_store, self.now())
        return True

    # ------------------------------------------------------------------ rows
    def rows(self, panel: str) -> list[tuple[list[Seg], str, object]]:
        """(segments, search text, the thing itself) for each visible row of a panel."""
        now, d = self.now(), self.data
        out: list[tuple[list[Seg], str, object]] = []
        if panel == "incidents":
            for i in d.incidents:
                role = SEV_ROLE.get(i["severity"], "dim")
                parts = [Seg(self.theme.glyph("warn") + " ", role, True), Seg(i["headline"], None, True), Seg("  " + i["who"], "dim"),
                         Seg(f"  {ago(i['updated'], now)}", "dim")]
                out.append((parts, f"{i['headline']} {i['who']} {i['summary']}", i))
        elif panel == "live":
            for e in reversed(d.events):
                if self.paused_at is not None and e["id"] > self.paused_at:
                    continue
                flagged = bool(e.get("alert_id"))
                if not flagged and not self.routine and e.get("kind") in ROUTINE:
                    continue
                role = SEV_ROLE.get(e.get("severity") or "", "warn") if flagged else None
                parts = [Seg(clock(e["ts"]) + " ", "dim"), Seg((self.theme.glyph("warn") + " ") if flagged else "  ", role, True),
                         Seg(str(e.get("label", "")), role, True), Seg(" " + str(e.get("summary", ""))),
                         Seg(("  " + e["remote"]) if e.get("remote") else "", "dim")]
                out.append((parts, f"{e.get('label', '')} {e.get('summary', '')} {e.get('remote', '')}", e))
        elif panel == "ports":
            for r in d.inventory.get("listening", []):
                name = r.get("program") or ""
                parts = [Seg(f":{r['port']:<6}", "accent", True), Seg((name or "unknown program")[:19].ljust(20), None if name else "dim"),
                         Seg("open to the network" if r.get("exposed") else "this machine only", "warn" if r.get("exposed") else "dim")]
                out.append((parts, f"{r['port']} {name}", r))
        elif panel == "connections":
            for r in d.inventory.get("connections", []):
                name = r.get("program") or ""
                parts = [Seg((name or "unknown program")[:17].ljust(18), None if name else "dim"), Seg(self.theme.glyph("arrow") + " "),
                         Seg(str(r.get("remote", "")), "warn" if r.get("external") else "dim")]
                out.append((parts, f"{name} {r.get('remote', '')}", r))
        elif panel == "programs":
            for r in d.inventory.get("processes", []):
                parts = [Seg(f"{r['pid']:<7}", "dim"), Seg(str(r.get("name", ""))[:15].ljust(16), None, True), Seg(str(r.get("command", "")), "dim")]
                out.append((parts, f"{r.get('name', '')} {r.get('command', '')} {r['pid']}", r))
        elif panel == "posture":
            marks = {"fail": ("✖", "bad"), "warn": ("▲", "warn"), "unknown": ("?", "dim"), "info": ("i", "dim")}
            for c in self.data.assessment.get("checks", []):
                if c.get("state") not in marks:
                    continue
                mark, role = marks[c["state"]]
                out.append(([Seg(mark + " ", role, True), Seg(str(c.get("title", "")), role if c["state"] in ("fail", "warn") else None, True), Seg("  " + str(c.get("detail", "")), "dim")],
                            f"{c.get('title', '')} {c.get('area', '')} {c.get('detail', '')}", c))
        q = self.query[panel].lower()
        if q:
            out = [r for r in out if q in r[1].lower()]
        return out

    # ------------------------------------------------------------------ drawing
    def _box(self, panel: str, width: int, height: int) -> list[str]:
        g, th = self.theme.glyph, self.theme
        focused = PANELS[self.focus] == panel
        border = "accent" if focused else "border"
        rows = self.rows(panel)
        n = len(rows)
        sel = min(self.sel[panel], max(0, n - 1))
        self.sel[panel] = sel
        inner_h, inner_w = max(0, height - 2), max(1, width - 4)
        first = 0 if sel < inner_h else sel - inner_h + 1
        title = [Seg(f"{PANELS.index(panel) + 1} ", "dim"), Seg(TITLES[panel], "accent" if focused else "brown", True)]
        if panel == "posture" and self.data.assessment.get("score") is not None:
            sc = self.data.assessment["score"]
            title.append(Seg(f" {sc}/100", "ok" if sc >= 90 else "warn" if sc >= 70 else "bad", True))
        extra = f" {n}" + (f' /{self.query[panel]}' if self.query[panel] else "") + (" paused" if panel == "live" and self.paused_at is not None else "")
        title.append(Seg(extra, "dim"))
        t = fit(title, max(1, width - 6), g("ell"))
        fill = max(0, width - 5 - seg_width(t))
        top = th.paint(g("tl") + g("h") + " ", border) + paint_segs(th, t) + th.paint(" " + g("h") * fill + g("tr"), border)
        lines = [top]
        for k in range(inner_h):
            idx = first + k
            if idx < n:
                parts = fit(_clean(rows[idx][0]), inner_w - 2, g("ell"))
                mark = Seg(g("prompt") + " " if idx == sel and focused else "  ", "accent", True)
                body = paint_segs(th, [mark, *parts])
                pad = " " * (inner_w - 2 - seg_width(parts))
            else:
                body, pad = paint_segs(th, [Seg("  ")]), " " * (inner_w - 2)
                if k == 0 and n == 0:
                    msg = self._empty(panel)
                    body = paint_segs(th, [Seg("  "), *fit([Seg(msg, "dim")], inner_w - 2, g("ell"))])
                    pad = " " * (inner_w - 2 - min(inner_w - 2, display_width(msg)))
            lines.append(th.paint(g("v") + " ", border) + body + pad + th.paint(" " + g("v"), border))
        if height >= 2:
            lines.append(th.paint(g("bl") + g("h") * (width - 2) + g("br"), border))
        return lines[:height]

    def _empty(self, panel: str) -> str:
        if self.query[panel]:
            return "nothing matches"
        if panel == "incidents":
            return "Nothing needs your attention."
        if panel == "live":
            return "Quiet. Press r to include routine activity."
        if panel == "posture":
            return "Everything checked is fine." if self.data.assessment.get("checks") else "Checking this machine..."
        return "Waiting for the first look..."

    def _header(self, width: int) -> list[str]:
        th, d = self.theme, self.data
        ov = d.overview or {}
        state = ov.get("state", "stopped")
        role = {"critical": "bad", "attention": "warn", "protected": "ok"}.get(state, "dim")
        role_name = getattr(self.runtime, "role", "viewer") if self.runtime else "viewer"
        mode = getattr(self.runtime, "mode", "limited") if self.runtime else "limited"
        left = [Seg(" erinix ", "accent", True), Seg(th.glyph("dot") + " ", "dim"), Seg(ov.get("headline", "") or d.error, role, True)]
        right = [Seg("watching " if role_name == "agent" else "viewing ", "dim"),
                 Seg("everything" if mode == "full" else "your programs only", "ok" if mode == "full" else "warn", True), Seg(" ")]
        gap = max(1, width - seg_width(left) - seg_width(right))
        l1 = paint_segs(th, fit(_clean([*left, Seg(" " * gap), *right]), width, th.glyph("ell")))
        op = ov.get("open", {})
        act = [p["events"] for p in ov.get("activity", [])]
        srcs = ov.get("sources", [])
        ok = sum(1 for s in srcs if s.get("state") == "ok")
        sc = d.assessment.get("score")
        health = [Seg(f"health {sc}/100  ", "ok" if sc >= 90 else "warn" if sc >= 70 else "bad", True)] if sc is not None else []
        line = [Seg(" "), *health, Seg(str(op.get("critical", 0)), "bad", True), Seg(" critical  "), Seg(str(op.get("total", 0)), "warn", True), Seg(" open  "),
                Seg(str(len(d.incidents)), None, True), Seg(" incidents  "), Seg(f"{ok}/{len(srcs)}", "ok" if ok == len(srcs) else "warn", True),
                Seg(" sources  "), Seg(str(ov.get("events_24h", 0)), None, True), Seg(" events/24h  ", None), Seg(sparkline(act, 28), "accent")]
        return [l1, paint_segs(th, fit(_clean(line), width, th.glyph("ell")))]

    def _footer(self, width: int) -> list[str]:
        th = self.theme
        if self.mode in ("search", "command"):
            prompt = "/" if self.mode == "search" else ":"
            row = [Seg(" " + prompt, "accent", True), Seg(self.buffer), Seg("▏", "accent")]
            hint = [Seg(" Enter runs, Esc cancels", "dim")]
        elif self.mode == "confirm":
            row = [Seg(" y", "accent", True), Seg(" do it    "), Seg("any other key", "accent", True), Seg(" cancel")]
            hint = []
        else:
            row = [Seg(" " + (self.flash or self._status()), "warn" if self.flash else "dim")]
            hint = []
        if self.mode == "command":
            keys = self._suggestions()
        elif self.mode == "confirm":
            keys = []
        elif self.mode == "overlay":
            keys = [Seg(" Esc", "accent", True), Seg(" or "), Seg("q", "accent", True), Seg(" go back   "), Seg("Up / Down", "accent", True), Seg(" scroll")]
        else:
            keys = [Seg(" ")]
            for key, label in CONTEXT_KEYS[PANELS[self.focus]] + [("Tab", "next panel"), (":", "type a command"), ("?", "guide"), ("q", "quit")]:
                keys += [Seg(key, "accent", True), Seg(f" {label}  ")]
        return [paint_segs(th, fit(_clean([*row, *hint]), width, th.glyph("ell"))), paint_segs(th, fit(keys, width, th.glyph("ell")))]

    def _suggestions(self) -> list[Seg]:
        """While typing a command: the commands that match, or the usage of the one typed."""
        if self.registry is None:
            return [Seg(" no commands here", "dim")]
        text = self.buffer.strip().lower()
        cmds = [c for c in self.registry.commands if c.name not in ("watch", "serve", "demo", "exit", "quit")]
        first = ["assess", "block", "kill", "fix", "actions", "undo", "alerts", "status", "help"]
        cmds.sort(key=lambda c: first.index(c.name) if c.name in first else len(first))     # the useful ones first
        exact = next((c for c in cmds if text == c.name or text.startswith(c.name + " ")), None)
        if exact is not None:
            return [Seg(" " + exact.usage, "accent", True), Seg("   " + exact.summary, "dim")]
        names = [c.name for c in cmds if c.name.startswith(text.split(" ")[0])] if text else [c.name for c in cmds]
        return [Seg(" ", "dim"), *[Seg(n + "  ", "accent") for n in names[:14]]] if names else [Seg(" no command starts like that: type help", "dim")]

    def _status(self) -> str:
        rt = self.runtime
        if self.data.error:
            return self.data.error
        if rt is not None and getattr(rt, "error", ""):
            return rt.error
        if rt is not None and getattr(rt, "note", "") and getattr(rt, "mode", "full") != "full":
            return f"full view not available: {rt.note}"
        if rt is not None and getattr(rt, "mode", "full") != "full":
            unknown = sum(1 for r in self.data.inventory.get("listening", []) if not r.get("program"))
            if unknown:
                return f"{unknown} ports show 'unknown program': press R to see every program"
        return "Press ? for the guide, or : to type a command"

    def render(self) -> list[str]:
        cols, rows = self.size_fn()
        cols, rows = max(20, cols), max(8, rows)
        th = self.theme
        head, foot = self._header(cols), self._footer(cols)
        body_h = rows - len(head) - len(foot)
        if self.mode in ("overlay", "confirm"):
            body = self._overlay_box(cols, body_h)
        elif cols >= 110 and not self.zoom:
            lw = cols * 11 // 20
            rw = cols - lw
            h1 = max(3, body_h * 2 // 5)
            left = self._box("incidents", lw, h1) + self._box("live", lw, body_h - h1)
            q = max(3, body_h // 4)
            right = self._box("posture", rw, q) + self._box("ports", rw, q) + self._box("connections", rw, q) + self._box("programs", rw, body_h - 3 * q)
            body = [l + r for l, r in zip(left, right)]
        else:
            tabs = [Seg(" ")]
            for i, p in enumerate(PANELS):
                on = i == self.focus
                tabs += [Seg(f"{i + 1} {TITLES[p]}", "accent" if on else "dim", on), Seg("  ")]
            body = [paint_segs(th, fit(tabs, cols, th.glyph("ell")))] + self._box(PANELS[self.focus], cols, body_h - 1)
        body = body[:body_h] + [""] * max(0, body_h - len(body))
        return head + body + foot

    def _overlay_box(self, width: int, height: int) -> list[str]:
        th, g = self.theme, self.theme.glyph
        inner = max(1, width - 4)
        view = max(0, height - 2)
        top = th.paint(g("tl") + g("h") + " ", "accent") + th.paint(safe(self.overlay_title), "accent", True) + th.paint(" " + g("h") * max(0, width - 5 - display_width(self.overlay_title)) + g("tr"), "accent")
        out = [top]
        for k in range(view):
            i = self.overlay_scroll + k
            text = self.overlay[i] if i < len(self.overlay) else ""
            parts = fit([Seg(safe(text))], inner, g("ell"))
            out.append(th.paint(g("v") + " ", "accent") + paint_segs(th, parts) + " " * (inner - seg_width(parts)) + th.paint(" " + g("v"), "accent"))
        out.append(th.paint(g("bl") + g("h") * (width - 2) + g("br"), "accent"))
        return out[:height]

    # ------------------------------------------------------------------ keys
    def handle(self, tok: str) -> None:
        if self.mode == "confirm":
            return self._confirm_key(tok)
        if self.mode in ("search", "command"):
            return self._edit(tok)
        if self.mode == "overlay":
            return self._overlay_key(tok)
        self.flash = ""
        panel = PANELS[self.focus]
        n = len(self.rows(panel))
        page = max(3, self.size_fn()[1] // 3)
        if tok == "q" and self.zoom:
            self.zoom = False
        elif tok in ("q", "\x03", "\x04"):
            self.done = True
        elif tok == "\t":
            self.focus = (self.focus + 1) % len(PANELS)
        elif tok == "\x1b[Z":
            self.focus = (self.focus - 1) % len(PANELS)
        elif tok in "123456" and len(tok) == 1:
            self.focus = int(tok) - 1
        elif tok in ("j", "\x1b[B", "\x1bOB"):
            self.sel[panel] = min(max(0, n - 1), self.sel[panel] + 1)
        elif tok in ("\x1b[A", "\x1bOA"):
            self.sel[panel] = max(0, self.sel[panel] - 1)
        elif tok == "\x1b[6~":
            self.sel[panel] = min(max(0, n - 1), self.sel[panel] + page)
        elif tok == "\x1b[5~":
            self.sel[panel] = max(0, self.sel[panel] - page)
        elif tok in ("g", "\x1b[H"):
            self.sel[panel] = 0
        elif tok in ("G", "\x1b[F"):
            self.sel[panel] = max(0, n - 1)
        elif tok == "z":
            self.zoom = not self.zoom
        elif tok == "r":
            self.routine = not self.routine
            self.flash = "routine activity " + ("shown" if self.routine else "hidden")
        elif tok == "p":
            self.paused_at = None if self.paused_at is not None else (self.data.events[-1]["id"] if self.data.events else 0)
            self.flash = "live feed paused" if self.paused_at is not None else "live feed running"
        elif tok == "/":
            self.mode, self.buffer = "search", self.query[panel]
        elif tok == ":":
            self.mode, self.buffer = "command", ""
        elif tok == "?":
            self.show("Help", HELP)
        elif tok == "s":
            self.show("What Erinix is watching", self._sources_lines())
        elif tok in ("\r", "\n"):
            if self.zoom:
                self.open_row()
            else:
                self.zoom = True                       # first Enter: the panel fills the screen, to read and select
        elif tok == "\x1b" and self.zoom:
            self.zoom = False
        elif tok == "x":
            self.close_incident()
        elif tok == "w":
            self.open_web()
        elif tok == "a":
            self.recheck()
        elif tok == "b":
            self.act_block()
        elif tok == "k":
            self.act_kill()
        elif tok == "f":
            self.act_fix()
        elif tok == "R":
            self.elevate()
        elif tok == "\x1b":
            if self.query[panel]:
                self.query[panel] = ""

    def _edit(self, tok: str) -> None:
        if tok == "\x1b":
            if self.mode == "search":
                self.query[PANELS[self.focus]] = ""
            self.mode, self.buffer = "normal", ""
        elif tok in ("\r", "\n"):
            text, mode = self.buffer.strip(), self.mode
            self.mode, self.buffer = "normal", ""
            if mode == "search":
                self.query[PANELS[self.focus]] = text
                self.sel[PANELS[self.focus]] = 0
            elif text:
                self.run_command(text)
        elif tok in ("\x7f", "\b"):
            self.buffer = self.buffer[:-1]
            if self.mode == "search":
                self.query[PANELS[self.focus]] = self.buffer
        elif len(tok) == 1 and tok.isprintable() and len(self.buffer) < 200:
            self.buffer += tok
            if self.mode == "search":
                self.query[PANELS[self.focus]] = self.buffer

    def _overlay_key(self, tok: str) -> None:
        view = max(1, self.size_fn()[1] - 6)
        top = max(0, len(self.overlay) - view)
        if tok in ("q", "\x1b", "\r", "\n"):
            self.mode = "normal"
        elif tok in ("j", "\x1b[B"):
            self.overlay_scroll = min(top, self.overlay_scroll + 1)
        elif tok in ("k", "\x1b[A"):
            self.overlay_scroll = max(0, self.overlay_scroll - 1)
        elif tok == "\x1b[6~":
            self.overlay_scroll = min(top, self.overlay_scroll + view)
        elif tok == "\x1b[5~":
            self.overlay_scroll = max(0, self.overlay_scroll - view)

    # ------------------------------------------------------------------ actions
    def show(self, title: str, lines: list[str]) -> None:
        import textwrap

        width = max(20, self.size_fn()[0] - 6)
        wrapped: list[str] = []
        for x in lines:
            x = safe(x)
            wrapped += textwrap.wrap(x, width, subsequent_indent="    ", replace_whitespace=False, drop_whitespace=False) or [""]
        self.overlay_title, self.overlay, self.overlay_scroll, self.mode = title, wrapped, 0, "overlay"

    def _sources_lines(self) -> list[str]:
        lines = [f"{s.get('name', '?'):<28} {s.get('state', '?'):<8} {s.get('detail', '')}" for s in self.data.overview.get("sources", [])]
        return lines or ["Nothing is being watched yet."]

    def selected(self):
        rows = self.rows(PANELS[self.focus])
        return rows[min(self.sel[PANELS[self.focus]], len(rows) - 1)][2] if rows else None

    def open_row(self) -> None:
        item, panel = self.selected(), PANELS[self.focus]
        if item is None:
            return
        if panel == "incidents":
            from erinix.incidents import incident_detail
            try:
                store = self.open_store()
            except Exception:
                return
            try:
                detail = incident_detail(store, item["id"])
            finally:
                store.close()
            if detail is None:
                self.flash = "that incident is gone"
                return
            lines = [detail["headline"], "", detail["summary"], ""]
            if detail["next_steps"]:
                lines += ["What to do:"] + [f"  {i + 1}. {s}" for i, s in enumerate(detail["next_steps"])] + [""]
            lines += ["What happened:"] + [f"  {clock(e['time'])}  {e['label']}  {e['summary']}  {e.get('remote') or ''}" for e in detail["timeline"]]
            lines += ["", "Press x on the list to close this incident once you have dealt with it."]
            self.show(detail["headline"], lines)
        else:
            self.show(*self.detail(panel, item))

    def detail(self, panel: str, item: dict) -> tuple[str, list[str]]:
        """A readable card for one row, one fact per line."""
        yes = lambda v: "yes" if v else "no"
        unknown = "unknown (press R in the cockpit to see every program)"
        if panel == "ports":
            return f"Port {item.get('port')}", [f"Program:      {item.get('program') or unknown}", f"Address:      {item.get('local')}",
                    f"Open to the network: {yes(item.get('exposed'))}", f"User id:      {item.get('uid')}", f"Process id:   {item.get('pid') or '-'}"]
        if panel == "connections":
            return "Connection", [f"Program:      {item.get('program') or unknown}", f"From:         {item.get('local')}", f"To:           {item.get('remote')}",
                                  f"Outside your network: {yes(item.get('external'))}", f"User id:      {item.get('uid')}", f"Process id:   {item.get('pid') or '-'}"]
        if panel == "programs":
            return str(item.get("name", "Program")), [f"Process id:   {item.get('pid')}", f"Parent id:    {item.get('ppid')}", f"User id:      {item.get('uid')}",
                                                      "", "Command:", f"  {item.get('command', '')}"]
        if panel == "posture":
            states = {"fail": "Needs fixing", "warn": "Worth a look", "unknown": "Could not check", "info": "For your information"}
            lines = [str(item.get("title", "")), "", f"Result:   {states.get(item.get('state'), item.get('state'))}", f"Area:     {item.get('area')}", "", "What was found:", f"  {item.get('detail', '')}"]
            if item.get("fix"):
                lines += ["", "How to fix:", f"  {item['fix']}", "", "Erinix only looks. It never changes your system files."]
            return "Health check", lines
        if panel == "live":
            return str(item.get("label", "Event")), [f"Time:         {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(item.get('ts', 0))))}",
                    f"What:         {item.get('summary', '')}", f"From:         {item.get('remote') or '-'}",
                    f"Part of an attack: {yes(item.get('alert_id'))}" + (f" ({item.get('tag')})" if item.get("tag") else "")]
        return TITLES[panel], [f"{k}: {v}" for k, v in item.items()]

    def close_incident(self) -> None:
        item = self.selected() if PANELS[self.focus] == "incidents" else None
        if item is None:
            self.flash = "select an incident first (panel 1)"
            return
        from erinix.incidents import set_incident_status
        from erinix.store import Store
        try:
            store = Store()
            try:
                changed = set_incident_status(store, item["id"], "closed")
            finally:
                store.close()
        except Exception as exc:
            self.flash = f"cannot close it: {type(exc).__name__}"
            return
        self.flash = f"incident closed ({changed} alerts)"
        self.refresh(True)

    def run_command(self, text: str) -> None:
        """Run a normal Erinix command and show what it printed in an overlay."""
        if self.registry is None:
            self.flash = "commands are not available here"
            return
        import shlex

        from erinix.commands.registry import Context

        try:
            tokens = shlex.split(text)
        except ValueError:
            self.flash = "unbalanced quotes"
            return
        if not tokens:
            return
        if tokens[0] in ("exit", "quit"):
            self.done = True
            return
        if tokens[0] in ("watch", "serve", "demo"):
            self.flash = f"'{tokens[0]}' is not needed here: Erinix is already watching"
            return
        plain = Theme(0, self.theme.unicode, width=max(40, self.size_fn()[0] - 6))
        buf = io.StringIO()
        ctx = Context(plain, plain, buf, buf, emitter=lambda f: buf.write(f(plain.width) + "\n"))
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                self.registry.run(ctx, tokens)
        except SystemExit:
            pass
        except Exception as exc:
            buf.write(f"error: {type(exc).__name__}\n")
        lines = [term.strip_ansi(x) for x in buf.getvalue().splitlines()] or ["Done."]
        self.show(text, lines)
        self.refresh(True)

    def open_web(self) -> None:
        """Open the dashboard in the browser; the link is also shown and copied, in case no browser opens."""
        self.run_command("ui")
        url = next((w for line in self.overlay for w in line.split() if w.startswith("http://127.0.0.1:")), "")
        if url and self.out is not None and term.copy_to_clipboard(self.out, url):
            self.overlay.append("")
            self.overlay.append("The link is also copied: paste it into a browser if none opened.")

    # ---- mitigation: always shown first, never done without a y
    def ask(self, action: str, args: dict, title: str = "") -> None:
        from erinix import actions

        if self.service is None:
            self.flash = "actions are not available here"
            return
        try:
            plan = self.service.plan(action, args)
        except actions.ActionError as exc:
            self.flash = str(exc)
            return
        lines = list(plan.steps)
        if plan.warning:
            lines += ["", plan.warning]
        if plan.needs_root and not getattr(self.service.helper, "alive", False) and os.geteuid() != 0:
            lines += ["", "This needs root: press R first to give Erinix the root helper."]
        lines += ["", "Press y to do it, any other key to cancel."]
        self.show(plan.title, lines)
        self.mode = "confirm"
        self.pending = (action, plan.args if action != "kill" else plan.args, plan.title)

    def _confirm_key(self, tok: str) -> None:
        pending, self.pending, self.mode = self.pending, None, "normal"
        if tok != "y" or pending is None:
            self.flash = "cancelled, nothing was changed"
            return
        action, args, title = pending
        result = self.service.run_action(action, args, title)
        extra = []
        if result.get("ok") and result.get("n") and result.get("undo"):
            extra = ["", f"Written to the journal as #{result['n']}. Undo with:  :undo {result['n']}"]
        self.show("Done" if result.get("ok") else "Not done", [result.get("message", "")] + extra)
        self.refresh(True)

    def _remote_ip(self, item: dict) -> str:
        text = str(item.get("remote") or "")
        if text.startswith("["):                           # [v6]:port
            return text[1:].split("]")[0]
        return text.rsplit(":", 1)[0] if text.count(":") == 1 else text

    def act_block(self) -> None:
        item, panel = self.selected(), PANELS[self.focus]
        ip = ""
        if panel == "incidents" and item and not item.get("local"):
            ip = str(item.get("who", ""))
        elif panel in ("live", "connections") and item:
            ip = self._remote_ip(item)
        if not ip:
            self.flash = "select an incident, an event or a connection that comes from an address"
            return
        self.ask("block", {"ip": ip, "minutes": 60})

    def act_kill(self) -> None:
        item, panel = self.selected(), PANELS[self.focus]
        if panel not in ("programs", "ports", "connections") or not item or not isinstance(item.get("pid"), int):
            self.flash = "select a program (panel 6), a port or a connection that shows its program"
            return
        self.ask("kill", {"pid": item["pid"]})

    def act_fix(self) -> None:
        item = self.selected() if PANELS[self.focus] == "posture" else None
        if not item:
            self.flash = "select a row in the Health panel (3)"
            return
        self.ask("fix", {"check": str(item.get("id", ""))})

    def recheck(self) -> None:
        """Check the machine again now; the agent does it (with root's eyes when it has them) and the panel updates in a moment."""
        agent = getattr(self.runtime, "agent", None)
        if agent is None:
            self.run_command("assess --all")
            return
        agent.request_assessment()
        self.flash = "checking the machine again..."

    def elevate(self) -> None:
        if self.elevate_fn is None:
            self.flash = "already seeing everything" if getattr(self.runtime, "mode", "") == "full" else "this cannot be done here"
            return
        self.flash = self.elevate_fn() or ""
        rt = self.runtime
        if rt is not None and getattr(rt, "mode", "full") != "full" and self.flash not in ("cancelled", ""):
            self.show("Could not see every program", [self.flash, "", "Erinix keeps watching your own programs.", "",
                                                      "Things to try:", "  - run  sudo -v  in this terminal, then press R again",
                                                      "  - check that your user may use sudo", "  - or start with  erinix --elevate"])
            self.flash = ""
        self.refresh(True)

    # ------------------------------------------------------------------ the loop
    def draw(self) -> None:
        lines = self.render()
        if lines == self._last:                  # an unchanged screen is not repainted: repainting would clear a text selection
            return
        self._last = lines
        self.out.write("\x1b[H" + "\n".join(f"{ln}\x1b[K" for ln in lines))
        self.out.flush()

    def run(self, fd: int) -> int:
        reader = term.KeyReader(fd)
        self.refresh(True)
        stack = contextlib.ExitStack()
        self._stack, self._fd = stack, fd
        stack.enter_context(term.raw_input_mode(fd))
        stack.enter_context(term.fullscreen(self.out, mouse=False))
        try:
            self.out.write("\x1b[?25l")
            self.draw()
            last = None
            while not self.done:
                try:
                    tok = reader.read(timeout=0.25)
                except KeyboardInterrupt:
                    tok = "q"
                except EOFError:
                    break
                size = self.size_fn()
                changed = self.refresh() or size != last
                last = size
                if tok is not None:
                    if tok.startswith("\x1b[<"):          # mouse: ignored for now (wheel scrolls the selection)
                        ev = term.parse_mouse(tok)
                        if ev is not None and ev.button in (64, 65):
                            self.handle("\x1b[A" if ev.button == 64 else "j")
                    else:
                        self.handle(tok)
                    changed = True
                if changed:
                    self.draw()
        finally:
            self._stack.close()
        return 0

    @contextlib.contextmanager
    def suspended(self):
        """Give the terminal back (normal screen, normal input) for something that needs it, like a sudo password."""
        self._stack.close()
        try:
            yield
        finally:
            self._stack = contextlib.ExitStack()
            self._stack.enter_context(term.raw_input_mode(self._fd))
            self._stack.enter_context(term.fullscreen(self.out, mouse=False))
            self.out.write("\x1b[?25l")
            self._last = None
            self.draw()
