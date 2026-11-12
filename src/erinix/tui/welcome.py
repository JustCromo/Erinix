"""Welcome screen: information box on the left, mascot on the right."""

from __future__ import annotations

import os
import shutil
import textwrap
from dataclasses import dataclass

from erinix import __version__
from erinix.sensors import selector
from erinix.tui import mascot
from erinix.ui.render import Seg, banner_segs, box
from erinix.ui.theme import Theme

MODE_NAMES = {"ebpf": "eBPF (CO-RE)", "auditd": "auditd", "minimal": "minimal"}
RIGHT_WIDTH = mascot.WIDTH + 6
LEFT_MAX = 74
MIN_TWO_PANELS = 96

COMMANDS = (
    ("help", "Explore available commands and options"),
    ("status", "See what needs your attention"),
    ("alerts", "List the alerts, then: alert 1"),
    ("ui", "Open the web dashboard"),
    ("demo", "Load simulated attacks to try Erinix"),
    ("doctor", "Check what Erinix can use on this machine"),
    ("clear", "Refresh this welcome screen (Ctrl-L)"),
)
INTRO = (
    "Chain-based intrusion detection for Linux hosts.",
    "Progressive alerts. Careful, declared response.",
    "When it cannot see, it says so: silence is never an all-clear.",
)
ABOUT = ("Erinix correlates host events into attack chains (service, shell, connection, "
         "root). It tells attacks apart from normal activity and always states what it cannot see.")


@dataclass(frozen=True, slots=True)
class SessionInfo:
    euid: int
    mode: str            # readable name of the sensor in use now
    potential: str       # readable name of the sensor with root privileges
    rootless: bool
    launch: str          # command to start with privileges
    state: str = ""      # one-line live state read from the store

    @property
    def status_text(self) -> str:
        return f"sensor {self.mode}" + (" (rootless)" if self.rootless else "")


def session_info() -> SessionInfo:
    from erinix.summary import live_state

    plan = selector.choose(selector.detect())
    exe = shutil.which("erinix") or "erinix"
    return SessionInfo(os.geteuid(), MODE_NAMES[plan.mode.value], MODE_NAMES[plan.potential.value],
                       plan.rootless, f"sudo {exe}", live_state()[1])


def _left(theme: Theme, width: int, info: SessionInfo) -> list[str]:
    star = theme.glyph("star")
    inner = max(20, width - 4)
    title = [Seg(f"{star} ERINIX {theme.glyph('dot')} LINUX HOST INTRUSION DETECTION", "accent", True)]

    def head(label: str) -> list[Seg]:
        return [Seg(f"{star} {label}", "accent", True)]

    cw = max(len(c) for c, _ in COMMANDS) + 2
    lw = len("PRIVILEGES") + 2
    mode = ("ROOTLESS" if info.rootless else "ROOT") + f" {theme.glyph('dot')} UID {info.euid}"
    sensor = info.mode.upper() + ("" if not info.rootless else f" {theme.glyph('dot')} with root: {info.potential}")
    session: list[list[Seg]] = [
        [Seg("STATE".ljust(lw), "accent", True), Seg(info.state or "No data yet")],
        [Seg("MODE".ljust(lw), "accent", True), Seg(mode)],
        [Seg("SENSOR".ljust(lw), "accent", True), Seg(sensor)],
    ]
    if info.rootless:
        session += [[Seg("PRIVILEGES".ljust(lw), "accent", True), Seg("Detection and response need elevated access")],
                    [Seg(" " * lw), Seg("Start with: "), Seg(info.launch, "accent")]]
    else:
        session.append([Seg("PRIVILEGES".ljust(lw), "accent", True), Seg("Full access: sensors and response available")])
    sections = [
        (None, [[Seg(t)] for t in INTRO]),
        (head("ABOUT"), [[Seg(t)] for t in textwrap.wrap(ABOUT, inner)]),
        (head("QUICK START"), [[Seg(c.ljust(cw), "accent", True), Seg(d)] for c, d in COMMANDS]),
        (head("SESSION"), session),
    ]
    return box(theme, title, sections, width=width, border="brown")


def _right(theme: Theme, height: int) -> list[str]:
    star = theme.glyph("star")
    art = mascot.lines(theme) or banner_segs(theme, __version__)
    inner_rows = max(len(art), height - 4)
    top = (inner_rows - len(art)) // 2
    width = RIGHT_WIDTH - 4
    centered = []
    for row in art:
        used = sum(len(s.text) for s in row)
        centered.append([Seg(" " * max(0, (width - used) // 2)), *row])
    lines = [[] for _ in range(top)] + centered + [[] for _ in range(inner_rows - top - len(art))]
    title = [Seg(f"{star} ERINIX {star}", "accent", True)]
    caption = [Seg(f"SPINES UP {theme.glyph('dot')} EYES OPEN", "accent", True)]
    return box(theme, title, [(None, lines)], width=RIGHT_WIDTH, border="brown", caption=caption)


def build(theme: Theme, width: int, info: SessionInfo) -> list[str]:
    """Lines of the screen (already colored) for a terminal `width` columns wide."""
    if width >= MIN_TWO_PANELS:
        left_w = min(LEFT_MAX, width - RIGHT_WIDTH - 3)
        left = _left(theme, left_w, info)
        right = _right(theme, len(left))
        gap = width - left_w - RIGHT_WIDTH
        rows = max(len(left), len(right))
        blank_l, blank_r = " " * left_w, " " * RIGHT_WIDTH
        return [(left[i] if i < len(left) else blank_l) + " " * gap + (right[i] if i < len(right) else blank_r)
                for i in range(rows)]
    return _left(theme, min(LEFT_MAX, max(40, width - 1)), info)
