"""Schermata di benvenuto: riquadro informativo a sinistra, mascotte a destra."""

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

MODE_NAMES = {"ebpf": "eBPF (CO-RE)", "auditd": "auditd", "minimal": "minimale"}
RIGHT_WIDTH = mascot.WIDTH + 6
LEFT_MAX = 74
MIN_TWO_PANELS = 96

COMMANDS = (
    ("help", "Elenco dei comandi e delle opzioni"),
    ("doctor", "Controlla cosa può usare Erinix qui"),
    ("rules list", "Elenca le regole caricate"),
    ("replay", "Rigioca un attacco simulato"),
    ("clear", "Ripulisce lo schermo (Ctrl-L)"),
)
INTRO = (
    "Rilevamento di catene d'attacco su host Linux.",
    "Alert progressivi. Risposta prudente e dichiarata.",
    "Quando non vede, lo dice: il silenzio non è mai un via libera.",
)
ABOUT = ("Erinix correla gli eventi dell'host in catene d'attacco (servizio, shell, connessione, "
         "root). Distingue gli attacchi dall'attività normale e dichiara sempre cosa non riesce a vedere.")


@dataclass(frozen=True, slots=True)
class SessionInfo:
    euid: int
    mode: str            # nome leggibile del sensore in uso ora
    potential: str       # nome leggibile del sensore con i privilegi di root
    rootless: bool
    launch: str          # comando per avviare con privilegi

    @property
    def status_text(self) -> str:
        return f"sensore {self.mode}" + (" (rootless)" if self.rootless else "")


def session_info() -> SessionInfo:
    plan = selector.choose(selector.detect())
    exe = shutil.which("erinix") or "erinix"
    return SessionInfo(os.geteuid(), MODE_NAMES[plan.mode.value], MODE_NAMES[plan.potential.value],
                       plan.rootless, f"sudo {exe}")


def _left(theme: Theme, width: int, info: SessionInfo) -> list[str]:
    star = theme.glyph("star")
    inner = max(20, width - 4)
    title = [Seg(f"{star} ERINIX {theme.glyph('dot')} RILEVAMENTO INTRUSIONI SU LINUX", "accent", True)]

    def head(label: str) -> list[Seg]:
        return [Seg(f"{star} {label}", "accent", True)]

    cw = max(len(c) for c, _ in COMMANDS) + 2
    lw = len("PRIVILEGI") + 2
    mode = ("ROOTLESS" if info.rootless else "ROOT") + f" {theme.glyph('dot')} UID {info.euid}"
    sensor = info.mode.upper() + ("" if not info.rootless else f" {theme.glyph('dot')} con root: {info.potential}")
    session: list[list[Seg]] = [
        [Seg("MODALITÀ".ljust(lw), "accent", True), Seg(mode)],
        [Seg("SENSORE".ljust(lw), "accent", True), Seg(sensor)],
    ]
    if info.rootless:
        session += [[Seg("PRIVILEGI".ljust(lw), "accent", True), Seg("Senza root Erinix è solo osservatore")],
                    [Seg(" " * lw), Seg("Avvia con: "), Seg(info.launch, "accent")]]
    else:
        session.append([Seg("PRIVILEGI".ljust(lw), "accent", True), Seg("Completi: sensori e risposta disponibili")])
    sections = [
        (None, [[Seg(t)] for t in INTRO]),
        (head("INFO"), [[Seg(t)] for t in textwrap.wrap(ABOUT, inner)]),
        (head("AVVIO RAPIDO"), [[Seg(c.ljust(cw), "accent", True), Seg(d)] for c, d in COMMANDS]),
        (head("SESSIONE"), session),
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
    caption = [Seg(f"PUNTE ALTE {theme.glyph('dot')} OCCHI APERTI", "accent", True)]
    return box(theme, title, [(None, lines)], width=RIGHT_WIDTH, border="brown", caption=caption)


def build(theme: Theme, width: int, info: SessionInfo) -> list[str]:
    """Righe della schermata (già colorate) per un terminale largo `width`."""
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
