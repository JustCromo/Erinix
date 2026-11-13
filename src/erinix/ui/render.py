"""Tables, panels, bars and banner for the console, with no dependencies.

Security: EVERY text goes through `safe()` before being printed, because it can
come from hostile files or processes (no escape sequences injected into the
terminal). Widths are computed on the plain text, never on the colored one.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Sequence, Union

from erinix.ui.theme import Theme

MIN_COL = 6
NARROW_COL = 2
_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def safe(text: object) -> str:
    """Make any text safely printable (control characters are escaped)."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(text))


def display_width(text: str) -> int:
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


@dataclass(frozen=True, slots=True)
class Seg:
    """A fragment of text with its color role."""

    text: str
    role: str | None = None
    bold: bool = False
    fg: tuple[int, int, int] | None = None
    bg: tuple[int, int, int] | None = None


Cell = Union[str, Seg, Sequence[Seg]]


def segs(cell: Cell) -> list[Seg]:
    if isinstance(cell, str):
        return [Seg(safe(cell))]
    if isinstance(cell, Seg):
        return [Seg(safe(cell.text), cell.role, cell.bold, cell.fg, cell.bg)]
    return [Seg(safe(s.text), s.role, s.bold, s.fg, s.bg) for s in cell]


def seg_width(parts: Sequence[Seg]) -> int:
    return sum(display_width(s.text) for s in parts)


def fit(parts: Sequence[Seg], width: int, ell: str) -> list[Seg]:
    """Truncate to `width` visible characters, adding the ellipsis."""
    if width <= 0:
        return []
    if seg_width(parts) <= width:
        return list(parts)
    if display_width(ell) >= width:
        return [Seg(ell[:width])]
    budget = width - display_width(ell)
    out: list[Seg] = []
    last: Seg | None = None
    for s in parts:
        piece: list[str] = []
        stop = False
        for ch in s.text:
            cw = display_width(ch)
            if cw > budget:
                stop = True
                break
            piece.append(ch)
            budget -= cw
        if piece:
            out.append(Seg("".join(piece), s.role, s.bold, s.fg, s.bg))
            last = s
        if stop:
            break
    out.append(Seg(ell, last.role if last else None))
    return out


def paint_segs(theme: Theme, parts: Sequence[Seg]) -> str:
    return "".join(theme.paint(s.text, s.role, s.bold, fg=s.fg, bg=s.bg) for s in parts)


def merge(parts: Sequence[Seg]) -> list[Seg]:
    """Merge adjacent fragments with the same style (fewer sequences to print)."""
    out: list[Seg] = []
    for s in parts:
        if out and (out[-1].role, out[-1].bold, out[-1].fg, out[-1].bg) == (s.role, s.bold, s.fg, s.bg):
            out[-1] = Seg(out[-1].text + s.text, s.role, s.bold, s.fg, s.bg)
        else:
            out.append(s)
    return out


def table(theme: Theme, headers: Sequence[str], rows: Sequence[Sequence[Cell]],
          *, width: int | None = None) -> str:
    width = width or theme.width
    n = len(headers)
    head = [[Seg(safe(h), "accent", True)] for h in headers]
    body = [[segs(c) for c in row] for row in rows]
    for row in body:
        if len(row) != n:
            raise ValueError("row with a different number of columns than the header")
    widths = [max([seg_width(head[i])] + [seg_width(r[i]) for r in body]) for i in range(n)]
    excess = sum(widths) + 3 * n + 1 - width
    for floor in (MIN_COL, NARROW_COL):          # on very narrow terminals squeeze columns further rather than overflow
        while excess > 0:
            i = max(range(n), key=lambda k: widths[k])
            if widths[i] <= floor:
                break
            cut = min(excess, widths[i] - floor)
            widths[i] -= cut
            excess -= cut

    g = theme.glyph
    ell = g("ell")

    def b(text: str) -> str:
        return theme.paint(text, "border")

    def rule(left: str, mid: str, right: str) -> str:
        return b(g(left) + g(mid).join(g("h") * (w + 2) for w in widths) + g(right))

    def line(cells: Sequence[Sequence[Seg]]) -> str:
        parts = []
        for cell, w in zip(cells, widths):
            f = fit(cell, w, ell)
            parts.append(" " + paint_segs(theme, f) + " " * (w - seg_width(f)) + " ")
        return b(g("v")) + b(g("v")).join(parts) + b(g("v"))

    out = [rule("tl", "tt", "tr"), line(head), rule("lt", "x", "rt")]
    out += [line(r) for r in body]
    out.append(rule("bl", "bt", "br"))
    return "\n".join(out)


def panel(theme: Theme, title: Sequence[Seg], lines: Sequence[Sequence[Seg]],
          *, right: Sequence[Seg] = (), width: int | None = None, border: str = "border") -> str:
    width = width or theme.width
    g = theme.glyph
    ell = g("ell")

    def b(text: str) -> str:
        return theme.paint(text, border)

    rw = seg_width(right)
    # Fixed width of the top border: "╭─ " + title + " " + fill
    # [+ " " + right + " "] + "─╮"  ->  6 characters + optional right part.
    reserve = 6 + (rw + 2 if right else 0)
    t = fit(title, max(1, width - reserve - 1), ell)
    fill = max(1, width - (seg_width(t) + reserve))
    top = (b(g("tl") + g("h") + " ") + paint_segs(theme, t) + b(" " + g("h") * fill))
    if right:
        top += b(" ") + paint_segs(theme, right) + b(" ")
    top += b(g("h") + g("tr"))
    inner = width - 4
    out = [top]
    for ln in lines:
        f = fit(ln, inner, ell)
        out.append(b(g("v") + " ") + paint_segs(theme, f) + " " * (inner - seg_width(f)) + b(" " + g("v")))
    out.append(b(g("bl") + g("h") * (width - 2) + g("br")))
    return "\n".join(out)


def progress(theme: Theme, done: int, total: int) -> list[Seg]:
    return [Seg(theme.glyph("full") * done, "accent"), Seg(theme.glyph("empty") * (total - done), "border")]


def banner_segs(theme: Theme, version: str, columns: int = 52) -> list[list[Seg]]:
    n = max(8, min(theme.width, columns) // 2)
    cycle = ("border", "brown", "accent", "brown")
    top = [Seg("/\\", cycle[i % 4]) for i in range(n)]
    bottom = [Seg("\\/", cycle[(n - 1 - i) % 4]) for i in range(n)]
    title = [Seg("  E R I N I X", "accent", True), Seg("   host-based IDS", "brown")]
    sub = [Seg("  Nemirix suite " + theme.glyph("dot") + " v" + version, "dim")]
    return [top, title, sub, bottom]


def banner(theme: Theme, version: str) -> list[str]:
    return [paint_segs(theme, p) for p in banner_segs(theme, version)]


Section = tuple["Sequence[Seg] | None", "Sequence[Sequence[Seg]]"]


def box(theme: Theme, title: Sequence[Seg], sections: Sequence[Section], *, width: int,
        border: str = "brown", caption: Sequence[Seg] = ()) -> list[str]:
    """Box with a title, sections separated by headed rules, and a caption at the bottom.

    Each section is (heading | None, lines). Returns the already-colored lines,
    all `width` columns wide, so they can be placed side by side with other boxes.
    """
    g = theme.glyph
    ell = g("ell")
    inner = max(1, width - 4)

    def b(text: str) -> str:
        return theme.paint(text, border)

    def head(left: str, right: str, label: Sequence[Seg]) -> str:
        t = fit(label, max(1, width - 7), ell)
        fill = max(1, width - (seg_width(t) + 5))
        return b(g(left) + g("h") + " ") + paint_segs(theme, t) + b(" " + g("h") * fill + g(right))

    def row(line: Sequence[Seg]) -> str:
        f = fit(line, inner, ell)
        return b(g("v") + " ") + paint_segs(theme, f) + " " * (inner - seg_width(f)) + b(" " + g("v"))

    out = [head("tl", "tr", title)]
    for index, (heading, lines) in enumerate(sections):
        if heading is not None:
            out.append(head("lt", "rt", heading))
        if index == 0:
            out.append(row([]))
        out.extend(row(line) for line in lines)
        out.append(row([]))
    if caption:
        c = fit(caption, max(1, width - 9), ell)
        fill = max(1, width - (seg_width(c) + 6))
        out.append(b(g("bl") + g("h") * fill + " ") + paint_segs(theme, c) + b(" " + g("h") * 2 + g("br")))
    else:
        out.append(b(g("bl") + g("h") * (width - 2) + g("br")))
    return out
