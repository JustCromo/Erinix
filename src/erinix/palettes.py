"""Colour palettes for the whole product: the dashboard and the console draw from the same definitions.

Every palette is cozy and readable: the tests check the contrast of text, accent and severity
colours against the background, so a pretty palette can never become a tiring one.
The chosen name lives in the shared store (meta "palette"): change it anywhere, it changes everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

DEFAULT = "cacao"
_DARK_GLASS = dict(glass_hi="rgba(255,255,255,.13)", glass="rgba(255,255,255,.075)", glass_soft="rgba(255,255,255,.045)",
                   edge="rgba(255,255,255,.17)", hl="rgba(255,255,255,.22)", shadow="rgba(0,0,0,.40)")
_LIGHT_GLASS = dict(glass_hi="rgba(255,255,255,.78)", glass="rgba(255,255,255,.58)", glass_soft="rgba(255,255,255,.42)",
                    edge="rgba(110,80,50,.20)", hl="rgba(255,255,255,.9)", shadow="rgba(90,60,30,.18)")


@dataclass(frozen=True, slots=True)
class Palette:
    name: str
    label: str
    blurb: str
    dark: bool
    colors: Mapping[str, str]
    console_of: str | None = None          # a light palette borrows its dark sibling for the (dark) terminal

    def css_block(self, selector: str) -> str:
        body = "".join(f"  --{k.replace('_', '-')}: {v};\n" for k, v in self.colors.items())
        return f"{selector} {{\n{body}  color-scheme: {'dark' if self.dark else 'light'};\n}}\n"


def _p(name, label, blurb, dark, colors, console_of=None):
    return Palette(name, label, blurb, dark, {**(_DARK_GLASS if dark else _LIGHT_GLASS), **colors}, console_of)


PALETTES: dict[str, Palette] = {p.name: p for p in (
    _p("cacao", "Cacao e caramello", "Marrone caldo, panna e caramello: come un caffè d'inverno.", True, dict(
        bg_0="#1a120d", bg_1="#2a1c14", aura_1="rgba(232,166,106,.30)", aura_2="rgba(168,126,98,.26)", aura_3="rgba(190,214,160,.12)",
        text="#f8eee1", muted="#cdb9a3", faint="#a08a76", accent="#e8a66a", accent_2="#f3c48f", accent_ink="#2a1608", moss="#a9c98a",
        bark="#d9b48b", low="#a9c98a", medium="#f1c76b", high="#ee8f6a", critical="#f0626e", ink_soft="rgba(20,10,4,.40)")),
    _p("miele", "Muschio e miele", "Verde muschio morbido con il giallo del miele: calmo e naturale.", True, dict(
        bg_0="#121a12", bg_1="#1c281b", aura_1="rgba(242,184,75,.32)", aura_2="rgba(120,160,100,.28)", aura_3="rgba(220,200,150,.12)",
        text="#f4f1e3", muted="#bfc7b0", faint="#8f9a7e", accent="#f2b84b", accent_2="#f7d27f", accent_ink="#231a05", moss="#a7d17a",
        bark="#d8c08a", low="#a7d17a", medium="#f2c14e", high="#f08c52", critical="#f2566a", ink_soft="rgba(8,14,8,.40)")),
    _p("prugna", "Prugna e pesca", "Viola di sera con un tocco di pesca: moderna e accogliente.", True, dict(
        bg_0="#17101f", bg_1="#251a31", aura_1="rgba(255,158,138,.34)", aura_2="rgba(150,120,210,.30)", aura_3="rgba(255,214,170,.12)",
        text="#f7eef5", muted="#cbbad1", faint="#9d8da6", accent="#ff9e8a", accent_2="#ffc2b0", accent_ink="#2a0f0a", moss="#9fdcb4",
        bark="#e3b7c9", low="#9fdcb4", medium="#ffd27a", high="#ff8f6b", critical="#ff5d7a", ink_soft="rgba(14,6,20,.42)")),
    _p("nebbia", "Nebbia e sabbia", "Verde-azzurro nebbioso con la sabbia: riposante, quasi marino.", True, dict(
        bg_0="#0d1a1f", bg_1="#142a31", aura_1="rgba(127,214,194,.30)", aura_2="rgba(90,140,190,.26)", aura_3="rgba(230,205,160,.14)",
        text="#eef5f2", muted="#b4c7c6", faint="#869c9c", accent="#7fd6c2", accent_2="#a9e8d8", accent_ink="#06201b", moss="#9fe0a0",
        bark="#e0cba0", low="#9fe0a0", medium="#f5cf72", high="#ff9468", critical="#ff5f6d", ink_soft="rgba(3,14,18,.42)")),
    _p("autunno", "Falò d'autunno", "Bordeaux e ruggine con l'ambra del fuoco: caldo e deciso.", True, dict(
        bg_0="#1c0f10", bg_1="#2e1618", aura_1="rgba(245,158,63,.34)", aura_2="rgba(190,70,70,.28)", aura_3="rgba(205,170,110,.14)",
        text="#fbefe3", muted="#d3b9aa", faint="#a68c7d", accent="#f59e3f", accent_2="#fbc274", accent_ink="#2b1304", moss="#b6c97a",
        bark="#dcae83", low="#b6c97a", medium="#f6c860", high="#f0875a", critical="#ff5a64", ink_soft="rgba(24,8,8,.42)")),
    _p("bosco", "Bosco di notte", "Verde notte e arancio del riccio (la palette di prima).", True, dict(
        bg_0="#08130d", bg_1="#0e2018", aura_1="rgba(255,138,61,.36)", aura_2="rgba(92,176,96,.30)", aura_3="rgba(201,160,108,.16)",
        text="#f6f0e5", muted="#b7c2b1", faint="#8f9c83", accent="#ff8a3d", accent_2="#ffb36b", accent_ink="#1e1106", moss="#9bd66b",
        bark="#d4a76f", low="#9bd66b", medium="#ffc247", high="#ff7a4d", critical="#ff4d5e", ink_soft="rgba(5,12,8,.38)")),
    _p("latte", "Latte (chiara)", "Panna e terracotta su fondo chiaro: luminosa, per chi preferisce il giorno.", False, dict(
        bg_0="#f4ede2", bg_1="#e8dccb", aura_1="rgba(214,140,92,.38)", aura_2="rgba(150,175,130,.34)", aura_3="rgba(236,196,146,.36)",
        text="#33241a", muted="#665343", faint="#7d6a58", accent="#b9551f", accent_2="#d9895a", accent_ink="#fff8f0", moss="#3f7a3d",
        bark="#7e5a3c", low="#3f7a3d", medium="#9a6a0c", high="#bd4617", critical="#be2236", ink_soft="rgba(255,255,255,.50)"),
       console_of="cacao"),
)}


def get(name: str | None) -> Palette:
    return PALETTES.get(name or "", PALETTES[DEFAULT])


def stored_name(path=None) -> str:
    """The palette chosen by the user (kept in the shared store), or the default. Never fails."""
    import os

    from erinix.store import Store, StoreError

    forced = os.environ.get("ERINIX_PALETTE")
    if is_known(forced):
        return forced                                     # type: ignore[return-value]
    try:
        with Store(path, readonly=True) as store:
            name = store.get_meta("palette", None)
    except (StoreError, OSError, ValueError):
        return DEFAULT
    return name if is_known(name) else DEFAULT


def is_known(name: object) -> bool:
    return isinstance(name, str) and name in PALETTES


def info() -> list[dict]:
    """What the picker shows: name, label, blurb and a few swatches."""
    out = []
    for p in PALETTES.values():
        c = p.colors
        out.append({"name": p.name, "label": p.label, "blurb": p.blurb, "dark": p.dark,
                    "swatch": [c["bg_1"], c["accent"], c["moss"], c["bark"]]})
    return out


def css() -> str:
    """All palettes as CSS variables. The default is also on :root, so the first paint already has colours."""
    parts = [PALETTES[DEFAULT].css_block(":root")]
    parts += [p.css_block(f':root[data-palette="{p.name}"]') for p in PALETTES.values()]
    return "/* generated from erinix/palettes.py */\n" + "".join(parts)


# ------------------------------------------------------------------ contrast
def _rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def luminance(hex_color: str) -> float:
    def channel(v: int) -> float:
        s = v / 255
        return s / 12.92 if s <= 0.03928 else ((s + 0.055) / 1.055) ** 2.4
    r, g, b = _rgb(hex_color)
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


# ------------------------------------------------------------------- console
def console_roles(name: str | None) -> dict[str, tuple[tuple[int, int, int], int, int]]:
    """Colour roles of the terminal theme, taken from the palette (a light palette uses its dark sibling)."""
    from erinix.ui.theme import PALETTE as BASE, rgb_to_256

    p = get(name)
    if p.console_of:
        p = get(p.console_of)
    c = p.colors

    def mix(a: str, b: str, t: float) -> tuple[int, int, int]:
        (r1, g1, b1), (r2, g2, b2) = _rgb(a), _rgb(b)
        return round(r1 + (r2 - r1) * t), round(g1 + (g2 - g1) * t), round(b1 + (b2 - b1) * t)

    rgbs = {"accent": _rgb(c["accent"]), "brown": _rgb(c["bark"]), "border": mix(c["bark"], c["bg_1"], 0.55), "dim": _rgb(c["faint"]),
            "ok": _rgb(c["low"]), "warn": _rgb(c["medium"]), "bad": _rgb(c["high"])}
    return {role: (rgb, rgb_to_256(rgb), BASE[role][2]) for role, rgb in rgbs.items()}
