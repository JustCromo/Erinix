"""The Erinix colours ("Plum and peach") and the appearance setting shared by the dashboard and the console.

One palette, two variants: light (peach paper, plum ink) and dark (night plum, peach ink).
The setting is only which variant to use: "auto" follows the system, "light" and "dark" force one.
The tests check the contrast of text, buttons and severity colours in both variants, so a pretty
palette can never become a tiring one. The choice lives in the shared store (meta "theme"):
change it anywhere, it changes everywhere.
"""

from __future__ import annotations

from typing import Mapping

DEFAULT = "auto"

LIGHT: Mapping[str, str] = {
    "bg": "#fbede4", "card": "#fff8f3", "card_2": "#fbf0e8", "text": "#2e1b33", "muted": "#6f5775", "faint": "#735d79",
    "border": "#ebd3c8", "primary": "#7a2f7d", "on_primary": "#ffffff", "accent": "#f29a76",
    "ok": "#3f7d4e", "low": "#427088", "medium": "#9a6414", "high": "#b8481f", "critical": "#a63232", "on_critical": "#ffffff",
    "shadow": "rgba(46, 27, 51, .10)",
}
DARK: Mapping[str, str] = {
    "bg": "#1c1022", "card": "#28172f", "card_2": "#22132a", "text": "#f6e8f0", "muted": "#bba0c2", "faint": "#a58fae",
    "border": "#43284d", "primary": "#ff9e7d", "on_primary": "#1c1022", "accent": "#c77ddb",
    "ok": "#7fc08e", "low": "#7fb0c8", "medium": "#e0ae4a", "high": "#e88b5f", "critical": "#f07a7a", "on_critical": "#1c1022",
    "shadow": "rgba(0, 0, 0, .35)",
}
VARIANTS: dict[str, Mapping[str, str]] = {"light": LIGHT, "dark": DARK}

MODES: dict[str, tuple[str, str]] = {
    "auto": ("Automatic", "Follows your system: light by day, dark at night."),
    "light": ("Light", "Peach paper and plum ink."),
    "dark": ("Dark", "Night plum and peach ink."),
}


def _block(selector: str, colors: Mapping[str, str], scheme: str) -> str:
    body = "".join(f"  --{k.replace('_', '-')}: {v};\n" for k, v in colors.items())
    return f"{selector} {{\n{body}  color-scheme: {scheme};\n}}\n"


def css() -> str:
    """Both variants as CSS variables. Without a choice the system decides; data-theme forces one."""
    dark_auto = _block(':root:not([data-theme="light"])', DARK, "dark").replace("\n", "\n  ").rstrip(" ")
    return ("/* generated from erinix/palettes.py */\n"
            + _block(":root", LIGHT, "light dark")
            + "@media (prefers-color-scheme: dark) {\n  " + dark_auto + "}\n"
            + _block(':root[data-theme="light"]', LIGHT, "light")
            + _block(':root[data-theme="dark"]', DARK, "dark"))


def is_known(name: object) -> bool:
    return isinstance(name, str) and name in MODES


def stored_name(path=None) -> str:
    """The appearance chosen by the user (kept in the shared store), or the default. Never fails."""
    import os

    from erinix.store import Store, StoreError

    forced = os.environ.get("ERINIX_THEME")
    if is_known(forced):
        return forced                                     # type: ignore[return-value]
    try:
        with Store(path, readonly=True) as store:
            name = store.get_meta("theme", None)
    except (StoreError, OSError, ValueError):
        return DEFAULT
    return name if is_known(name) else DEFAULT


def info() -> list[dict]:
    """What the picker shows: name, label, blurb and four swatches."""
    out = []
    for name, (label, blurb) in MODES.items():
        a, b = (LIGHT, DARK) if name == "auto" else ((DARK, DARK) if name == "dark" else (LIGHT, LIGHT))
        swatch = [a["bg"], a["primary"], b["card"], b["accent"]] if name == "auto" else [a["bg"], a["card"], a["primary"], a["accent"]]
        out.append({"name": name, "label": label, "blurb": blurb, "swatch": swatch})
    return out


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
def console_roles(name: str | None = None) -> dict[str, tuple[tuple[int, int, int], int, int]]:
    """Colour roles of the terminal theme. Terminals are mostly dark, so they always use the dark variant."""
    from erinix.ui.theme import PALETTE as BASE, rgb_to_256

    c = DARK

    def mix(a: str, b: str, t: float) -> tuple[int, int, int]:
        (r1, g1, b1), (r2, g2, b2) = _rgb(a), _rgb(b)
        return round(r1 + (r2 - r1) * t), round(g1 + (g2 - g1) * t), round(b1 + (b2 - b1) * t)

    rgbs = {"accent": _rgb(c["primary"]), "brown": _rgb(c["muted"]), "border": mix(c["muted"], c["card"], 0.55), "dim": _rgb(c["faint"]),
            "ok": _rgb(c["ok"]), "warn": _rgb(c["medium"]), "bad": _rgb(c["high"])}
    return {role: (rgb, rgb_to_256(rgb), BASE[role][2]) for role, rgb in rgbs.items()}
