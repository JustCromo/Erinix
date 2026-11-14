"""The Erinix colours ("Stone and indigo") and the appearance setting shared by the dashboard and the console.

One palette, two variants: light (warm paper, indigo ink) and dark (warm stone, soft indigo ink).
The setting is only which variant to use: "auto" follows the system, "light" and "dark" force one.
The tests check the contrast of text, buttons and severity colours in both variants, so a pretty
palette can never become a tiring one. The choice lives in the shared store (meta "theme"):
change it anywhere, it changes everywhere.
"""

from __future__ import annotations

from typing import Mapping

DEFAULT = "auto"

LIGHT: Mapping[str, str] = {
    "bg": "#f6f1ea", "card": "#fffcf7", "card_2": "#faf6f0", "text": "#2b2420", "muted": "#6a5d54", "faint": "#6f6258",
    "border": "#e3d9ce", "primary": "#3f3a8c", "on_primary": "#ffffff", "accent": "#c77d5e",
    # severity: strong fills (badges, stripes) with the colour of the text that sits on them.
    # Green is only for "ok" (checks, all quiet); the identity colours are never green (green is Nemirix's)
    "ok": "#2a7a45", "low": "#566685", "medium": "#e9a21a", "high": "#cc4a0b", "critical": "#c4122f",
    "on_ok": "#ffffff", "on_low": "#ffffff", "on_medium": "#2b2420", "on_high": "#ffffff", "on_critical": "#ffffff",
    "medium_text": "#8f5b00",                                  # amber that stays readable as text on paper
    "shadow": "rgba(43, 36, 32, .10)",
}
DARK: Mapping[str, str] = {
    "bg": "#1b1716", "card": "#262120", "card_2": "#211c1b", "text": "#f3ede6", "muted": "#cfc3b8", "faint": "#b0a398",
    "border": "#3a3230", "primary": "#b9b4ff", "on_primary": "#1b1716", "accent": "#e8b4a0",
    "ok": "#6fcf8a", "low": "#a3b1d1", "medium": "#ffc247", "high": "#ff8447", "critical": "#ff5468",
    "on_ok": "#1b1716", "on_low": "#1b1716", "on_medium": "#1b1716", "on_high": "#1b1716", "on_critical": "#1b1716",
    "medium_text": "#ffc247",
    "shadow": "rgba(0, 0, 0, .35)",
}
VARIANTS: dict[str, Mapping[str, str]] = {"light": LIGHT, "dark": DARK}

MODES: dict[str, tuple[str, str]] = {
    "auto": ("Automatic", "Follows your system: light by day, dark at night."),
    "light": ("Light", "Warm paper and indigo ink."),
    "dark": ("Dark", "Warm stone and soft indigo ink."),
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
            "ok": _rgb(c["ok"]), "warn": _rgb(c["medium_text"]), "bad": _rgb(c["high"])}
    return {role: (rgb, rgb_to_256(rgb), BASE[role][2]) for role, rgb in rgbs.items()}
