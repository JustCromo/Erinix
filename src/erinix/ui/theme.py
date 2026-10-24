"""Color theme of Erinix.

Information and highlights in hedgehog tones (browns and a cold orange);
everything else stays in the terminal's default color; red/green/yellow are
reserved for alerts (traffic light), tuned to sit well next to the browns.

Terminal support: truecolor, 256 colors, 16 colors, no color.
NO_COLOR is respected; ERINIX_COLOR=always|never|auto forces the choice.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Mapping, TextIO

# role -> (truecolor RGB, 256-color index, 16-color SGR code)
PALETTE: Mapping[str, tuple[tuple[int, int, int], int, int]] = {
    "accent": ((226, 122, 63), 173, 33),    # cold orange: highlights, titles
    "brown": ((176, 136, 102), 137, 33),    # light brown: information
    "border": ((124, 96, 74), 94, 90),      # dark brown: borders, decorations
    "dim": ((150, 138, 126), 245, 90),      # secondary
    "ok": ((125, 170, 92), 107, 32),        # green
    "warn": ((227, 179, 65), 179, 93),      # amber yellow
    "bad": ((224, 86, 75), 167, 91),        # red
}
# Maximum severity: bold white on a red background.
_CRIT = {3: "1;38;2;255;255;255;48;2;184;48;42", 2: "1;38;5;231;48;5;124", 1: "1;97;41"}

MIN_WIDTH, MAX_WIDTH = 60, 120

_UNICODE = {"tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│", "lt": "├",
            "rt": "┤", "tt": "┬", "bt": "┴", "x": "┼", "ok": "✔", "warn": "▲", "bad": "✖",
            "full": "█", "empty": "░", "ell": "…", "prompt": "▸", "arrow": "→", "dot": "·",
            "star": "✦"}
_ASCII = {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|", "lt": "+",
          "rt": "+", "tt": "+", "bt": "+", "x": "+", "ok": "OK", "warn": "!!", "bad": "XX",
          "full": "#", "empty": "-", "ell": "...", "prompt": ">", "arrow": "->", "dot": "-",
          "star": "*"}


def rgb_to_256(rgb: tuple[int, int, int]) -> int:
    """Nearest color in the 6x6x6 cube of the 256-color palette."""
    def level(v: int) -> int:
        return 0 if v < 48 else 1 if v < 115 else min(5, (v - 35) // 40)
    r, g, b = rgb
    return 16 + 36 * level(r) + 6 * level(g) + level(b)


def detect_color_level(stream: TextIO | None = None, env: Mapping[str, str] | None = None) -> int:
    """0 = no color, 1 = 16 colors, 2 = 256 colors, 3 = truecolor."""
    env = os.environ if env is None else env
    stream = sys.stdout if stream is None else stream
    pref = env.get("ERINIX_COLOR", "auto").lower()
    if pref == "never":
        return 0
    if pref != "always":
        if env.get("NO_COLOR"):
            return 0
        if not (hasattr(stream, "isatty") and stream.isatty()):
            return 0
    term = env.get("TERM", "")
    if term == "dumb":
        return 0
    if env.get("COLORTERM", "").lower() in ("truecolor", "24bit"):
        return 3
    if "256" in term:
        return 2
    return 1


def detect_unicode(stream: TextIO | None = None) -> bool:
    stream = sys.stdout if stream is None else stream
    enc = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
    return enc == "utf8"


class Theme:
    def __init__(self, color_level: int = 0, unicode: bool = True, width: int | None = None) -> None:
        self.color_level = color_level
        self.unicode = unicode
        self._width = width

    @classmethod
    def from_stream(cls, stream: TextIO | None = None, env: Mapping[str, str] | None = None) -> "Theme":
        return cls(detect_color_level(stream, env), detect_unicode(stream))

    @property
    def width(self) -> int:
        if self._width is not None:
            return self._width
        columns = shutil.get_terminal_size((100, 24)).columns
        return max(MIN_WIDTH, min(MAX_WIDTH, columns))

    def glyph(self, name: str) -> str:
        return (_UNICODE if self.unicode else _ASCII)[name]

    def _rgb_param(self, rgb: tuple[int, int, int], background: bool) -> str:
        if self.color_level >= 3:
            return f"{48 if background else 38};2;{rgb[0]};{rgb[1]};{rgb[2]}"
        return f"{48 if background else 38};5;{rgb_to_256(rgb)}"

    def _params(self, role: str | None, bold: bool, fg=None, bg=None) -> str:
        params: list[str] = []
        if role == "crit":
            return _CRIT[self.color_level]
        if bold:
            params.append("1")
        if self.color_level >= 2:
            if fg is not None:
                params.append(self._rgb_param(fg, False))
            if bg is not None:
                params.append(self._rgb_param(bg, True))
        spec = PALETTE.get(role) if role and fg is None else None
        if spec is not None:
            rgb, idx, sgr = spec
            if self.color_level >= 3:
                params.append(f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}")
            elif self.color_level == 2:
                params.append(f"38;5;{idx}")
            else:
                params.append(str(sgr))
        return ";".join(params)

    def paint(self, text: str, role: str | None = None, bold: bool = False, *,
              prompt: bool = False, fg=None, bg=None) -> str:
        """Color `text`. With prompt=True the sequences are protected for readline.

        fg/bg are free RGB colors (256 colors and truecolor only): used by the mascot.
        """
        if self.color_level == 0 or not text:
            return text
        params = self._params(role, bold, fg, bg)
        if not params:
            return text
        start, end = f"\x1b[{params}m", "\x1b[0m"
        if prompt:
            start, end = f"\001{start}\002", f"\001{end}\002"
        return f"{start}{text}{end}"
