"""Tema colori di Erinix.

Informazioni ed evidenziazioni in toni di riccio (marroni e arancio freddo);
tutto il resto resta nel colore predefinito del terminale; rosso/verde/giallo
sono riservati alle segnalazioni (semaforo), tarati per stare bene accanto ai
marroni.

Supporto ai terminali: truecolor, 256 colori, 16 colori, nessun colore.
Si rispetta NO_COLOR; ERINIX_COLOR=always|never|auto forza la scelta.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Mapping, TextIO

# ruolo -> (RGB truecolor, indice a 256 colori, codice SGR a 16 colori)
PALETTE: Mapping[str, tuple[tuple[int, int, int], int, int]] = {
    "accent": ((226, 122, 63), 173, 33),    # arancio freddo: evidenze, titoli
    "brown": ((176, 136, 102), 137, 33),    # marrone chiaro: informazioni
    "border": ((124, 96, 74), 94, 90),      # marrone scuro: bordi, decorazioni
    "dim": ((150, 138, 126), 245, 90),      # secondario
    "ok": ((125, 170, 92), 107, 32),        # verde
    "warn": ((227, 179, 65), 179, 93),      # giallo ambra
    "bad": ((224, 86, 75), 167, 91),        # rosso
}
# Gravità massima: bianco in grassetto su sfondo rosso.
_CRIT = {3: "1;38;2;255;255;255;48;2;184;48;42", 2: "1;38;5;231;48;5;124", 1: "1;97;41"}

MIN_WIDTH, MAX_WIDTH = 60, 120

_UNICODE = {"tl": "╭", "tr": "╮", "bl": "╰", "br": "╯", "h": "─", "v": "│", "lt": "├",
            "rt": "┤", "tt": "┬", "bt": "┴", "x": "┼", "ok": "✔", "warn": "▲", "bad": "✖",
            "full": "█", "empty": "░", "ell": "…", "prompt": "▸", "arrow": "→", "dot": "·"}
_ASCII = {"tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "-", "v": "|", "lt": "+",
          "rt": "+", "tt": "+", "bt": "+", "x": "+", "ok": "OK", "warn": "!!", "bad": "XX",
          "full": "#", "empty": "-", "ell": "...", "prompt": ">", "arrow": "->", "dot": "-"}


def detect_color_level(stream: TextIO | None = None, env: Mapping[str, str] | None = None) -> int:
    """0 = nessun colore, 1 = 16 colori, 2 = 256 colori, 3 = truecolor."""
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

    def _params(self, role: str | None, bold: bool) -> str:
        params: list[str] = []
        if role == "crit":
            return _CRIT[self.color_level]
        if bold:
            params.append("1")
        spec = PALETTE.get(role) if role else None
        if spec is not None:
            rgb, idx, sgr = spec
            if self.color_level >= 3:
                params.append(f"38;2;{rgb[0]};{rgb[1]};{rgb[2]}")
            elif self.color_level == 2:
                params.append(f"38;5;{idx}")
            else:
                params.append(str(sgr))
        return ";".join(params)

    def paint(self, text: str, role: str | None = None, bold: bool = False, *, prompt: bool = False) -> str:
        """Colora `text`. Con prompt=True protegge le sequenze per readline."""
        if self.color_level == 0 or not text:
            return text
        params = self._params(role, bold)
        if not params:
            return text
        start, end = f"\x1b[{params}m", "\x1b[0m"
        if prompt:
            start, end = f"\001{start}\002", f"\001{end}\002"
        return f"{start}{text}{end}"
