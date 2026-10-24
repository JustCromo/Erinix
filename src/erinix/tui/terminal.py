"""Basso livello del terminale per la console a schermo intero (solo Unix).

Stesse idee di Vulpnix (schermo alternativo, tasti grezzi, mouse SGR,
selezione con copia tramite OSC 52), con alcune correzioni:
- decodifica UTF-8 incrementale: le lettere accentate non si spezzano;
- tasti letti a blocchi e separati da un tokenizer, con incolla protetta;
- l'evidenziazione della selezione conserva i colori;
- la copia negli appunti ha un limite di dimensione.
"""

from __future__ import annotations

import base64
import codecs
import os
import re
import select
import shutil
import signal
import sys
import termios
import tty
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, TextIO

ESC = "\x1b"
ALT_ON, ALT_OFF = ESC + "[?1049h", ESC + "[?1049l"
MOUSE_ON, MOUSE_OFF = ESC + "[?1002h" + ESC + "[?1006h", ESC + "[?1006l" + ESC + "[?1002l"
PASTE_ON, PASTE_OFF = ESC + "[?2004h", ESC + "[?2004l"
CURSOR_SHOW, CURSOR_HIDE = ESC + "[?25h", ESC + "[?25l"
RESET = ESC + "[0m"
PASTE_START, PASTE_END = ESC + "[200~", ESC + "[201~"

MAX_CLIPBOARD_BYTES = 75_000
_ESC_WAIT = 0.05
_MAX_PENDING = 64

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_MOUSE = re.compile(r"\x1b\[<(\d{1,5});(\d{1,5});(\d{1,5})([Mm])")
_CSI_BODY = set("0123456789:;<=>?") | set(" !\"#$%&'()*+,-./")


# ----------------------------------------------------------------- larghezze
def char_width(ch: str) -> int:
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def visible_width(text: str) -> int:
    return sum(char_width(c) for c in strip_ansi(text))


def terminal_size() -> tuple[int, int]:
    size = shutil.get_terminal_size((80, 24))
    return size.columns, size.lines


def clip_ansi_line(line: str, width: int) -> str:
    """Taglia a `width` colonne conservando le sequenze di stile."""
    out: list[str] = []
    column = 0
    pos = 0

    def take(chars: str) -> bool:
        nonlocal column
        for ch in chars:
            w = char_width(ch)
            if column + w > width:
                return False
            out.append(ch)
            column += w
        return True

    for m in _ANSI.finditer(line):
        if not take(line[pos:m.start()]):
            out.append(RESET)
            return "".join(out)
        out.append(m.group())
        pos = m.end()
    if not take(line[pos:]):
        out.append(RESET)
    return "".join(out)


# ------------------------------------------------------------------- tasti
def tokenize(buf: str) -> tuple[list[str], str]:
    """Separa l'input in tasti. Restituisce (tasti completi, resto incompleto)."""
    tokens: list[str] = []
    i, n = 0, len(buf)
    while i < n:
        ch = buf[i]
        if ch != ESC:
            tokens.append(ch)
            i += 1
            continue
        if i + 1 >= n:
            return tokens, buf[i:]
        nxt = buf[i + 1]
        if nxt == "[":
            j = i + 2
            while j < n and buf[j] in _CSI_BODY:
                j += 1
            if j >= n:
                return tokens, buf[i:]
            if "@" <= buf[j] <= "~":
                tokens.append(buf[i:j + 1])
                i = j + 1
            else:
                tokens.append(ESC)      # sequenza malformata: il resto si legge come testo
                i += 1
        elif nxt == "O":
            if i + 2 >= n:
                return tokens, buf[i:]
            tokens.append(buf[i:i + 3])
            i += 3
        else:
            tokens.append(buf[i:i + 2])  # Alt + tasto
            i += 2
    return tokens, ""


class KeyReader:
    """Legge i tasti da un descrittore di file, uno alla volta."""

    def __init__(self, fd: int) -> None:
        self.fd = fd
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._queue: list[str] = []
        self._rest = ""

    def read(self, timeout: float | None = None) -> str | None:
        while True:
            if self._queue:
                return self._queue.pop(0)
            wait = _ESC_WAIT if self._rest else timeout
            if wait is not None and not select.select([self.fd], [], [], wait)[0]:
                if self._rest:               # ESC isolato o sequenza rimasta a metà
                    rest, self._rest = self._rest, ""
                    return rest
                return None
            data = os.read(self.fd, 4096)
            if not data:
                raise EOFError
            tokens, self._rest = tokenize(self._rest + self._decoder.decode(data))
            if len(self._rest) > _MAX_PENDING:
                self._rest = ""
            self._queue.extend(tokens)


# ------------------------------------------------------------------- mouse
@dataclass(frozen=True, slots=True)
class MouseEvent:
    button: int
    x: int            # colonna, da 1
    y: int            # riga, da 1
    released: bool

    @property
    def wheel(self) -> bool:
        return bool(self.button & 64)

    @property
    def wheel_up(self) -> bool:
        return self.wheel and not self.button & 1

    @property
    def motion(self) -> bool:
        return bool(self.button & 32) and not self.wheel

    @property
    def left(self) -> bool:
        return not self.wheel and (self.button & 3) == 0


def parse_mouse(token: str) -> MouseEvent | None:
    m = _MOUSE.fullmatch(token)
    if m is None:
        return None
    button, x, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if x < 1 or y < 1:
        return None
    return MouseEvent(button, x, y, m.group(4) == "m")


@dataclass(frozen=True, slots=True)
class Selection:
    """Selezione di testo: (riga del documento, colonna), da zero."""

    anchor: tuple[int, int]
    focus: tuple[int, int]

    @property
    def bounds(self) -> tuple[tuple[int, int], tuple[int, int]]:
        return tuple(sorted((self.anchor, self.focus)))  # type: ignore[return-value]

    @property
    def is_empty(self) -> bool:
        return self.anchor == self.focus

    def columns(self, line: int) -> tuple[int, int | None] | None:
        """Colonne selezionate (ultima inclusa; None = fino a fine riga)."""
        (l0, c0), (l1, c1) = self.bounds
        if line < l0 or line > l1:
            return None
        return (c0 if line == l0 else 0), (c1 if line == l1 else None)


def highlight_columns(text: str, start: int, end: int) -> str:
    """Video inverso sulle colonne [start, end), conservando i colori."""
    out: list[str] = []
    column = 0
    on = False

    def chars(segment: str) -> None:
        nonlocal column, on
        for ch in segment:
            w = char_width(ch)
            if w == 0:
                out.append(ch)
                continue
            selected = column < end and column + w > start
            if selected != on:
                out.append(ESC + ("[7m" if selected else "[27m"))
                on = selected
            out.append(ch)
            column += w

    pos = 0
    for m in _ANSI.finditer(text):
        chars(text[pos:m.start()])
        out.append(m.group())
        if on and m.group().endswith("m"):
            out.append(ESC + "[7m")        # un reset dentro la selezione non deve spegnerla
        pos = m.end()
    chars(text[pos:])
    if on:
        out.append(ESC + "[27m")
    return "".join(out)


def extract_selected_text(lines: list[str], selection: Selection) -> str:
    """Testo visibile selezionato, senza sequenze di stile."""
    if selection.is_empty:
        return ""
    (l0, _), (l1, _) = selection.bounds
    if l0 < 0 or l1 >= len(lines):
        return ""
    picked: list[str] = []
    for number in range(l0, l1 + 1):
        plain = strip_ansi(lines[number])
        cols = selection.columns(number)
        if cols is None:
            continue
        first, last = cols
        stop = visible_width(plain) if last is None else last + 1
        chars: list[str] = []
        column = 0
        prev = False
        for ch in plain:
            w = char_width(ch)
            if w == 0:
                if prev:
                    chars.append(ch)
                continue
            prev = column < stop and column + w > first
            if prev:
                chars.append(ch)
            column += w
        picked.append("".join(chars).rstrip())
    return "\n".join(picked)


def copy_to_clipboard(out: TextIO, text: str) -> bool:
    """Chiede al terminale di copiare negli appunti (OSC 52), entro un limite."""
    data = text.encode("utf-8")
    if not data or len(data) > MAX_CLIPBOARD_BYTES:
        return False
    out.write(f"{ESC}]52;c;{base64.b64encode(data).decode('ascii')}{ESC}\\")
    out.flush()
    return True


# ------------------------------------------------------- modalità terminale
@contextmanager
def raw_input_mode(fd: int) -> Iterator[None]:
    previous = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, previous)


def _exit_on_signal(signum: int, _frame: object) -> None:
    raise SystemExit(128 + signum)


@contextmanager
def fullscreen(out: TextIO) -> Iterator[None]:
    """Schermo alternativo, mouse e incolla protetta; sempre ripristinati all'uscita."""
    previous: dict[int, object] = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, _exit_on_signal)
        out.write(ALT_ON + MOUSE_ON + PASTE_ON + ESC + "[2J" + ESC + "[H")
        out.flush()
        yield
    finally:
        try:
            out.write(RESET + PASTE_OFF + MOUSE_OFF + CURSOR_SHOW + ALT_OFF)
            out.flush()
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)  # type: ignore[arg-type]
