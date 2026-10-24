"""Low-level terminal handling for the full-screen console (Unix only).

Same ideas as Vulpnix (alternate screen, raw keys, SGR mouse, selection with
copy via OSC 52), with a few fixes:
- incremental UTF-8 decoding: accented letters are not split;
- keys are read in chunks and split by a tokenizer, with protected paste;
- selection highlighting keeps the colors;
- clipboard copy has a size limit.
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


# ----------------------------------------------------------------- widths
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
    """Clip to `width` columns, keeping the style sequences."""
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


# ------------------------------------------------------------------- keys
def tokenize(buf: str) -> tuple[list[str], str]:
    """Split the input into keys. Returns (complete keys, incomplete remainder)."""
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
                tokens.append(ESC)      # malformed sequence: the rest is read as text
                i += 1
        elif nxt == "O":
            if i + 2 >= n:
                return tokens, buf[i:]
            tokens.append(buf[i:i + 3])
            i += 3
        else:
            tokens.append(buf[i:i + 2])  # Alt + key
            i += 2
    return tokens, ""


class KeyReader:
    """Read keys from a file descriptor, one at a time."""

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
                if self._rest:               # lone ESC or a sequence left half-way
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
    x: int            # column, 1-based
    y: int            # row, 1-based
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
    """Text selection: (document line, column), zero-based."""

    anchor: tuple[int, int]
    focus: tuple[int, int]

    @property
    def bounds(self) -> tuple[tuple[int, int], tuple[int, int]]:
        return tuple(sorted((self.anchor, self.focus)))  # type: ignore[return-value]

    @property
    def is_empty(self) -> bool:
        return self.anchor == self.focus

    def columns(self, line: int) -> tuple[int, int | None] | None:
        """Selected columns (last one included; None = to the end of the line)."""
        (l0, c0), (l1, c1) = self.bounds
        if line < l0 or line > l1:
            return None
        return (c0 if line == l0 else 0), (c1 if line == l1 else None)


def highlight_columns(text: str, start: int, end: int) -> str:
    """Reverse video on columns [start, end), keeping the colors."""
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
            out.append(ESC + "[7m")        # a reset inside the selection must not switch it off
        pos = m.end()
    chars(text[pos:])
    if on:
        out.append(ESC + "[27m")
    return "".join(out)


def extract_selected_text(lines: list[str], selection: Selection) -> str:
    """Selected visible text, without style sequences."""
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
    """Ask the terminal to copy to the clipboard (OSC 52), within a limit."""
    data = text.encode("utf-8")
    if not data or len(data) > MAX_CLIPBOARD_BYTES:
        return False
    out.write(f"{ESC}]52;c;{base64.b64encode(data).decode('ascii')}{ESC}\\")
    out.flush()
    return True


# ------------------------------------------------------- terminal modes
@contextmanager
def raw_input_mode(fd: int) -> Iterator[None]:
    previous = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, previous)


_last_signal: int | None = None


def last_signal() -> int | None:
    """The signal that ended the console, if any (so the exit is never silent)."""
    return _last_signal


def _exit_on_signal(signum: int, _frame: object) -> None:
    global _last_signal
    _last_signal = signum
    raise SystemExit(128 + signum)


@contextmanager
def fullscreen(out: TextIO) -> Iterator[None]:
    """Alternate screen, mouse and protected paste; always restored on exit."""
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
