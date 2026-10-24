"""Console a schermo intero di Erinix.

È un CLIENT, non l'agente: chiuderla non spegne la protezione.

Sicurezza
- Tabella chiusa di comandi, nessuna esecuzione in shell.
- Tutto ciò che i comandi stampano passa da `sanitize_line`: nel terminale
  arrivano solo testo e sequenze di colore (SGR); nessuna altra sequenza di
  escape (niente OSC, spostamenti del cursore, titoli, appunti).
- L'incolla protetta non esegue mai nulla: il testo va nella riga, e gli
  "a capo" diventano spazi.
- Il terminale viene sempre ripristinato, anche in caso di errore o segnale.
"""

from __future__ import annotations

import os
import re
import shlex
import sys
import time
from pathlib import Path
from typing import Callable, TextIO

from erinix import __version__  # noqa: F401  (usato dalla schermata)
from erinix import history as history_store
from erinix.commands.registry import Context, Registry
from erinix.tui import terminal as term
from erinix.tui import welcome
from erinix.tui.editor import LineEditor
from erinix.ui.render import Seg, fit, paint_segs, safe
from erinix.ui.theme import Theme

MAX_OUTPUT_LINES = 5000
WHEEL_STEP = 3
FLASH_SECONDS = 2.0
DRAW_INTERVAL = 0.03
MAX_PASTE = 4096

_SGR = re.compile(r"\x1b\[[0-9;]{0,64}m")


def _strip_controls(text: str) -> str:
    return "".join(c for c in text.replace("\t", "    ") if c.isprintable())


def sanitize_line(line: str) -> str:
    """Lascia passare solo testo stampabile e sequenze di colore (SGR)."""
    out: list[str] = []
    pos = 0
    for m in _SGR.finditer(line):
        out.append(_strip_controls(line[pos:m.start()]))
        out.append(m.group())
        pos = m.end()
    out.append(_strip_controls(line[pos:]))
    return "".join(out)


class LineSink:
    """Raccoglie ciò che i comandi stampano e lo trasforma in righe dello schermo."""

    encoding = "utf-8"

    def __init__(self, app: "TuiApp") -> None:
        self._app = app
        self._partial = ""

    def isatty(self) -> bool:
        return True

    def write(self, text: str) -> int:
        self._partial += text.replace("\r", "")
        *complete, self._partial = self._partial.split("\n")
        for line in complete:
            self._app.append_line(sanitize_line(line))
        if complete:
            self._app.draw()
        return len(text)

    def flush(self) -> None:
        self.flush_partial()

    def flush_partial(self) -> None:
        if self._partial:
            self._app.append_line(sanitize_line(self._partial))
            self._partial = ""
            self._app.draw()


class TuiApp:
    def __init__(self, registry: Registry, *, theme: Theme, out: TextIO,
                 session: welcome.SessionInfo | None = None,
                 session_fn: Callable[[], welcome.SessionInfo] = welcome.session_info,
                 history: list[str] | None = None, history_file: Path | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.registry = registry
        self.theme = theme
        self.out = out
        self._session_fn = session_fn
        self.session = session or session_fn()
        self._welcome_key: tuple | None = None
        self._welcome_lines: list[str] = []
        self.editor = LineEditor(history)
        self.history_file = history_file
        self.clock = clock
        self.lines: list[str] = []
        self.scroll = 0
        self.selection: term.Selection | None = None
        self.done = False
        self.flash = ""
        self._flash_until = 0.0
        self._paste: list[str] | None = None
        self._view_start = 0
        self._last_draw = 0.0
        self._last_cols = 0
        self._doc: list[str] = []
        self._top = 0
        self._view_rows = 1
        self._drag = False
        sink = LineSink(self)
        self._sink = sink
        self.ctx = Context(theme, theme, sink, sink)  # type: ignore[arg-type]

    # ------------------------------------------------------------- documento
    def append_line(self, line: str) -> None:
        self.lines.append(line)
        if len(self.lines) > MAX_OUTPUT_LINES:
            del self.lines[: len(self.lines) - MAX_OUTPUT_LINES]
            self.selection = None

    def clear(self) -> None:
        self.lines.clear()
        self.scroll = 0
        self.selection = None
        self.session = self._session_fn()      # rilegge privilegi e sensore disponibili

    def _prompt(self) -> tuple[str, int]:
        t = self.theme
        glyph = t.glyph("prompt")
        return t.paint("erinix", "accent", True) + " " + t.paint(glyph, "brown") + " ", 6 + 1 + len(glyph) + 1

    def _prompt_line(self, cols: int) -> tuple[str, int]:
        prompt, pw = self._prompt()
        ed = self.editor
        avail = max(2, cols - pw - 1)
        start = min(self._view_start, ed.cursor)
        while start < ed.cursor and term.visible_width(ed.text[start:ed.cursor]) > avail - 1:
            start += 1
        self._view_start = start
        shown = term.clip_ansi_line(safe(ed.text[start:]), avail)
        return prompt + shown, pw + term.visible_width(ed.text[start:ed.cursor])

    # -------------------------------------------------------------- disegno
    def _status_bar(self, cols: int) -> str:
        t = self.theme
        if self.flash and self.clock() < self._flash_until:
            tail = [Seg(self.flash, "ok", True)]
        else:
            tail = [Seg("rotella/PgUp: scorri  ·  trascina: copia  ·  Ctrl-L: pulisci  ·  Ctrl-D: esci", "dim")]
        parts = [Seg(f" {t.glyph('star')} ERINIX ", "accent", True), Seg(self.session.status_text, "brown"),
                 Seg("  ·  ", "border"), *tail]
        fitted = fit(parts, cols, t.glyph("ell"))
        return paint_segs(t, fitted)

    def render_frame(self, cols: int, rows: int) -> str:
        if cols != self._last_cols:
            self._last_cols = cols
            self.selection = None
        view_rows = max(1, rows - 1)
        prompt_text, cursor_col = self._prompt_line(cols)
        key = (cols, self.session, self.theme.color_level)
        if key != self._welcome_key:
            self._welcome_key = key
            self._welcome_lines = welcome.build(self.theme, cols, self.session)
        doc = self._welcome_lines + self.lines + [prompt_text]
        total = len(doc)
        self.scroll = max(0, min(self.scroll, max(0, total - view_rows)))
        top = max(0, total - view_rows - self.scroll)
        self._doc, self._top, self._view_rows = doc, top, view_rows
        out = [term.CURSOR_HIDE]
        for i in range(view_rows):
            index = top + i
            text = ""
            if index < total:
                line = doc[index]
                sel = self.selection.columns(index) if self.selection and not self.selection.is_empty else None
                if sel is not None:
                    first, last = sel
                    line = term.highlight_columns(line, first, 10**6 if last is None else last + 1)
                text = term.clip_ansi_line(line, cols)
            out.append(f"{term.ESC}[{i + 1};1H{text}{term.RESET}{term.ESC}[K")
        out.append(f"{term.ESC}[{rows};1H{self._status_bar(cols)}{term.RESET}{term.ESC}[K")
        prompt_index = total - 1
        if top <= prompt_index < top + view_rows:
            out.append(f"{term.ESC}[{prompt_index - top + 1};{min(cursor_col, cols - 1) + 1}H{term.CURSOR_SHOW}")
        return "".join(out)

    def draw(self, force: bool = False) -> None:
        now = self.clock()
        if not force and now - self._last_draw < DRAW_INTERVAL:
            return
        self._last_draw = now
        cols, rows = term.terminal_size()
        self.out.write(self.render_frame(cols, rows))
        self.out.flush()

    # --------------------------------------------------------------- scorrere
    def scroll_by(self, lines: int) -> None:
        self.scroll = max(0, self.scroll + lines)

    # ------------------------------------------------------------------ input
    def handle_token(self, tok: str) -> None:
        if self._paste is not None:
            self._handle_paste_token(tok)
            return
        if tok == term.PASTE_START:
            self._paste = []
            return
        mouse = term.parse_mouse(tok)
        if mouse is not None:
            self._handle_mouse(mouse)
            return
        self._handle_key(tok)

    def _handle_paste_token(self, tok: str) -> None:
        if tok == term.PASTE_END:
            text = "".join(self._paste or [])
            self._paste = None
            text = re.sub(r"[\r\n]+", " ", text)
            self.editor.insert(text[:MAX_PASTE])
            self.scroll, self.selection = 0, None
            return
        if self._paste is not None and len(tok) == 1 and (tok.isprintable() or tok in "\r\n\t") \
                and len(self._paste) < MAX_PASTE * 4:
            self._paste.append(tok)

    def _handle_key(self, tok: str) -> None:
        ed = self.editor
        if tok in ("\x1b[5~", "\x1b[6~"):
            page = max(1, self._view_rows - 2)
            self.scroll_by(page if tok == "\x1b[5~" else -page)
            return
        self.selection = None
        if tok in ("\r", "\n"):
            self.submit()
            return
        self.scroll = 0
        if tok in ("\x7f", "\x08"):
            ed.backspace()
        elif tok == "\x04":
            if ed.text:
                ed.delete()
            else:
                self.done = True
        elif tok == "\x03":
            self.cancel_line()
        elif tok == "\x0c":
            self.clear()
        elif tok in ("\x01", "\x1b[H", "\x1b[1~", "\x1bOH"):
            ed.home()
        elif tok in ("\x05", "\x1b[F", "\x1b[4~", "\x1bOF"):
            ed.end()
        elif tok == "\x0b":
            ed.kill_to_end()
        elif tok == "\x15":
            ed.kill_line()
        elif tok == "\x17":
            ed.delete_word_back()
        elif tok == "\t":
            self.complete()
        elif tok == "\x1b[A":
            ed.history_prev()
        elif tok == "\x1b[B":
            ed.history_next()
        elif tok == "\x1b[C":
            ed.right()
        elif tok == "\x1b[D":
            ed.left()
        elif tok in ("\x1b[1;5C", "\x1bf"):
            ed.word_right()
        elif tok in ("\x1b[1;5D", "\x1bb"):
            ed.word_left()
        elif tok == "\x1b[3~":
            ed.delete()
        elif len(tok) == 1 and tok.isprintable():
            ed.insert(tok)

    def _handle_mouse(self, ev: term.MouseEvent) -> None:
        if ev.wheel:
            self.scroll_by(WHEEL_STEP if ev.wheel_up else -WHEEL_STEP)
            return
        if not ev.left:
            return
        line = self._top + min(max(ev.y - 1, 0), self._view_rows - 1)
        pos = (min(line, max(0, len(self._doc) - 1)), ev.x - 1)
        if ev.released:
            if self._drag and self.selection is not None:
                self.selection = term.Selection(self.selection.anchor, pos)
                self._finish_selection()
            self._drag = False
        elif ev.motion and self._drag and self.selection is not None:
            self.selection = term.Selection(self.selection.anchor, pos)
        elif not ev.motion:
            self.selection = term.Selection(pos, pos)
            self._drag = True

    def _finish_selection(self) -> None:
        if self.selection is None or self.selection.is_empty:
            return
        text = term.extract_selected_text(self._doc, self.selection)
        if text and term.copy_to_clipboard(self.out, text):
            self.flash = f"copiato negli appunti ({len(text)} caratteri)"
            self._flash_until = self.clock() + FLASH_SECONDS

    # ------------------------------------------------------------- comandi
    def cancel_line(self) -> None:
        self.append_line(self._prompt()[0] + safe(self.editor.text) + self.theme.paint("^C", "dim"))
        self.editor.kill_line()
        self.scroll = 0

    def complete(self) -> None:
        ed = self.editor
        before = ed.text[: ed.cursor]
        prefix = before.rsplit(" ", 1)[-1]
        matches = [w for w in self.registry.complete(before) if w.startswith(prefix)]
        if not matches:
            return
        if len(matches) == 1:
            ed.insert(matches[0][len(prefix):] + " ")
            return
        common = os.path.commonprefix(matches)
        if len(common) > len(prefix):
            ed.insert(common[len(prefix):])
        else:
            self.append_line(self._prompt()[0] + safe(before))
            self.append_line(self.theme.paint("  " + "   ".join(safe(m) for m in matches), "brown"))

    def submit(self) -> None:
        raw = self.editor.submit()
        self.scroll, self.selection = 0, None
        self.append_line(self._prompt()[0] + safe(raw))
        if not raw.strip():
            return
        try:
            tokens = shlex.split(raw)
        except ValueError as exc:
            self.ctx.error(f"sintassi non valida: {exc}")
            return
        if tokens[0] in ("exit", "quit"):
            self.done = True
            return
        if tokens[0] == "clear":
            self.clear()
            return
        found = self.registry.resolve(tokens)
        try:
            self.registry.run(self.ctx, tokens)
        except KeyboardInterrupt:
            self.ctx.error("interrotto")
        except Exception as exc:  # la console non deve cadere per un errore in un comando
            self.ctx.error(f"errore interno ({type(exc).__name__}): {exc}")
        finally:
            self._sink.flush_partial()
        if found and found[0].sensitive:
            self.editor.forget_last(raw)

    # ------------------------------------------------------------------ ciclo
    def run(self, fd: int | None = None) -> int:
        fd = sys.stdin.fileno() if fd is None else fd
        reader = term.KeyReader(fd)
        if self.history_file is not None:
            self.editor.history = history_store.read_lines(self.history_file)
        try:
            with term.raw_input_mode(fd), term.fullscreen(self.out):
                self.draw(force=True)
                while not self.done:
                    try:
                        tok = reader.read(timeout=0.25)
                    except KeyboardInterrupt:
                        self.cancel_line()
                        self.draw(force=True)
                        continue
                    except EOFError:
                        break
                    size_changed = term.terminal_size()[0] != self._last_cols
                    flash_over = bool(self.flash) and self.clock() >= self._flash_until
                    if flash_over:
                        self.flash = ""
                    if tok is not None:
                        self.handle_token(tok)
                    if tok is not None or size_changed or flash_over:
                        self.draw(force=True)
        finally:
            if self.history_file is not None:
                history_store.write_lines(self.history_file, self.editor.history)
        return 0
