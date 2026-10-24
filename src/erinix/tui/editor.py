"""Command-line editor: text, cursor and history (no I/O)."""

from __future__ import annotations

MAX_LEN = 4096
MAX_HISTORY = 500


class LineEditor:
    def __init__(self, history: list[str] | None = None) -> None:
        self.text = ""
        self.cursor = 0
        self.history: list[str] = list(history or [])[-MAX_HISTORY:]
        self._nav: int | None = None
        self._draft = ""

    # -------------------------------------------------------------- editing
    def insert(self, chunk: str) -> None:
        clean = "".join(c for c in chunk if c.isprintable())[: MAX_LEN - len(self.text)]
        if not clean:
            return
        self.text = self.text[: self.cursor] + clean + self.text[self.cursor:]
        self.cursor += len(clean)
        self._nav = None

    def backspace(self) -> None:
        if self.cursor:
            self.text = self.text[: self.cursor - 1] + self.text[self.cursor:]
            self.cursor -= 1
            self._nav = None

    def delete(self) -> None:
        if self.cursor < len(self.text):
            self.text = self.text[: self.cursor] + self.text[self.cursor + 1:]
            self._nav = None

    def kill_to_end(self) -> None:
        self.text = self.text[: self.cursor]

    def kill_line(self) -> None:
        self.text, self.cursor, self._nav = "", 0, None

    def delete_word_back(self) -> None:
        start = self.word_start()
        self.text = self.text[:start] + self.text[self.cursor:]
        self.cursor = start
        self._nav = None

    # ------------------------------------------------------------- movement
    def left(self) -> None:
        self.cursor = max(0, self.cursor - 1)

    def right(self) -> None:
        self.cursor = min(len(self.text), self.cursor + 1)

    def home(self) -> None:
        self.cursor = 0

    def end(self) -> None:
        self.cursor = len(self.text)

    def word_start(self) -> int:
        i = self.cursor
        while i > 0 and self.text[i - 1] == " ":
            i -= 1
        while i > 0 and self.text[i - 1] != " ":
            i -= 1
        return i

    def word_left(self) -> None:
        self.cursor = self.word_start()

    def word_right(self) -> None:
        i, n = self.cursor, len(self.text)
        while i < n and self.text[i] == " ":
            i += 1
        while i < n and self.text[i] != " ":
            i += 1
        self.cursor = i

    # ------------------------------------------------------------ history
    def history_prev(self) -> None:
        if not self.history:
            return
        if self._nav is None:
            self._draft = self.text
            self._nav = len(self.history) - 1
        elif self._nav > 0:
            self._nav -= 1
        self.text = self.history[self._nav]
        self.cursor = len(self.text)

    def history_next(self) -> None:
        if self._nav is None:
            return
        self._nav += 1
        if self._nav >= len(self.history):
            self._nav = None
            self.text = self._draft
        else:
            self.text = self.history[self._nav]
        self.cursor = len(self.text)

    def submit(self) -> str:
        line = self.text
        if line.strip() and (not self.history or self.history[-1] != line):
            self.history.append(line)
            del self.history[:-MAX_HISTORY]
        self.text, self.cursor, self._nav, self._draft = "", 0, None, ""
        return line

    def forget_last(self, line: str) -> None:
        """Remove a line from the history (sensitive commands)."""
        if self.history and self.history[-1] == line:
            self.history.pop()
