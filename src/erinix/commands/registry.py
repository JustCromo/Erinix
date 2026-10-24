"""Registro unico dei comandi.

Tabella CHIUSA: ogni comando è una voce con funzione, aiuto e uso. Niente
comandi costruiti da testo esterno, niente esecuzione in shell. Console
interattiva e riga di comando pescano dalla stessa tabella.
"""

from __future__ import annotations

import difflib
import sys
from dataclasses import dataclass, field
from typing import Callable, Sequence, TextIO

from erinix.ui.render import Cell, Seg, paint_segs, safe, table
from erinix.ui.theme import Theme


class UsageError(Exception):
    """Argomenti non validi per il comando."""


@dataclass(slots=True)
class Context:
    theme: Theme
    err_theme: Theme
    out: TextIO
    err: TextIO
    # Se impostato (console a schermo intero), riceve i blocchi che dipendono dalla
    # larghezza, così si possono ridisegnare quando il terminale cambia dimensione.
    emitter: Callable[[Callable[[int], str]], None] | None = None

    @classmethod
    def from_env(cls, color: bool = True) -> "Context":
        theme, err_theme = Theme.from_stream(sys.stdout), Theme.from_stream(sys.stderr)
        if not color:
            theme.color_level = err_theme.color_level = 0
        return cls(theme, err_theme, sys.stdout, sys.stderr)

    def say(self, text: str = "") -> None:
        print(text, file=self.out)

    def line(self, *parts: Seg) -> None:
        self.say(paint_segs(self.theme, [Seg(safe(p.text), p.role, p.bold) for p in parts]))

    def emit(self, renderable: Callable[[int], str]) -> None:
        """Stampa un blocco (tabella, pannello) la cui forma dipende dalla larghezza."""
        if self.emitter is not None:
            self.emitter(renderable)
        else:
            self.say(renderable(self.theme.width))

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[Cell]]) -> None:
        self.emit(lambda width: table(self.theme, headers, rows, width=width))

    def error(self, text: str) -> None:
        mark = self.err_theme.paint(self.err_theme.glyph("bad"), "bad", True)
        print(f"{mark} {safe(text)}", file=self.err)


Handler = Callable[[Context, list[str]], int]


@dataclass(frozen=True, slots=True)
class Command:
    name: str                  # "doctor" oppure "rules validate"
    summary: str
    usage: str
    group: str
    handler: Handler
    arg_words: tuple[str, ...] = ()
    sensitive: bool = False    # non finisce nella cronologia della console


def parse_args(args: list[str], *, flags: Sequence[str] = (), options: Sequence[str] = (),
               max_positional: int = 1) -> tuple[list[str], set[str], dict[str, str]]:
    positional: list[str] = []
    found: set[str] = set()
    values: dict[str, str] = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a in flags:
            found.add(a)
        elif a in options:
            i += 1
            if i >= len(args):
                raise UsageError(f"{safe(a)} richiede un valore")
            values[a] = args[i]
        elif a.startswith("-"):
            raise UsageError(f"opzione sconosciuta: {safe(a)}")
        else:
            positional.append(a)
        i += 1
    if len(positional) > max_positional:
        raise UsageError("troppi argomenti")
    return positional, found, values


@dataclass(slots=True)
class Registry:
    _commands: dict[str, Command] = field(default_factory=dict)

    def add(self, command: Command) -> None:
        self._commands[command.name] = command

    @property
    def commands(self) -> list[Command]:
        return list(self._commands.values())

    def _groups(self) -> dict[str, list[str]]:
        groups: dict[str, list[str]] = {}
        for name in self._commands:
            if " " in name:
                head, sub = name.split(" ", 1)
                groups.setdefault(head, []).append(sub)
        return groups

    def first_words(self) -> list[str]:
        return sorted({n.split(" ", 1)[0] for n in self._commands})

    def resolve(self, tokens: Sequence[str]) -> tuple[Command, list[str]] | None:
        if not tokens:
            return None
        if len(tokens) >= 2 and f"{tokens[0]} {tokens[1]}" in self._commands:
            return self._commands[f"{tokens[0]} {tokens[1]}"], list(tokens[2:])
        if tokens[0] in self._commands:
            return self._commands[tokens[0]], list(tokens[1:])
        return None

    def complete(self, buffer: str) -> list[str]:
        tokens = buffer.split()
        done = tokens if buffer.endswith(" ") else tokens[:-1]
        groups = self._groups()
        if not done:
            return sorted(set(self.first_words()) | {"exit", "quit"})
        if len(done) == 1 and done[0] in groups:
            return sorted(groups[done[0]])
        found = self.resolve(done)
        return list(found[0].arg_words) if found else []

    def run(self, ctx: Context, tokens: Sequence[str]) -> int:
        found = self.resolve(tokens)
        if found is None:
            word = tokens[0]
            groups = self._groups()
            if word in groups:
                ctx.error(f"'{safe(word)}' richiede un sottocomando: {', '.join(sorted(groups[word]))}")
                return 2
            hint = difflib.get_close_matches(word, self.first_words(), n=1)
            extra = f" Intendevi '{hint[0]}'?" if hint else ""
            ctx.error(f"comando sconosciuto: {safe(word)}.{extra} Scrivi 'help' per l'elenco.")
            return 2
        command, args = found
        try:
            return command.handler(ctx, args)
        except UsageError as exc:
            ctx.error(str(exc))
            print(f"  uso: {command.usage}", file=ctx.err)
            return 2
