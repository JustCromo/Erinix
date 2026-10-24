"""Classic interactive console of Erinix (prompt `erinix ▸`), used with --plain.

It is a CLIENT: it is not the agent. Closing it does not switch protection off,
and a compromised console does not have the agent's powers.

Security: closed table of commands, no shell execution, length-limited lines,
history in a 0600 file that it refuses to read if it is not the user's or is
accessible to others.
"""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path
from typing import Callable

from erinix import __version__
from erinix.commands.registry import Context, Registry
from erinix.history import HISTORY_MAX, MAX_LINE, history_path, is_trusted
from erinix.sensors import selector
from erinix.ui.render import Seg, banner, paint_segs

def load_history(readline, path: Path) -> None:
    if not is_trusted(path):
        return  # someone else's file, or accessible to others: do not trust it
    try:
        readline.read_history_file(str(path))
    except OSError:
        pass


def save_history(readline, path: Path) -> None:
    try:
        os.makedirs(path.parent, mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
        readline.write_history_file(str(path))
    except OSError:
        pass


class Console:
    def __init__(self, registry: Registry, ctx: Context, input_fn: Callable[[str], str] | None = None) -> None:
        self.registry = registry
        self.ctx = ctx
        self._input = input_fn
        self._readline = None

    def _setup_readline(self):
        try:
            import readline
        except ImportError:
            return None
        readline.set_history_length(HISTORY_MAX)
        readline.set_completer_delims(" \t\n")

        def completer(text: str, state: int):
            options = [w for w in self.registry.complete(readline.get_line_buffer()) if w.startswith(text)]
            return options[state] if state < len(options) else None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
        load_history(readline, history_path())
        return readline

    def _prompt(self) -> str:
        t = self.ctx.theme
        use = self._readline is not None
        return (t.paint("erinix", "accent", True, prompt=use) + " "
                + t.paint(t.glyph("prompt"), "brown", prompt=use) + " ")

    def _welcome(self) -> None:
        for line in banner(self.ctx.theme, __version__):
            self.ctx.say(line)
        plan = selector.choose(selector.detect())
        mode = {"ebpf": "eBPF", "auditd": "auditd", "minimal": "minimal"}[plan.mode.value]
        self.ctx.say()
        self.ctx.line(Seg("sensor ", "brown"), Seg(mode, "accent", True),
                      Seg(" (rootless)" if plan.rootless else "", "dim"),
                      Seg("  ·  ", "border"), Seg("help", "accent"), Seg(" for commands, ", "dim"),
                      Seg("exit", "accent"), Seg(" to quit", "dim"))
        self.ctx.say()

    def run(self) -> int:
        self._welcome()
        if self._input is None:
            self._input = input
            if sys.stdin.isatty():
                self._readline = self._setup_readline()
        prompt = self._prompt()
        try:
            while True:
                try:
                    raw = self._input(prompt)
                except EOFError:
                    self.ctx.say()
                    break
                except KeyboardInterrupt:
                    self.ctx.say("^C")
                    continue
                raw = raw.strip()
                if not raw:
                    continue
                if len(raw) > MAX_LINE:
                    self.ctx.error("line too long")
                    continue
                try:
                    tokens = shlex.split(raw)
                except ValueError as exc:
                    self.ctx.error(f"invalid syntax: {exc}")
                    continue
                if tokens[0] in ("exit", "quit"):
                    break
                found = self.registry.resolve(tokens)
                try:
                    self.registry.run(self.ctx, tokens)
                except KeyboardInterrupt:
                    self.ctx.say()
                    self.ctx.error("interrupted")
                if found and found[0].sensitive and self._readline is not None:
                    n = self._readline.get_current_history_length()
                    if n:
                        self._readline.remove_history_item(n - 1)
        finally:
            if self._readline is not None:
                save_history(self._readline, history_path())
        return 0
