"""Punto d'ingresso: `erinix` apre la console; `erinix <comando>` esegue e termina.

Console e riga di comando usano lo stesso registro di comandi.
"""

from __future__ import annotations

import os
import sys

from erinix import __version__
from erinix.commands.builtin import build_registry
from erinix.commands.registry import Context
from erinix.console import Console
from erinix.history import history_path
from erinix.tui.app import TuiApp
from erinix.ui.theme import Theme


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    color = True
    if "--no-color" in args:
        args = [a for a in args if a != "--no-color"]
        color = False
    plain = "--plain" in args
    args = [a for a in args if a != "--plain"]
    ctx = Context.from_env(color)
    registry = build_registry()
    if not args:
        if sys.stdin.isatty() and sys.stdout.isatty():
            if plain or os.environ.get("TERM", "dumb") in ("", "dumb"):
                return Console(registry, ctx).run()
            theme = Theme.from_stream(sys.stdout)
            if not color:
                theme.color_level = 0
            return TuiApp(registry, theme=theme, out=sys.stdout, history_file=history_path()).run()
        return registry.run(ctx, ["help"])
    if args[0] in ("--version", "-V"):
        print(f"erinix {__version__}")
        return 0
    if args[0] in ("--help", "-h"):
        args = ["help"]
    return registry.run(ctx, args)


if __name__ == "__main__":
    raise SystemExit(main())
