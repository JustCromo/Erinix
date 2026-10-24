"""Punto d'ingresso: `erinix` apre la console; `erinix <comando>` esegue e termina.

Console e riga di comando usano lo stesso registro di comandi.
"""

from __future__ import annotations

import sys

from erinix import __version__
from erinix.commands.builtin import build_registry
from erinix.commands.registry import Context
from erinix.console import Console


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    color = True
    if "--no-color" in args:
        args = [a for a in args if a != "--no-color"]
        color = False
    ctx = Context.from_env(color)
    registry = build_registry()
    if not args:
        if sys.stdin.isatty() and sys.stdout.isatty():
            return Console(registry, ctx).run()
        return registry.run(ctx, ["help"])
    if args[0] in ("--version", "-V"):
        print(f"erinix {__version__}")
        return 0
    if args[0] in ("--help", "-h"):
        args = ["help"]
    return registry.run(ctx, args)


if __name__ == "__main__":
    raise SystemExit(main())
