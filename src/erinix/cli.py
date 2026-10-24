"""Punto d'ingresso della riga di comando di Erinix."""

from __future__ import annotations

import argparse
import sys

from erinix import __version__
from erinix.rules import RuleError, load_rules

DEFAULT_RULES_DIR = "/etc/erinix/rules"


def safe(text: object) -> str:
    """Rende stampabile in sicurezza un testo che arriva da file esterni."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(text))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="erinix", description="Host-based IDS - Nemirix suite")
    parser.add_argument("--version", action="version", version=f"erinix {__version__}")
    sub = parser.add_subparsers(dest="command")
    rules = sub.add_parser("rules", help="gestione delle regole")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    validate = rules_sub.add_parser("validate", help="valida un file o una cartella di regole")
    validate.add_argument("path", nargs="?", default=DEFAULT_RULES_DIR,
                          help=f"file o cartella (default: {DEFAULT_RULES_DIR})")
    return parser


def _cmd_rules_validate(path: str) -> int:
    try:
        ruleset = load_rules(path)
    except RuleError as exc:
        print(f"errore: {safe(exc)}", file=sys.stderr)
        return 2
    for p in ruleset.problems:
        who = f" ({safe(p.rule_id)})" if p.rule_id else ""
        print(f"[{safe(p.file)}]{who} {safe(p.message)}")
    print(f"{len(ruleset.chains)} catene, {len(ruleset.indicators)} indicatori, "
          f"{len(ruleset.problems)} problemi")
    return 1 if ruleset.problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "rules" and args.rules_command == "validate":
        return _cmd_rules_validate(args.path)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
