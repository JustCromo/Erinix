"""Commands that DO something: block, unblock, kill, fix, undo. Each shows what it will do, and asks first."""

from __future__ import annotations

import sys
import time

from erinix import actions
from erinix.commands.registry import Context, parse_args
from erinix.ui.render import Seg, safe


def _confirm(ctx: Context, plan: actions.Plan, flags: set[str]) -> bool:
    ctx.line(Seg(plan.title, None, True))
    for step in plan.steps[:12]:
        ctx.line(Seg("  " + step, "dim"))
    if plan.warning:
        ctx.line(Seg("  " + plan.warning, "warn"))
    if plan.needs_root:
        ctx.line(Seg("  This needs root: it runs through the root helper (press R in the cockpit, or start with erinix --elevate).", "dim"))
    if "--yes" in flags or ctx.emitter is not None:         # inside the cockpit, typing the whole command is the confirmation
        return True
    if not sys.stdin.isatty():
        ctx.error("add --yes to confirm")
        return False
    try:
        answer = input("Do it? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes", "s", "si")


def _report(ctx: Context, result: dict) -> int:
    if result["ok"]:
        ctx.line(Seg(ctx.theme.glyph("ok") + " ", "ok", True), Seg(result["message"]))
        if result.get("n"):
            ctx.line(Seg(f"  Written to the journal as #{result['n']}" + ("; undo with: undo " + str(result["n"]) if result.get("undo") else "."), "dim"))
        return 0
    ctx.error(result["message"])
    return 1


def _do(ctx: Context, action: str, args: dict, flags: set[str]) -> int:
    svc = actions.get_service()
    try:
        plan = svc.plan(action, args)
    except actions.ActionError as exc:
        ctx.error(str(exc))
        return 1
    if not _confirm(ctx, plan, flags):
        ctx.line(Seg("Nothing was changed.", "dim"))
        return 1
    return _report(ctx, svc.run_action(action, args, plan.title))


def _minutes(options: dict[str, str]) -> int | None:
    raw = options.get("--minutes")
    if raw is None:
        return actions.DEFAULT_MINUTES
    return int(raw) if raw.isdigit() and len(raw) < 6 else None


def cmd_block(ctx: Context, args: list[str]) -> int:
    pos, flags, opts = parse_args(args, flags=("--yes",), options=("--minutes",), max_positional=1)
    if not pos:
        ctx.error("usage: block <ip> [--minutes N] [--yes]")
        return 2
    minutes = _minutes(opts)
    if minutes is None:
        ctx.error("--minutes needs a number")
        return 2
    return _do(ctx, "block", {"ip": pos[0], "minutes": minutes}, flags)


def cmd_unblock(ctx: Context, args: list[str]) -> int:
    pos, flags, _ = parse_args(args, flags=("--yes",), max_positional=1)
    if not pos:
        ctx.error("usage: unblock <ip> [--yes]")
        return 2
    return _do(ctx, "unblock", {"ip": pos[0]}, flags)


def cmd_kill(ctx: Context, args: list[str]) -> int:
    pos, flags, _ = parse_args(args, flags=("--yes", "--force"), max_positional=1)
    if not pos or not pos[0].isdigit() or len(pos[0]) > 8:
        ctx.error("usage: kill <program number> [--force] [--yes]   (the numbers are in the Programs panel)")
        return 2
    return _do(ctx, "kill", {"pid": int(pos[0]), "signal": "KILL" if "--force" in flags else "TERM"}, flags)


def cmd_fix(ctx: Context, args: list[str]) -> int:
    pos, flags, _ = parse_args(args, flags=("--yes",), max_positional=1)
    if not pos:
        ctx.line(Seg("Erinix can restore safe permissions for these checks:", None, True))
        for cid in actions.FIXABLE:
            ctx.line(Seg("  " + cid, "accent"))
        ctx.line(Seg("Use: fix <check>   (the other findings say how to fix them by hand)", "dim"))
        return 0
    return _do(ctx, "fix", {"check": pos[0]}, flags)


def cmd_actions(ctx: Context, args: list[str]) -> int:
    from erinix.store import Store, StoreError

    parse_args(args, max_positional=0)
    try:
        store = Store(readonly=True)
    except StoreError:
        ctx.line(Seg("Nothing has been done yet.", "dim"))
        return 0
    try:
        rows = actions.Journal(store).all()
    finally:
        store.close()
    if not rows:
        ctx.line(Seg("Nothing has been done yet.", "dim"))
        return 0
    for r in rows[-30:]:
        role = "ok" if r.get("ok") else "bad"
        when = time.strftime("%d/%m %H:%M", time.localtime(r.get("time", 0)))
        tail = "  (undone)" if r.get("undone") else ("  (can be undone: undo %s)" % r["n"] if r.get("undo") else "")
        ctx.line(Seg(f"#{r.get('n')} ", "dim"), Seg(when + "  ", "dim"), Seg(safe(str(r.get("title", ""))), role, True), Seg(tail, "dim"))
        ctx.line(Seg("     " + safe(str(r.get("message", ""))), "dim"))
    return 0


def cmd_blocked(ctx: Context, args: list[str]) -> int:
    from erinix.store import Store, StoreError

    parse_args(args, max_positional=0)
    try:
        store = Store(readonly=True)
    except StoreError:
        ctx.line(Seg("Nothing is blocked.", "dim"))
        return 0
    try:
        rows = actions.Journal(store).active_blocks()
    finally:
        store.close()
    if not rows:
        ctx.line(Seg("Nothing is blocked.", "dim"))
        return 0
    for r in rows:
        left = max(0, int((r["time"] + r.get("minutes", 0) * 60 - time.time()) / 60))
        ctx.line(Seg(safe((r.get("undo") or {}).get("ip", "?")), None, True), Seg(f"  {left} min left  (undo {r['n']})", "dim"))
    return 0


def cmd_undo(ctx: Context, args: list[str]) -> int:
    pos, flags, _ = parse_args(args, flags=("--yes",), max_positional=1)
    if not pos or not pos[0].isdigit() or len(pos[0]) > 6:
        ctx.error("usage: undo <number>   (see: actions)")
        return 2
    if "--yes" not in flags and ctx.emitter is None and sys.stdin.isatty():
        if input(f"Undo #{pos[0]}? [y/N] ").strip().lower() not in ("y", "yes", "s", "si"):
            ctx.line(Seg("Nothing was changed.", "dim"))
            return 1
    elif "--yes" not in flags and ctx.emitter is None:
        ctx.error("add --yes to confirm")
        return 1
    return _report(ctx, actions.get_service().undo(int(pos[0])))
