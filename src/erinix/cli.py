"""Entry point: `erinix` opens the console; `erinix <command>` runs and exits.

The console and the command line use the same command registry.
"""

from __future__ import annotations

import os
import signal
import sys

from erinix import __version__
from erinix.commands.builtin import build_registry
from erinix.commands.registry import Context
from erinix.console import Console
from erinix.history import history_path
from erinix.palettes import stored_name as stored_palette
from erinix.summary import live_state
from erinix.tui import terminal as term
from erinix.tui.app import TuiApp
from erinix.ui.theme import Theme


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    raw = list(args)
    args = [a for a in args if a != "--elevate"]
    color = True
    if "--no-color" in args:
        args = [a for a in args if a != "--no-color"]
        color = False
    plain = "--plain" in args
    classic = "--console" in args                       # the older scrolling console, kept for those who like it
    args = [a for a in args if a not in ("--plain", "--console")]
    ctx = Context.from_env(color)
    registry = build_registry()
    if not args:
        if sys.stdin.isatty() and sys.stdout.isatty():
            if plain or os.environ.get("TERM", "dumb") in ("", "dumb"):
                return Console(registry, ctx).run()
            theme = Theme.from_stream(sys.stdout, palette=stored_palette())
            if not color:
                theme.color_level = 0
            if classic:
                app = TuiApp(registry, theme=theme, out=sys.stdout, history_file=history_path(), status_provider=live_state)
                try:
                    code = app.run()
                except SystemExit:
                    sig = term.last_signal()
                    if sig is not None:        # the terminal is already restored: say why we ended
                        print(f"erinix: terminated by signal {signal.Signals(sig).name}", file=sys.stderr)
                    raise
                if app.exit_reason:
                    print(f"erinix: {app.exit_reason}", file=sys.stderr)
                return code
            return _cockpit(registry, theme, elevate="--elevate" in raw)
        return registry.run(ctx, ["help"])
    if args[0] == "helper" and len(args) == 1:         # hidden: the root side of `--elevate`, reads /proc and nothing else
        from erinix.sensors.procview import helper_main
        return helper_main()
    if args[0] in ("--version", "-V"):
        print(f"erinix {__version__}")
        return 0
    if args[0] in ("--help", "-h"):
        args = ["help"]
    return registry.run(ctx, args)


def _cockpit(registry, theme: Theme, *, elevate: bool) -> int:
    """`erinix`: start watching this machine and open the live cockpit, in one terminal."""
    from erinix import config as cfg
    from erinix.commands.builtin import default_rules_path
    from erinix.rules import RuleError, load_rules
    from erinix.runtime import AgentRuntime
    from erinix.sensors.procview import ElevatedHelper, code_is_user_writable
    from erinix.store import Store
    from erinix.tui.cockpit import Cockpit

    try:
        ruleset = load_rules(default_rules_path(None))
        runtime = AgentRuntime(ruleset=ruleset)
    except (cfg.ConfigError, RuleError) as exc:
        print(f"erinix: {exc}", file=sys.stderr)
        return 2
    helper = None
    if elevate and os.geteuid() != 0:
        helper = ElevatedHelper()
        if helper.authenticate():
            runtime.helper, runtime.elevate = helper, True
        else:
            print(f"erinix: {helper.error}; continuing with your own programs only", file=sys.stderr)
    runtime.start()
    from erinix import actions

    service = actions.Service(helper=helper if helper is not None and runtime.mode == "full" else None, open_store=lambda: Store())
    actions.set_service(service)
    cockpit = Cockpit(theme, sys.stdout, open_store=lambda: Store(readonly=True), registry=registry, runtime=runtime, service=service)

    def elevate_now() -> str:
        if os.geteuid() == 0 or runtime.mode == "full":
            return "already seeing every program"
        with cockpit.suspended():
            print("\nErinix will ask sudo for your password, only to READ the list of programs and connections.")
            if code_is_user_writable():
                print("Note: this copy of Erinix is in a folder you can write to (a development install),")
                print("so the root helper runs code that your own user could change. Fine for testing; for daily use install it system-wide.")
            answer = input("Continue? [y/N] ").strip().lower() if sys.stdin.isatty() else ""
            if answer not in ("y", "yes", "s", "si"):
                return "cancelled"
            helper = ElevatedHelper()
            if not helper.authenticate():
                return helper.error
        role = runtime.restart_with(helper)
        service.helper = helper if runtime.mode == "full" else None
        return "now seeing every program" if runtime.mode == "full" else (runtime.note or helper.error or f"could not elevate ({role})")

    cockpit.elevate_fn = elevate_now
    try:
        cockpit.run(sys.stdin.fileno())
    except SystemExit:
        sig = term.last_signal()
        if sig is not None:
            print(f"erinix: terminated by signal {signal.Signals(sig).name}", file=sys.stderr)
        raise
    finally:
        runtime.stop()
    if runtime.role == "viewer" and runtime.error:
        print(f"erinix: {runtime.error}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
