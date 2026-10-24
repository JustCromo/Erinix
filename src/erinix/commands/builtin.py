"""Commands available today: help, version, doctor, rules, replay."""

from __future__ import annotations

import os
import time
from pathlib import Path

from erinix import __version__
from erinix.commands.registry import Command, Context, Registry, UsageError, parse_args
from erinix.demo.scenarios import SCENARIOS, SEC
from erinix.engine import Alert, Correlator
from erinix.rules import Response, RuleError, RuleSet, load_rules
from erinix.sensors import selector
from erinix.ui.render import Seg, safe
from erinix.ui.views import alert_panel, describe_event, response_seg, severity_badge

DEFAULT_RULES_DIR = "/etc/erinix/rules"
MODE_NAMES = {"ebpf": "eBPF (CO-RE)", "auditd": "auditd", "minimal": "minimal"}
_RESPONSE_RANK = {Response.REPORT_ONLY: 0, Response.INTERACTIVE: 1, Response.AUTO: 2}
GROUP_ORDER = ("General", "Diagnostics", "Rules", "Demo")
COMING_SOON = "start · stop · status · ui · watch · alerts · incident · response · block · sensor"


# ------------------------------------------------------------------ helpers
def _mark(ctx: Context, kind: str) -> Seg:
    role = {"ok": "ok", "warn": "warn", "bad": "bad"}[kind]
    return Seg(ctx.theme.glyph(kind), role, True)


def _load(ctx: Context, path: str) -> RuleSet | None:
    try:
        return load_rules(path)
    except RuleError as exc:
        ctx.error(str(exc))
        return None


def _print_problems(ctx: Context, ruleset: RuleSet) -> None:
    for p in ruleset.problems:
        who = f" ({p.rule_id})" if p.rule_id else ""
        ctx.line(_mark(ctx, "bad"), Seg(" "), Seg(f"[{p.file}]", "brown"), Seg(who, "accent"), Seg(" " + p.message))


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" + ("" if n == 1 else "s")


def _summary(ctx: Context, ruleset: RuleSet) -> None:
    n = len(ruleset.problems)
    ctx.line(_mark(ctx, "ok" if n == 0 else "bad"),
             Seg(f" {_count(len(ruleset.chains), 'chain')}, {_count(len(ruleset.indicators), 'indicator')}, {_count(n, 'problem')}",
                 "ok" if n == 0 else "bad", True))


def default_rules_path(explicit: str | None = None) -> str:
    """Rules path: the explicit one, /etc/erinix/rules, or (repository checkouts only) ./rules."""
    if explicit:
        return explicit
    if os.path.isdir(DEFAULT_RULES_DIR):
        return DEFAULT_RULES_DIR
    checkout = Path(__file__).resolve().parents[3] / "rules"   # for development from a repository only
    return str(checkout) if checkout.is_dir() else DEFAULT_RULES_DIR


# ----------------------------------------------------------------- commands
def make_help(registry: Registry):
    def cmd_help(ctx: Context, args: list[str]) -> int:
        if args:
            found = registry.resolve(args)
            if found is None:
                ctx.error(f"unknown command: {safe(' '.join(args))}")
                return 2
            cmd = found[0]
            ctx.line(Seg("usage    ", "brown"), Seg(cmd.usage, "accent", True))
            ctx.line(Seg("summary  ", "brown"), Seg(cmd.summary))
            return 0
        rows: list[list] = []
        for group in GROUP_ORDER:
            members = [c for c in registry.commands if c.group == group]
            if not members:
                continue
            rows.append([Seg(group.upper(), "brown", True), ""])
            rows += [[Seg(c.usage, "accent"), c.summary] for c in members]
        ctx.table(["Command", "What it does"], rows)
        ctx.line(Seg("In the console, type commands without 'erinix' in front. Exit with ", "dim"),
                 Seg("exit", "accent"), Seg(" or Ctrl-D; clear with ", "dim"), Seg("clear", "accent"),
                 Seg(" or Ctrl-L.", "dim"))
        ctx.line(Seg("Coming soon: ", "dim"), Seg(COMING_SOON, "dim"))
        return 0
    return cmd_help


def cmd_version(ctx: Context, args: list[str]) -> int:
    parse_args(args, max_positional=0)
    ctx.say(f"erinix {__version__}")
    return 0


def cmd_doctor(ctx: Context, args: list[str]) -> int:
    _, _, opts = parse_args(args, options=("--rules",), max_positional=0)
    caps = selector.detect()
    plan = selector.choose(caps)
    g = ctx.theme.glyph

    def res(kind: str, text: str) -> Seg:
        return Seg(f"{g(kind)} {text}", kind)

    root = caps.euid == 0
    kernel_detail = caps.kernel_release if caps.kernel_ok_for_ebpf else \
        f"{caps.kernel_release} (eBPF needs at least {selector.MIN_EBPF_KERNEL[0]}.{selector.MIN_EBPF_KERNEL[1]})"
    if caps.auditd_running:
        audit = res("ok", "running")
    elif caps.auditd_installed:
        audit = res("warn", "installed, not running")
    else:
        audit = res("warn", "not installed")
    rules_path = default_rules_path(opts.get("--rules"))
    try:
        rs = load_rules(rules_path)
        n = len(rs.chains) + len(rs.indicators)
        rules_cell = res("ok", _count(n, "rule")) if not rs.problems else res("warn", f"{_count(n, 'rule')}, {_count(len(rs.problems), 'problem')}")
    except RuleError as exc:
        rules_cell = res("warn", "cannot load")
        rules_path = str(exc)       # the message already contains the path
    rows = [
        ["Privileges", res("ok", "root") if root else res("warn", "user"),
         f"euid {caps.euid}" + ("" if root else " · without root Erinix can only observe")],
        ["Kernel", res("ok" if caps.kernel_ok_for_ebpf else "warn", "ok" if caps.kernel_ok_for_ebpf else "old"), kernel_detail],
        ["BTF", res("ok", "present") if caps.btf else res("warn", "missing"), "required for eBPF CO-RE"],
        ["auditd", audit, "fallback sensor"],
        ["Rules", rules_cell, rules_path],
    ]
    ctx.table(["Check", "Result", "Detail"], rows)
    ctx.say()
    label = 26
    mode = MODE_NAMES[plan.mode.value]
    ctx.line(Seg("Sensor in use now".ljust(label), "brown"), Seg(mode, "accent", True),
             Seg("  (rootless)" if plan.rootless else "", "dim"))
    ctx.line(Seg("With root privileges".ljust(label), "brown"), Seg(MODE_NAMES[plan.potential.value], "accent", True))
    ctx.line(Seg("Reason".ljust(label), "brown"), Seg(plan.reason))
    return 0


def cmd_rules_validate(ctx: Context, args: list[str]) -> int:
    pos, _, _ = parse_args(args, max_positional=1)
    path = default_rules_path(pos[0] if pos else None)
    ruleset = _load(ctx, path)
    if ruleset is None:
        return 2
    ctx.line(Seg("rules ", "brown"), Seg(path, "dim"))
    _print_problems(ctx, ruleset)
    _summary(ctx, ruleset)
    return 1 if ruleset.problems else 0


def cmd_rules_list(ctx: Context, args: list[str]) -> int:
    pos, _, _ = parse_args(args, max_positional=1)
    path = default_rules_path(pos[0] if pos else None)
    ruleset = _load(ctx, path)
    if ruleset is None:
        return 2
    ctx.line(Seg("rules ", "brown"), Seg(path, "dim"))
    rows = []
    for c in ruleset.chains:
        top = max((s.severity for s in c.steps), key=lambda s: s.rank)
        resp = max((s.response for s in c.steps), key=_RESPONSE_RANK.get)
        rows.append([Seg(c.id, "accent"), "chain", str(len(c.steps)), f"{c.window_seconds}s",
                     c.link.value, severity_badge(top), response_seg(resp)])
    for i in ruleset.indicators:
        rows.append([Seg(i.id, "accent"), "indicator", "1", "-", "-",
                     severity_badge(i.severity), response_seg(i.response)])
    if rows:
        ctx.table(["Rule", "Type", "Steps", "Window", "Link", "Severity", "Response"], rows)
    _print_problems(ctx, ruleset)
    _summary(ctx, ruleset)
    return 1 if ruleset.problems else 0


def cmd_replay(ctx: Context, args: list[str]) -> int:
    pos, flags, opts = parse_args(args, flags=("--fast",), options=("--rules",), max_positional=1)
    name = pos[0] if pos else "revshell"
    scenario = SCENARIOS.get(name)
    if scenario is None:
        raise UsageError(f"unknown scenario: {safe(name)} (available: {', '.join(SCENARIOS)})")
    ruleset = _load(ctx, default_rules_path(opts.get("--rules")))
    if ruleset is None:
        return 2
    if ruleset.problems:
        _print_problems(ctx, ruleset)
    correlator = Correlator(ruleset)
    events = sorted(scenario.build(), key=lambda e: e.mono_ns)
    delay = 0.0 if "--fast" in flags or not ctx.out.isatty() else 0.35

    ctx.say()
    ctx.line(Seg("Scenario  ", "brown"), Seg(scenario.title, "accent", True))
    ctx.line(Seg(scenario.description, "dim"))
    ctx.say()
    final: dict[str, Alert] = {}
    try:
        for ev in events:
            if delay:
                time.sleep(delay)
            ctx.line(Seg(f"t+{ev.mono_ns / SEC:>5.1f}s", "brown"), Seg("  "),
                     Seg(f"{ev.type.value:<16}", "accent"), Seg("  "), *describe_event(ctx.theme, ev))
            for alert in correlator.process(ev):
                ctx.emit(lambda width, a=alert: alert_panel(ctx.theme, a, width=width))
                final[alert.alert_id] = alert
    except KeyboardInterrupt:
        ctx.say()
        ctx.error("interrupted")
        return 130

    ctx.say()
    stats = correlator.stats
    if final:
        rows = [[Seg(a.rule_id, "accent"), severity_badge(a.severity),
                 f"{a.steps_done}/{a.steps_total}" if a.kind == "chain" else "-",
                 response_seg(a.response), str(a.remote_addr or "-")] for a in final.values()]
        ctx.table(["Alert", "Severity", "Steps", "Response", "Remote"], rows)
    elif not scenario.expect_alerts:
        ctx.line(_mark(ctx, "ok"), Seg(" No alerts: normal activity recognized as such", "ok", True))
    else:
        ctx.line(_mark(ctx, "bad"), Seg(" Alerts were expected but none fired", "bad", True))
    ctx.line(Seg(f"events {stats.events_seen} · alerts {stats.alerts_emitted} · "
                 f"duplicates counted {stats.suppressed_duplicates}", "dim"))
    return 0 if bool(final) == scenario.expect_alerts else 1


# ----------------------------------------------------------------- registry
def build_registry() -> Registry:
    reg = Registry()
    reg.add(Command("help", "List the commands", "help [command]", "General", make_help(reg)))
    reg.add(Command("version", "Show the version", "version", "General", cmd_version))
    reg.add(Command("doctor", "Check what Erinix can use on this machine",
                    "doctor [--rules PATH]", "Diagnostics", cmd_doctor, arg_words=("--rules",)))
    reg.add(Command("rules validate", "Validate a rules file or folder",
                    "rules validate [path]", "Rules", cmd_rules_validate))
    reg.add(Command("rules list", "List the loaded rules",
                    "rules list [path]", "Rules", cmd_rules_list))
    reg.add(Command("replay", "Replay a simulated attack and show the alerts",
                    "replay [scenario] [--fast] [--rules PATH]", "Demo", cmd_replay,
                    arg_words=tuple(SCENARIOS) + ("--fast", "--rules")))
    return reg
