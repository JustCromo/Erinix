"""Viste riutilizzabili: alert, stati."""

from __future__ import annotations

from erinix.engine.alerts import Alert
from erinix.rules import Response, Severity
from erinix.ui.render import Seg, panel, progress
from erinix.ui.theme import Theme

SEVERITY_ROLE = {Severity.LOW: "ok", Severity.MEDIUM: "warn", Severity.HIGH: "bad", Severity.CRITICAL: "crit"}
RESPONSE_ROLE = {Response.AUTO: "bad", Response.INTERACTIVE: "warn", Response.REPORT_ONLY: "dim"}


def severity_badge(severity: Severity) -> Seg:
    label = severity.value.upper()
    return Seg(f" {label} " if severity is Severity.CRITICAL else label, SEVERITY_ROLE[severity], True)


def response_seg(response: Response) -> Seg:
    return Seg(response.value, RESPONSE_ROLE[response], response is Response.AUTO)


def alert_panel(theme: Theme, alert: Alert, *, width: int | None = None) -> str:
    title = [severity_badge(alert.severity), Seg(" "), Seg(alert.rule_id, "accent", True)]
    border = {"low": "border", "medium": "border", "high": "border", "critical": "bad"}[alert.severity.value]
    if alert.kind == "engine":
        lines = [[Seg(alert.description, "bad")], [Seg(alert.detail, "dim")]]
        return panel(theme, title, lines, width=width, border=border)
    lines: list[list[Seg]] = []
    if alert.kind == "chain":
        lines.append([*progress(theme, alert.steps_done, alert.steps_total),
                      Seg(f" {alert.steps_done}/{alert.steps_total}  ", "brown"),
                      Seg(alert.step_id, None, True),
                      Seg("  (completa)" if alert.complete else "", "dim")])
    else:
        lines.append([Seg("indicatore", "brown")])
    if alert.description:
        lines.append([Seg(alert.description, "dim")])
    meta = [Seg("risposta ", "brown"), response_seg(alert.response)]
    if alert.mitre:
        meta += [Seg("   MITRE ", "brown"), Seg(" ".join(alert.mitre))]
    lines.append(meta)
    where: list[Seg] = []
    if alert.remote_addr is not None:
        where += [Seg("remoto ", "brown"), Seg(str(alert.remote_addr))]
    if alert.anchor is not None:
        where += [Seg("   " if where else "", "brown"), Seg("radice pid ", "brown"), Seg(str(alert.anchor.pid))]
    if where:
        lines.append(where)
    right = [Seg(f"rev {alert.revision}", "dim")] if alert.kind == "chain" else []
    return panel(theme, title, lines, right=right, width=width, border=border)


def describe_event(theme: Theme, event) -> list[Seg]:
    """Descrizione breve di un evento, per la cronologia di `replay`."""
    from erinix.core.events import AuthInfo, EventType, FileInfo, NetInfo, PrivInfo

    p, pl = event.process, event.payload
    who = ""
    if p is not None:
        who = f"{p.exe.value.rsplit('/', 1)[-1] or p.comm.value}({p.key.pid})"
    arrow = theme.glyph("arrow")
    if event.type is EventType.PROCESS_EXEC and p is not None:
        parent = f", padre {p.parent.pid}" if p.parent else ""
        return [Seg(p.exe.value), Seg(f"  pid {p.key.pid}{parent}", "dim")]
    if isinstance(pl, NetInfo):
        return [Seg(who), Seg(f" {arrow} {pl.remote_addr}:{pl.remote_port}")]
    if isinstance(pl, PrivInfo):
        return [Seg(who), Seg(f"  uid {pl.old_uid} {arrow} {pl.new_uid} ({pl.method.value})")]
    if isinstance(pl, FileInfo):
        return [Seg(f"{pl.operation} {pl.path.value}"), Seg(f"  {who}", "dim")]
    if isinstance(pl, AuthInfo):
        return [Seg(f"{pl.service.value} utente {pl.user.value} da {pl.remote_addr}")]
    return [Seg(event.type.value)]
