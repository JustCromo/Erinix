"""Alerts produced by the correlation engine."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from erinix.core.events import ProcessKey
from erinix.rules import Response, Severity

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True, slots=True)
class Alert:
    """One alert per chain in progress: it is UPDATED, not duplicated.

    The same `alert_id` with a growing `revision` describes the same chain as it
    advances (progressive severity).
    """

    alert_id: str
    revision: int
    rule_id: str
    kind: str                      # "chain" | "indicator" | "engine"
    severity: Severity
    response: Response             # response level of the step just reached
    steps_done: int
    steps_total: int
    step_id: str
    complete: bool
    mitre: tuple[str, ...]
    description: str
    evidence: tuple[tuple[str, tuple[str, ...]], ...]   # (step id, event ids)
    process: ProcessKey | None     # process of the event that triggered the alert
    anchor: ProcessKey | None      # root of the chain (process_tree link)
    remote_addr: IPAddress | None
    mono_ns: int
    wall_ns: int
    detail: str = ""
    title: str = ""                 # plain-language headline from the rule ({remote} still in it)
    why: str = ""
    next_steps: tuple[str, ...] = ()
    step_labels: tuple[str, ...] = ()   # plain-language name of every step of the chain, in order
