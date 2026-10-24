"""Alert prodotti dal motore di correlazione."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from erinix.core.events import ProcessKey
from erinix.rules import Response, Severity

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True, slots=True)
class Alert:
    """Un alert per ogni catena in corso: si AGGIORNA, non si duplica.

    Lo stesso `alert_id` con `revision` crescente descrive la stessa catena
    man mano che avanza (gravità progressiva).
    """

    alert_id: str
    revision: int
    rule_id: str
    kind: str                      # "chain" | "indicator" | "engine"
    severity: Severity
    response: Response             # livello di risposta del passo appena raggiunto
    steps_done: int
    steps_total: int
    step_id: str
    complete: bool
    mitre: tuple[str, ...]
    description: str
    evidence: tuple[tuple[str, tuple[str, ...]], ...]   # (id passo, id evento)
    process: ProcessKey | None     # processo dell'evento che ha fatto scattare l'alert
    anchor: ProcessKey | None      # radice della catena (legame process_tree)
    remote_addr: IPAddress | None
    mono_ns: int
    wall_ns: int
    detail: str = ""
