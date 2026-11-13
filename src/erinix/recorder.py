"""Glue between the engine and the store: every event is recorded, every alert is saved.

An event that completes (or counts toward) an attack step is linked to its alert, so the
live view can colour it and the alert can show "what happened, step by step".
"""

from __future__ import annotations

from erinix.core.events import Event
from erinix.describe import describe
from erinix.engine import Correlator
from erinix.engine.alerts import Alert
from erinix.store import SEVERITY_RANK, Store


class Recorder:
    def __init__(self, store: Store, correlator: Correlator) -> None:
        self.store = store
        self.correlator = correlator

    def feed(self, event: Event) -> list[Alert]:
        alerts = self.correlator.process(event)
        link: tuple[str, str, str] | None = None
        for alert in alerts:
            for step, ids in alert.evidence:
                if event.id in ids and (link is None or SEVERITY_RANK[alert.severity.value] > SEVERITY_RANK[link[2]]):
                    link = (alert.alert_id, step, alert.severity.value)
        label, summary, remote = describe(event)
        ts = event.wall_ns / 1e9
        self.store.add_event(event_id=event.id, ts=ts, kind=event.type.value, label=label, summary=summary, remote=remote,
                             source=event.source.value, alert_id=link[0] if link else None, step=link[1] if link else None,
                             severity=link[2] if link else None)
        for alert in alerts:
            self.store.upsert_alert(alert, now=ts)
            for step, ids in alert.evidence:                      # earlier hits of a step become part of the attack now
                self.store.link_events(list(ids), alert.alert_id, step, alert.severity.value)
        self.store.bump(events=1, alerts=len(alerts), now=ts)
        return alerts
