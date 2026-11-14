"""Incidents: alerts grouped by who is behind them.

One attacker (an address) doing six different things is ONE incident with six attacks inside,
not six unrelated alerts. Alerts with no address (a program on this machine misbehaving) form
the incident "This machine". Types of attack are shown as tags, so a person can both find
"everything from this address" and "every SQL injection".
"""

from __future__ import annotations

import hashlib
import time

from erinix.store import SEVERITY_RANK, Store
from erinix.summary import humanize_full

MAX_ALERTS = 200
MAX_TIMELINE = 120
MAX_NEXT = 5
LOCAL = "This machine"
AREA_PHRASE = {"website": "your website", "logins": "your logins", "this machine": "this machine", "": "your system", "system": "your system"}


def group_key(row: dict) -> str:
    return f"ip:{row['remote']}" if row.get("remote") else "local"


def incident_id(key: str) -> str:
    return "i" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:10]


def _rank(row: dict) -> int:
    return SEVERITY_RANK.get(row["severity"], 0)


def _groups(store: Store) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for row in store.list_alerts("all", limit=MAX_ALERTS):
        groups.setdefault(group_key(row), []).append(row)
    return groups


def _headline(who: str, local: bool, rows: list[dict], top: dict) -> str:
    if len(rows) == 1:
        return humanize_full_headline(top)
    areas = {r.get("area", "") for r in rows} - {""}
    area = AREA_PHRASE["system" if len(areas) != 1 else next(iter(areas))]
    if local:
        return f"{len(rows)} suspicious things happened on this machine"
    return f"Someone at {who} tried {len(rows)} different attacks on {area}"


def humanize_full_headline(row: dict) -> str:
    from erinix.summary import expand

    return expand(row["title"], row.get("remote")) if row["title"] else (row["description"] or row["rule_id"])


def _summary_of(key: str, rows: list[dict]) -> dict:
    local = key == "local"
    who = LOCAL if local else key[3:]
    open_rows = [r for r in rows if r["status"] == "open"]
    basis = open_rows or rows
    top = max(basis, key=lambda r: (_rank(r), r["updated"]))
    tags: list[str] = []
    for r in sorted(basis, key=lambda r: (-_rank(r), -r["updated"])):
        if r.get("tag") and r["tag"] not in tags:
            tags.append(r["tag"])
    from erinix.summary import expand

    why = expand(top["why"], top.get("remote")) if top["why"] else top["description"]
    summary = why if len(rows) == 1 else f"Most serious: {humanize_full_headline(top)}. {why}"
    areas = {r.get("area", "") for r in rows} - {""}
    return {
        "id": incident_id(key), "who": who, "local": local, "severity": top["severity"],
        "status": "open" if open_rows else "closed",
        "headline": _headline(who, local, rows, top), "summary": summary, "tags": tags,
        "area": next(iter(areas)) if len(areas) == 1 else "system" if areas else "",
        "alert_count": len(rows), "open_alerts": len(open_rows),
        "first_seen": min(r["first_seen"] for r in rows), "updated": max(r["updated"] for r in rows),
    }


def build_incidents(store: Store, status: str = "open") -> list[dict]:
    """Incident summaries, the most serious (then the most recent) first."""
    if status not in ("open", "closed", "all"):
        raise ValueError("unknown status")
    items = [_summary_of(key, rows) for key, rows in _groups(store).items()]
    if status != "all":
        items = [i for i in items if i["status"] == status]
    return sorted(items, key=lambda i: (-SEVERITY_RANK.get(i["severity"], 0), -i["updated"]))


def incident_detail(store: Store, wanted_id: str) -> dict | None:
    """Everything about one incident: its attacks (with their steps), the events in order, what to do."""
    for key, rows in _groups(store).items():
        if incident_id(key) != wanted_id:
            continue
        data = _summary_of(key, rows)
        ordered = sorted(rows, key=lambda r: r["first_seen"])
        alerts = [humanize_full(store, r) for r in ordered]
        events = []
        for alert in alerts:
            for e in alert["timeline"]:
                events.append({**e, "tag": alert["tag"], "alert": alert["id"], "attack": alert["headline"]})
        events.sort(key=lambda e: (e["time"], e["id"]))
        steps: list[str] = []
        for alert in sorted(alerts, key=lambda a: -SEVERITY_RANK.get(a["severity"], 0)):
            for step in alert["next_steps"]:
                if step not in steps:
                    steps.append(step)
        data.update(alerts=alerts, timeline=events[-MAX_TIMELINE:], next_steps=steps[:MAX_NEXT])
        return data
    return None


def set_incident_status(store: Store, wanted_id: str, status: str) -> int:
    """Close (all its alerts dismissed) or reopen an incident. Returns how many alerts changed."""
    if status not in ("open", "closed"):
        raise ValueError("unknown status")
    target = "open" if status == "open" else "dismissed"
    changed = 0
    for key, rows in _groups(store).items():
        if incident_id(key) == wanted_id:
            for row in rows:
                if row["status"] != target and store.set_alert_status(row["alert_id"], target):
                    changed += 1
    return changed
