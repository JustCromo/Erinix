"""Plain-language view of the store: what every screen (console, dashboard, scripts) shows.

Technical details are always kept, but behind a "technical" section: the first
thing a person reads is what happened, why it matters and what to do.
"""

from __future__ import annotations

import time

from erinix import __version__
from erinix.store import SEVERITY_RANK, Store

STALE_AFTER = 30.0            # seconds without a heartbeat before the agent counts as stopped
ATTENTION_LIMIT = 5
NO_ADDRESS = "an unknown address"


def expand(text: str, remote: str | None) -> str:
    """Fill the one placeholder rules may use."""
    return text.replace("{remote}", remote or NO_ADDRESS)


def humanize(row: dict) -> dict:
    """An alert row -> what a person needs: headline, why, next steps; technical details apart."""
    remote = row.get("remote")
    headline = expand(row["title"], remote) if row["title"] else (row["description"] or row["rule_id"])
    chain = row["kind"] == "chain"
    return {
        "id": row["alert_id"],
        "tag": row.get("tag", ""), "area": row.get("area", ""),
        "headline": headline,
        "why": expand(row["why"], remote) if row["why"] else row["description"],
        "next_steps": [expand(s, remote) for s in row["next_steps"]],
        "severity": row["severity"],
        "status": row["status"],
        "first_seen": row["first_seen"],
        "updated": row["updated"],
        "remote": remote,
        "progress": {"done": row["steps_done"], "total": row["steps_total"], "complete": row["complete"]} if chain else None,
        "technical": {
            "rule": row["rule_id"], "kind": row["kind"], "description": row["description"],
            "response": row["response"], "step": row["step_id"], "mitre": row["mitre"],
            "anchor_pid": row["anchor_pid"], "revision": row["revision"], "evidence": row["evidence"],
            "detail": row["detail"],
        },
    }


def _steps_and_timeline(store: Store, row: dict) -> tuple[list[dict], list[dict]]:
    """For a chain: every step as done / current / pending, with the event that completed it.
    For every alert: the events that belong to it, oldest first."""
    linked = store.events_for_alert(row["alert_id"])
    timeline = [{"id": e["id"], "time": e["ts"], "label": e["label"], "summary": e["summary"], "remote": e["remote"],
                 "step": e["step"], "severity": e["severity"]} for e in linked]
    if row["kind"] != "chain":
        return [], timeline
    labels, evidence = row["step_labels"], row["evidence"]
    steps: list[dict] = []
    for i in range(row["steps_total"]):
        done = i < row["steps_done"]
        label = (labels[i] if i < len(labels) and labels[i] else "") or (
            evidence[i][0].replace("-", " ").capitalize() if i < len(evidence) else f"Step {i + 1}")
        step = {"index": i + 1, "label": label, "state": "done" if done else "current" if i == row["steps_done"] and not row["complete"] else "pending",
                "time": None, "detail": "", "count": 0}
        if done and i < len(evidence) and evidence[i][1]:
            ids = evidence[i][1]
            last = store.events_by_event_id(ids[-1:]).get(ids[-1])
            step["count"] = len(ids)
            if last:
                step["time"] = last["ts"]
                step["detail"] = last["summary"]
        steps.append(step)
    return steps, timeline


def humanize_full(store: Store, row: dict) -> dict:
    """humanize() plus the live timeline (steps for chains, linked events for every alert)."""
    data = humanize(row)
    data["steps"], data["timeline"] = _steps_and_timeline(store, row)
    return data


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def build_overview(store: Store, *, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    counts = store.counts()
    by = counts["open_by_severity"]
    sources = store.get_meta("sources", []) or []
    mode = store.get_meta("mode", None)
    heartbeat = store.get_meta("heartbeat", None)
    age = None if not isinstance(heartbeat, (int, float)) else max(0.0, now - heartbeat)
    demo = mode == "demo"
    running = demo or (mode == "live" and age is not None and age < STALE_AFTER)

    if not running:
        state, headline = "stopped", "Erinix is not running"
    elif by["critical"]:
        state, headline = "critical", "Needs your attention now"
    elif counts["open"]:
        n = counts["open"]
        state, headline = "attention", f"{n} {_plural(n, 'thing needs', 'things need')} attention"
    else:
        state = "protected"
        headline = "Demo data loaded: nothing needs attention" if demo else "Protected: nothing needs your attention"

    blind = [f"{s.get('name', '?')}: {s.get('detail') or s.get('state', 'unknown')}"
             for s in sources if isinstance(s, dict) and s.get("state") != "ok"]
    extra = store.get_meta("blind_spots", []) or []
    blind += [str(b) for b in extra if isinstance(b, str)]
    if not sources and not demo:
        blind.append("Nothing is being watched yet. Start the agent, or load demo data with: erinix demo")

    from erinix import palettes
    from erinix.incidents import build_incidents

    attention = [humanize_full(store, r) for r in store.list_alerts("open", limit=ATTENTION_LIMIT)]
    incidents = build_incidents(store, "open")
    chosen = store.get_meta("theme", None)
    activity = store.activity(now=now)
    return {
        "state": state, "headline": headline, "demo": demo, "mode": mode or "none",
        "since": store.get_meta("started", None), "heartbeat_age": age,
        "open": {"total": counts["open"], **by}, "dismissed": counts["dismissed"],
        "attention": attention,
        "events_24h": sum(p["events"] for p in activity), "alerts_24h": sum(p["alerts"] for p in activity),
        "activity": activity, "sources": [s for s in sources if isinstance(s, dict)],
        "blind_spots": blind, "version": __version__,
        "incidents": {"open": len(incidents), "top": incidents[:3]},
        "theme": chosen if palettes.is_known(chosen) else palettes.DEFAULT, "themes": palettes.info(),
    }


_INVENTORY_CAPS = {"processes": 400, "listening": 300, "connections": 300}


def _clean(value: object, depth: int = 0) -> object:
    """Numbers, booleans and short text only: whatever is stored is shown, never trusted."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value[:400]
    if isinstance(value, dict) and depth < 3:
        return {str(k)[:40]: _clean(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, list) and depth < 3:
        return [_clean(v, depth + 1) for v in value[:400]]
    return None


def empty_inventory() -> dict:
    return {"available": False, "host": {}, "processes": [], "process_total": 0, "listening": [], "connections": [], "at": None}


def build_inventory(store: Store) -> dict:
    """What the agent sees on the machine right now: host, programs, listening ports, connections."""
    raw = store.get_meta("inventory", None)
    if not isinstance(raw, dict):
        return empty_inventory()
    out: dict = {"available": True}
    for key in ("host", "at", "process_total"):
        out[key] = _clean(raw.get(key, {} if key == "host" else None))
    for key, cap in _INVENTORY_CAPS.items():
        rows = raw.get(key, [])
        out[key] = [_clean(r) for r in rows[:cap] if isinstance(r, dict)] if isinstance(rows, list) else []
    return out


def _palette_info() -> list[dict]:
    from erinix import palettes

    return palettes.info()


def empty_overview() -> dict:
    """What every screen shows before any data exists."""
    return {"state": "stopped", "headline": "Erinix is not running", "demo": False, "mode": "none", "since": None,
            "heartbeat_age": None, "open": {"total": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
            "dismissed": 0, "attention": [], "events_24h": 0, "alerts_24h": 0, "activity": [], "sources": [],
            "blind_spots": ["Nothing is being watched yet. Start the agent, or load demo data with: erinix demo"],
            "version": __version__, "incidents": {"open": 0, "top": []}, "theme": "auto", "themes": _palette_info()}


def ago(epoch: float, now: float | None = None) -> str:
    seconds = max(0, int((time.time() if now is None else now) - epoch))
    if seconds < 10:
        return "just now"
    if seconds < 60:
        return f"{seconds} s ago"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


def live_state(path: object = None) -> tuple[str, str]:
    """(state, one-line text) read from the store: for the console status bar and welcome screen."""
    from erinix.store import StoreError

    try:
        with Store(path, readonly=True) as store:
            o = build_overview(store)
    except (StoreError, OSError, ValueError):
        return "stopped", "No data yet"
    text = o["headline"]
    if o["state"] == "critical" and o["open"]["total"] > 1:
        text += f" ({o['open']['total']} open)"
    return o["state"], text + (" · demo" if o["demo"] else "")


def severity_rank(name: str) -> int:
    return SEVERITY_RANK.get(name, 0)
