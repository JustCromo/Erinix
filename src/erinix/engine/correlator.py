"""Correlation engine: advances the chains with every event.

How it works
- Each chain has one INSTANCE per "story": for the process_tree link it is the
  root (the process that satisfied the first step); for login_session the
  session; for remote_ip the address.
- Steps must be completed IN ORDER. A step with `count` N needs N events inside
  a SLIDING WINDOW of `window_seconds` (like fail2ban).
- After the first step the whole chain must finish within `window_seconds` of
  its start, otherwise the instance expires and a new story can begin.
- One alert per chain: it is updated (same alert_id, growing revision) at every
  completed step, with severity = the highest among the completed steps.

Reliability (no silent drops)
- Memory is bounded per rule. At the limit, ONLY candidates that have not yet
  completed any step are sacrificed, oldest first; chains that already advanced
  are never touched. If there is nothing to sacrifice, the new candidate is
  refused.
- Every sacrifice or refusal is COUNTED (Stats) and raises a critical
  "engine-overload" alert (at most one per minute): a flood is an attack signal.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass

from erinix.core.events import Event, EventType
from erinix.core.process_tree import ProcessTree
from erinix.engine.alerts import Alert
from erinix.engine.matching import matches
from erinix.rules import Chain, Indicator, Link, Response, RuleSet, Severity

NS = 1_000_000_000
DEFAULT_MAX_PER_RULE = 1024
SWEEP_INTERVAL_NS = NS
OVERLOAD_ALERT_INTERVAL_NS = 60 * NS
MAX_EVIDENCE_IDS = 16
MAX_INDICATOR_MEMORY = 4096
INDICATOR_DEDUP_NS = 300 * NS      # the same rule for the same source alerts again after 5 minutes
OVERLOAD_RULE_ID = "engine-overload"


@dataclass(slots=True)
class Stats:
    events_seen: int = 0
    alerts_emitted: int = 0
    evicted_instances: int = 0
    refused_instances: int = 0
    suppressed_duplicates: int = 0


class _Instance:
    __slots__ = ("chain", "key", "anchor", "alert_id", "revision", "reached", "hits",
                 "start_mono", "evidence", "remote")

    def __init__(self, chain: Chain, key: object, anchor, start_mono: int) -> None:
        self.chain = chain
        self.key = key
        self.anchor = anchor
        self.alert_id = uuid.uuid4().hex
        self.revision = 0
        self.reached = 0
        self.hits: deque[tuple[int, str]] = deque()
        self.start_mono = start_mono
        self.evidence: list[tuple[str, tuple[str, ...]]] = []
        self.remote = None   # last remote address seen: stays in the alert at later steps too


class Correlator:
    def __init__(self, rules: RuleSet, tree: ProcessTree | None = None, *,
                 max_per_rule: int = DEFAULT_MAX_PER_RULE) -> None:
        if max_per_rule < 1:
            raise ValueError("max_per_rule must be >= 1")
        # Careful: an empty ProcessTree is "falsy" (it has __len__), so no `tree or ...`.
        self.tree = tree if tree is not None else ProcessTree()
        self.stats = Stats()
        self._max = max_per_rule
        self._indicators: dict[EventType, list[Indicator]] = defaultdict(list)
        for ind in rules.indicators:
            self._indicators[ind.event].append(ind)
        self._chains: dict[EventType, list[Chain]] = defaultdict(list)
        for chain in rules.chains:
            for event_type in dict.fromkeys(s.event for s in chain.steps):
                self._chains[event_type].append(chain)
        self._instances: dict[tuple[str, object], _Instance] = {}
        self._candidates: dict[str, OrderedDict[object, None]] = defaultdict(OrderedDict)
        self._count: dict[str, int] = defaultdict(int)
        self._seen_indicators: OrderedDict[tuple, int] = OrderedDict()   # (rule, source) -> last alert time
        self._last_sweep = 0
        self._last_overload: int | None = None

    # ------------------------------------------------------------ entry point
    def process(self, event: Event) -> list[Alert]:
        self.stats.events_seen += 1
        self._learn(event)
        self._sweep(event.mono_ns)
        alerts: list[Alert] = []
        for ind in self._indicators.get(event.type, ()):
            if matches(ind.match, event, self.tree):
                alert = self._indicator_alert(ind, event)
                if alert is not None:
                    alerts.append(alert)
        for chain in self._chains.get(event.type, ()):
            alerts.extend(self._advance(chain, event))
        self.stats.alerts_emitted += len(alerts)
        return alerts

    @property
    def open_instances(self) -> int:
        return len(self._instances)

    # ----------------------------------------------------------- internals
    def _learn(self, event: Event) -> None:
        p = event.process
        if p is None:
            return
        if event.type is EventType.PROCESS_EXEC:
            self.tree.on_exec(p)
        elif event.type is EventType.PROCESS_EXIT:
            self.tree.on_exit(p.key, event.mono_ns)
        elif p.key not in self.tree:
            self.tree.on_exec(p)  # process started before us: we learn it

    def _sweep(self, now: int) -> None:
        if now - self._last_sweep < SWEEP_INTERVAL_NS:
            return
        self._last_sweep = now
        for inst in list(self._instances.values()):
            if self._expired(inst, now):
                self._remove(inst)

    def _prune(self, inst: _Instance, now: int) -> None:
        limit = inst.chain.window_seconds * NS
        while inst.hits and now - inst.hits[0][0] > limit:
            inst.hits.popleft()

    def _expired(self, inst: _Instance, now: int) -> bool:
        if inst.reached == 0:
            self._prune(inst, now)
            return not inst.hits
        return now - inst.start_mono > inst.chain.window_seconds * NS

    def _remove(self, inst: _Instance) -> None:
        if self._instances.pop((inst.chain.id, inst.key), None) is None:
            return
        self._count[inst.chain.id] -= 1
        self._candidates[inst.chain.id].pop(inst.key, None)

    @staticmethod
    def _link_key(chain: Chain, event: Event) -> object | None:
        if chain.link is Link.REMOTE_IP:
            return getattr(event.payload, "remote_addr", None)
        if event.process is None:
            return None
        if chain.link is Link.LOGIN_SESSION:
            return event.process.loginuid
        return event.process.key  # process_tree: candidate root

    def _find(self, chain: Chain, event: Event) -> _Instance | None:
        if chain.link is Link.PROCESS_TREE:
            p = event.process
            if p is None:
                return None
            for key in (p.key, *self.tree.ancestors(p.key)):
                inst = self._instances.get((chain.id, key))
                if inst is not None:
                    return inst
            return None
        key = self._link_key(chain, event)
        return None if key is None else self._instances.get((chain.id, key))

    def _advance(self, chain: Chain, event: Event) -> list[Alert]:
        inst = self._find(chain, event)
        if inst is not None and self._expired(inst, event.mono_ns):
            self._remove(inst)
            inst = None
        alerts: list[Alert] = []
        if inst is None:
            first = chain.steps[0]
            if first.event is not event.type or not matches(first.match, event, self.tree):
                return []
            key = self._link_key(chain, event)
            if key is None:
                return []
            inst, extra = self._create(chain, key, event)
            alerts.extend(extra)
            if inst is None:
                return alerts
        alerts.extend(self._feed(inst, event))
        return alerts

    def _create(self, chain: Chain, key: object, event: Event) -> tuple[_Instance | None, list[Alert]]:
        alerts: list[Alert] = []
        if self._count[chain.id] >= self._max:
            candidates = self._candidates[chain.id]
            if candidates:
                victim = self._instances[(chain.id, next(iter(candidates)))]
                self._remove(victim)
                self.stats.evicted_instances += 1
                alerts.extend(self._overload_alert(chain, event))
            else:
                self.stats.refused_instances += 1
                return None, self._overload_alert(chain, event)
        anchor = event.process.key if chain.link is Link.PROCESS_TREE and event.process else None
        inst = _Instance(chain, key, anchor, event.mono_ns)
        self._instances[(chain.id, key)] = inst
        self._count[chain.id] += 1
        self._candidates[chain.id][key] = None
        return inst, alerts

    def _feed(self, inst: _Instance, event: Event) -> list[Alert]:
        chain = inst.chain
        if inst.reached >= len(chain.steps):
            return []
        step = chain.steps[inst.reached]
        if step.event is not event.type or not matches(step.match, event, self.tree):
            return []
        now = event.mono_ns
        seen = getattr(event.payload, "remote_addr", None)
        if seen is not None:
            inst.remote = seen
        inst.hits.append((now, event.id))
        self._prune(inst, now)
        if inst.reached == 0 and inst.key in self._candidates[chain.id]:
            self._candidates[chain.id].move_to_end(inst.key)
        if len(inst.hits) < step.count:
            return []
        if inst.reached == 0:
            inst.start_mono = inst.hits[0][0]
        inst.evidence.append((step.id, tuple(i for _, i in list(inst.hits)[-MAX_EVIDENCE_IDS:])))
        inst.reached += 1
        inst.hits.clear()
        if inst.reached == 1:
            self._candidates[chain.id].pop(inst.key, None)  # advanced: protected from eviction
        inst.revision += 1
        return [self._chain_alert(inst, step.id, event)]

    def _chain_alert(self, inst: _Instance, step_id: str, event: Event) -> Alert:
        chain = inst.chain
        done = chain.steps[: inst.reached]
        severity = max((s.severity for s in done), key=lambda s: s.rank)
        remote = inst.remote
        if isinstance(inst.key, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            remote = inst.key
        return Alert(
            alert_id=inst.alert_id, revision=inst.revision, rule_id=chain.id, kind="chain",
            severity=severity, response=done[-1].response, steps_done=inst.reached,
            steps_total=len(chain.steps), step_id=step_id,
            complete=inst.reached == len(chain.steps), mitre=chain.mitre,
            description=chain.description, evidence=tuple(inst.evidence),
            process=event.process.key if event.process else None, anchor=inst.anchor,
            remote_addr=remote, mono_ns=event.mono_ns, wall_ns=event.wall_ns,
        )

    def _indicator_alert(self, ind: Indicator, event: Event) -> Alert | None:
        who = event.process.key if event.process else getattr(event.payload, "remote_addr", None)
        if who is not None:
            ident = (ind.id, who)
            last = self._seen_indicators.get(ident)
            if last is not None and event.mono_ns - last < INDICATOR_DEDUP_NS:
                self._seen_indicators.move_to_end(ident)
                self.stats.suppressed_duplicates += 1        # counted, never silent
                return None
            self._seen_indicators[ident] = event.mono_ns
            self._seen_indicators.move_to_end(ident)
            while len(self._seen_indicators) > MAX_INDICATOR_MEMORY:
                self._seen_indicators.popitem(last=False)
        return Alert(
            alert_id=uuid.uuid4().hex, revision=1, rule_id=ind.id, kind="indicator",
            severity=ind.severity, response=ind.response, steps_done=1, steps_total=1,
            step_id=ind.id, complete=True, mitre=ind.mitre, description=ind.description,
            evidence=((ind.id, (event.id,)),),
            process=event.process.key if event.process else None, anchor=None,
            remote_addr=getattr(event.payload, "remote_addr", None),
            mono_ns=event.mono_ns, wall_ns=event.wall_ns,
        )

    def _overload_alert(self, chain: Chain, event: Event) -> list[Alert]:
        last = self._last_overload
        if last is not None and event.mono_ns - last < OVERLOAD_ALERT_INTERVAL_NS:
            return []
        self._last_overload = event.mono_ns
        return [Alert(
            alert_id=uuid.uuid4().hex, revision=1, rule_id=OVERLOAD_RULE_ID, kind="engine",
            severity=Severity.CRITICAL, response=Response.REPORT_ONLY, steps_done=0,
            steps_total=0, step_id="", complete=True, mitre=(),
            description="Correlation engine at capacity: possible attempt to blind the IDS.",
            evidence=(), process=None, anchor=None, remote_addr=None,
            mono_ns=event.mono_ns, wall_ns=event.wall_ns,
            detail=(f"rule={chain.id} evicted={self.stats.evicted_instances} "
                    f"refused={self.stats.refused_instances}"),
        )]
