"""Process tree with bounded memory.

The engine uses it to answer "does this process descend from that one?",
which is the main link between the steps of a chain.

Reliability: the size is bounded. When space is needed, already-exited
processes are removed first; if that is not enough, the oldest live ones are
removed and COUNTED (evicted_live), so the sensor can declare that the tree is
incomplete instead of staying silent.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from erinix.core.events import ProcessInfo, ProcessKey

DEFAULT_MAX_ENTRIES = 65536
MAX_DEPTH = 128  # guard against anomalous chains or cycles in the data


@dataclass(slots=True)
class _Node:
    info: ProcessInfo
    exited_ns: int | None = None


class ProcessTree:
    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max = max_entries
        self._nodes: OrderedDict[ProcessKey, _Node] = OrderedDict()
        self._exited: OrderedDict[ProcessKey, None] = OrderedDict()
        self.evicted_live = 0

    def __len__(self) -> int:
        return len(self._nodes)

    def __contains__(self, key: ProcessKey) -> bool:
        return key in self._nodes

    def on_exec(self, info: ProcessInfo) -> None:
        """Record a process, or update its image after an execve."""
        node = self._nodes.get(info.key)
        if node is not None:
            # execve changes neither the PID nor the start time: same process, new image.
            # The known parent stays the one recorded first.
            parent = node.info.parent or info.parent
            node.info = ProcessInfo(
                key=info.key, parent=parent, uid=info.uid, euid=info.euid,
                loginuid=info.loginuid, exe=info.exe, argv=info.argv,
                argv_truncated=info.argv_truncated, comm=info.comm,
            )
            return
        self._nodes[info.key] = _Node(info)
        self._evict_if_needed()

    def on_exit(self, key: ProcessKey, exited_ns: int) -> None:
        node = self._nodes.get(key)
        if node is None or node.exited_ns is not None:
            return
        node.exited_ns = exited_ns
        self._exited[key] = None

    def get(self, key: ProcessKey) -> ProcessInfo | None:
        node = self._nodes.get(key)
        return node.info if node else None

    def is_alive(self, key: ProcessKey) -> bool:
        node = self._nodes.get(key)
        return node is not None and node.exited_ns is None

    def ancestors(self, key: ProcessKey) -> list[ProcessKey]:
        """Ancestors from the direct parent upwards (safe against cycles)."""
        result: list[ProcessKey] = []
        seen = {key}
        node = self._nodes.get(key)
        while node is not None and node.info.parent is not None and len(result) < MAX_DEPTH:
            parent = node.info.parent
            if parent in seen:
                break
            seen.add(parent)
            result.append(parent)
            node = self._nodes.get(parent)
        return result

    def is_descendant(self, key: ProcessKey, ancestor: ProcessKey) -> bool:
        """True if `key` is `ancestor` or descends from it."""
        return key == ancestor or ancestor in self.ancestors(key)

    def _evict_if_needed(self) -> None:
        while len(self._nodes) > self._max:
            if self._exited:
                victim, _ = self._exited.popitem(last=False)
            else:
                victim = next(iter(self._nodes))
                self.evicted_live += 1
            self._nodes.pop(victim, None)
