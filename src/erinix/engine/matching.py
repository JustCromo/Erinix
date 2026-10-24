"""Confronto tra un evento e le condizioni 'match' di una regola.

Solo confronti esatti, prefissi e appartenenza a liste: nessuna espressione
regolare. Un campo sconosciuto non corrisponde MAI (fallisce chiuso).

Nota per i sensori: i percorsi devono arrivare già risolti (canonici) e
l'eseguibile deve essere quello visto dal kernel, non quello dichiarato.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from erinix.core.events import AuthInfo, Event, FileInfo, NetInfo, PrivInfo, ProcessInfo
from erinix.core.process_tree import ProcessTree

_Check = Callable[[Any, "ProcessInfo | None", Any, ProcessTree], bool]


def _parent_exe(w, p, pl, tree) -> bool:
    if p is None or p.parent is None:
        return False
    info = tree.get(p.parent)
    return info is not None and info.exe.value in w


def _ancestor_exe(w, p, pl, tree) -> bool:
    if p is None:
        return False
    for key in tree.ancestors(p.key):
        info = tree.get(key)
        if info is not None and info.exe.value in w:
            return True
    return False


_CHECKS: dict[str, _Check] = {
    "exe": lambda w, p, pl, t: p is not None and p.exe.value in w,
    "exe_prefix": lambda w, p, pl, t: p is not None and bool(p.exe.value) and p.exe.value.startswith(w),
    # exe sconosciuto (sensore che non lo vede) non conta come "inatteso".
    "exe_not": lambda w, p, pl, t: p is not None and bool(p.exe.value) and p.exe.value not in w,
    "parent_exe": _parent_exe,
    "ancestor_exe": _ancestor_exe,
    "argv_has": lambda w, p, pl, t: p is not None and any(a.value in w for a in p.argv),
    "from_login_session": lambda w, p, pl, t: p is not None and p.from_login_session == w,
    "remote_external": lambda w, p, pl, t: isinstance(pl, NetInfo) and pl.remote_is_external == w,
    "remote_port": lambda w, p, pl, t: isinstance(pl, NetInfo) and pl.remote_port in w,
    "local_port": lambda w, p, pl, t: isinstance(pl, NetInfo) and pl.local_port in w,
    "became_root": lambda w, p, pl, t: isinstance(pl, PrivInfo) and pl.became_root == w,
    "method": lambda w, p, pl, t: isinstance(pl, PrivInfo) and pl.method.value in w,
    "path": lambda w, p, pl, t: isinstance(pl, FileInfo) and pl.path.value in w,
    "path_prefix": lambda w, p, pl, t: isinstance(pl, FileInfo) and pl.path.value.startswith(w),
    "operation": lambda w, p, pl, t: isinstance(pl, FileInfo) and pl.operation in w,
    "service": lambda w, p, pl, t: isinstance(pl, AuthInfo) and pl.service.value in w,
}


def matches(match: Mapping[str, Any], event: Event, tree: ProcessTree) -> bool:
    """True se TUTTE le condizioni sono soddisfatte."""
    for field, wanted in match.items():
        check = _CHECKS.get(field)
        if check is None or not check(wanted, event.process, event.payload, tree):
            return False
    return True
