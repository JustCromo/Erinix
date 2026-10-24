"""Caricamento e validazione delle regole di Erinix (formato TOML).

Principi di sicurezza (vedi docs/PLANNING.md):
- le regole sono SOLO dichiarative: nessun codice, nessun eval, nessuna
  espressione regolare (niente ReDoS): solo valori esatti, prefissi e liste;
- schema chiuso: qualunque campo sconosciuto invalida la regola;
- una regola malformata viene scartata e segnalata, mai eseguita; le altre
  restano attive;
- i file devono essere di root (o dell'utente che esegue Erinix), non
  scrivibili da gruppo/altri e non essere symlink;
- limiti rigidi su dimensioni, numero di regole, passi e liste;
- una regola con risposta 'auto' deve spiegare perché la certezza è assoluta.
"""

from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from erinix.core.events import FILE_OPERATIONS, EventType

SCHEMA_VERSION = 1

MAX_FILE_BYTES = 1024 * 1024
MAX_RULES = 1000
MAX_STEPS = 16
MAX_LIST_ITEMS = 64
MAX_STR = 4096
MAX_DESCRIPTION = 500
MIN_WINDOW, MAX_WINDOW = 1, 86400
MAX_COUNT = 1000


class RuleError(ValueError):
    """Regola o file di regole non valido."""


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


class Response(str, Enum):
    REPORT_ONLY = "report_only"
    INTERACTIVE = "interactive"
    AUTO = "auto"


class Link(str, Enum):
    """Cosa rende i passi di una catena 'la stessa storia'."""

    PROCESS_TREE = "process_tree"      # processo del passo 1 o suoi discendenti
    LOGIN_SESSION = "login_session"    # stessa sessione di login (loginuid)
    REMOTE_IP = "remote_ip"            # stesso indirizzo remoto


_STR, _INT, _BOOL = "str_list", "int_list", "bool"
_PROC = {"exe": _STR, "exe_prefix": _STR, "exe_not": _STR}

# Schema chiuso: per ogni tipo di evento, i soli campi ammessi in 'match'.
MATCH_FIELDS: Mapping[EventType, Mapping[str, str]] = MappingProxyType({
    EventType.PROCESS_EXEC: {**_PROC, "parent_exe": _STR, "ancestor_exe": _STR,
                             "argv_has": _STR, "from_login_session": _BOOL},
    EventType.NET_CONNECT: {**_PROC, "remote_external": _BOOL, "remote_port": _INT},
    EventType.NET_ACCEPT: {**_PROC, "remote_external": _BOOL, "local_port": _INT},
    EventType.NET_LISTEN: {**_PROC, "local_port": _INT},
    EventType.PRIV_UID_CHANGE: {**_PROC, "became_root": _BOOL, "method": _STR},
    EventType.FILE_ACCESS: {**_PROC, "path": _STR, "path_prefix": _STR, "operation": _STR},
    EventType.AUTH_FAILURE: {"service": _STR},
    EventType.AUTH_SUCCESS: {"service": _STR},
})

_ABSOLUTE_FIELDS = frozenset({"exe", "exe_not", "parent_exe", "ancestor_exe", "path",
                              "exe_prefix", "path_prefix"})

_REMOTE_IP_EVENTS = frozenset({EventType.NET_CONNECT, EventType.NET_ACCEPT,
                               EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS})
_AUTH_EVENTS = frozenset({EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS})


# ------------------------------------------------------------------ modello
@dataclass(frozen=True, slots=True)
class Step:
    id: str
    event: EventType
    severity: Severity
    response: Response
    count: int
    match: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Chain:
    id: str
    description: str
    mitre: tuple[str, ...]
    window_seconds: int
    link: Link
    response: Response
    justification: str
    steps: tuple[Step, ...]


@dataclass(frozen=True, slots=True)
class Indicator:
    id: str
    description: str
    mitre: tuple[str, ...]
    event: EventType
    severity: Severity
    response: Response
    justification: str
    match: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class RuleProblem:
    file: str
    rule_id: str | None
    message: str


@dataclass(frozen=True, slots=True)
class RuleSet:
    chains: tuple[Chain, ...]
    indicators: tuple[Indicator, ...]
    problems: tuple[RuleProblem, ...]


# --------------------------------------------------------------- validatori
def _short(value: object, limit: int = 60) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _is_digits(value: str, n: int) -> bool:
    return len(value) == n and value.isascii() and value.isdigit()


def _is_ident(value: object) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 64 and value.isascii()
            and all(c.islower() or c.isdigit() or c in "-_" for c in value))


def _is_mitre(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("T"):
        return False
    body = value[1:]
    if "." in body:
        base, sub = body.split(".", 1)
        return _is_digits(base, 4) and _is_digits(sub, 3)
    return _is_digits(body, 4)


def _text(value: object, where: str, limit: int = MAX_STR) -> str:
    if not isinstance(value, str) or not value:
        raise RuleError(f"{where}: deve essere una stringa non vuota")
    if len(value) > limit:
        raise RuleError(f"{where}: troppo lunga (massimo {limit} caratteri)")
    if not value.isprintable():
        raise RuleError(f"{where}: contiene caratteri di controllo")
    return value


def _check_keys(table: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(str(k) for k in table if k not in allowed)
    if unknown:
        raise RuleError(f"{where}: campi non ammessi: {', '.join(_short(k, 30) for k in unknown)}")


def _enum(cls: type[Enum], value: object, where: str, field: str) -> Any:
    try:
        return cls(value)
    except ValueError:
        allowed = ", ".join(m.value for m in cls)
        raise RuleError(f"{where}: {field} non valido {_short(value, 40)} (ammessi: {allowed})") from None


def _str_list(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_LIST_ITEMS:
        raise RuleError(f"{where}: deve essere una lista di 1-{MAX_LIST_ITEMS} stringhe")
    items = [_text(v, where) for v in value]
    return tuple(dict.fromkeys(items))


def _int_list(value: object, where: str, low: int, high: int) -> tuple[int, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_LIST_ITEMS:
        raise RuleError(f"{where}: deve essere una lista di 1-{MAX_LIST_ITEMS} interi")
    for v in value:
        if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
            raise RuleError(f"{where}: valori ammessi: interi da {low} a {high}")
    return tuple(dict.fromkeys(value))


def _parse_match(event: EventType, raw: object, where: str) -> Mapping[str, Any]:
    allowed = MATCH_FIELDS.get(event)
    if allowed is None:
        raise RuleError(f"{where}: l'evento {event.value} non è utilizzabile nelle regole")
    if not isinstance(raw, dict) or not raw:
        raise RuleError(f"{where}: 'match' deve essere una tabella non vuota")
    result: dict[str, Any] = {}
    for key, value in raw.items():
        kind = allowed.get(key)
        if kind is None:
            raise RuleError(f"{where}: campo match {_short(key, 30)} non ammesso per "
                            f"{event.value} (ammessi: {', '.join(sorted(allowed))})")
        w = f"{where}, match.{key}"
        if kind == _BOOL:
            if not isinstance(value, bool):
                raise RuleError(f"{w}: deve essere true o false")
            result[key] = value
        elif kind == _INT:
            result[key] = _int_list(value, w, 0, 65535)
        else:
            items = _str_list(value, w)
            if key in _ABSOLUTE_FIELDS and not all(i.startswith("/") for i in items):
                raise RuleError(f"{w}: servono percorsi assoluti (che iniziano con '/')")
            if key == "operation" and not set(items) <= FILE_OPERATIONS:
                raise RuleError(f"{w}: operazioni ammesse: {', '.join(sorted(FILE_OPERATIONS))}")
            result[key] = items
    return MappingProxyType(result)


def _common(raw: Mapping[str, Any], where: str) -> tuple[str, tuple[str, ...]]:
    description = ""
    if "description" in raw:
        description = _text(raw["description"], f"{where}, description", MAX_DESCRIPTION)
    mitre_raw = raw.get("mitre", [])
    if not isinstance(mitre_raw, list) or len(mitre_raw) > MAX_LIST_ITEMS:
        raise RuleError(f"{where}: 'mitre' deve essere una lista di identificativi (es. T1190)")
    for m in mitre_raw:
        if not _is_mitre(m):
            raise RuleError(f"{where}: identificativo MITRE non valido {_short(m, 30)}")
    return description, tuple(dict.fromkeys(mitre_raw))


def _justification(raw: Mapping[str, Any], where: str, needed: bool) -> str:
    if "justification" not in raw:
        if needed:
            raise RuleError(f"{where}: una regola con risposta 'auto' deve avere 'justification' "
                            "(perché la certezza è assoluta)")
        return ""
    return _text(raw["justification"], f"{where}, justification", MAX_DESCRIPTION)


def _ident(raw: Mapping[str, Any], where: str) -> str:
    value = raw.get("id")
    if not _is_ident(value):
        raise RuleError(f"{where}: 'id' obbligatorio (a-z, 0-9, '-', '_', massimo 64 caratteri)")
    return value


def _parse_step(raw: object, index: int, where: str, default: Response, link: Link) -> Step:
    w = f"{where}, passo {index}"
    if not isinstance(raw, dict):
        raise RuleError(f"{w}: deve essere una tabella")
    _check_keys(raw, {"id", "event", "severity", "response", "count", "match"}, w)
    step_id = _ident(raw, w)
    event = _enum(EventType, raw.get("event"), w, "event")
    if event not in MATCH_FIELDS:
        raise RuleError(f"{w}: l'evento {event.value} non è utilizzabile nelle regole")
    if link is Link.REMOTE_IP and event not in _REMOTE_IP_EVENTS:
        raise RuleError(f"{w}: con link 'remote_ip' servono eventi con indirizzo remoto")
    if link is Link.LOGIN_SESSION and event in _AUTH_EVENTS:
        raise RuleError(f"{w}: con link 'login_session' servono eventi legati a un processo")
    severity = _enum(Severity, raw.get("severity"), w, "severity")
    response = default if "response" not in raw else _enum(Response, raw["response"], w, "response")
    count = raw.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_COUNT:
        raise RuleError(f"{w}: 'count' deve essere un intero da 1 a {MAX_COUNT}")
    match = _parse_match(event, raw.get("match"), w)
    return Step(step_id, event, severity, response, count, match)


def _parse_chain(raw: dict) -> Chain:
    rule_id = _ident(raw, "catena")
    where = f"catena {rule_id}"
    _check_keys(raw, {"id", "description", "mitre", "window_seconds", "link", "response",
                      "justification", "step"}, where)
    description, mitre = _common(raw, where)
    window = raw.get("window_seconds")
    if isinstance(window, bool) or not isinstance(window, int) or not MIN_WINDOW <= window <= MAX_WINDOW:
        raise RuleError(f"{where}: 'window_seconds' deve essere un intero da {MIN_WINDOW} a {MAX_WINDOW}")
    link = _enum(Link, raw.get("link"), where, "link")
    default = Response.REPORT_ONLY if "response" not in raw else _enum(Response, raw["response"], where, "response")
    steps_raw = raw.get("step")
    if not isinstance(steps_raw, list) or not 2 <= len(steps_raw) <= MAX_STEPS:
        raise RuleError(f"{where}: servono da 2 a {MAX_STEPS} passi ([[chain.step]]); "
                        "per un evento singolo usa [[indicator]]")
    steps = tuple(_parse_step(s, i + 1, where, default, link) for i, s in enumerate(steps_raw))
    ids = [s.id for s in steps]
    if len(set(ids)) != len(ids):
        raise RuleError(f"{where}: gli id dei passi devono essere univoci")
    needs_just = default is Response.AUTO or any(s.response is Response.AUTO for s in steps)
    justification = _justification(raw, where, needs_just)
    return Chain(rule_id, description, mitre, window, link, default, justification, steps)


def _parse_indicator(raw: dict) -> Indicator:
    rule_id = _ident(raw, "indicatore")
    where = f"indicatore {rule_id}"
    _check_keys(raw, {"id", "description", "mitre", "event", "severity", "response",
                      "justification", "match"}, where)
    description, mitre = _common(raw, where)
    event = _enum(EventType, raw.get("event"), where, "event")
    severity = _enum(Severity, raw.get("severity"), where, "severity")
    response = Response.REPORT_ONLY if "response" not in raw else _enum(Response, raw["response"], where, "response")
    match = _parse_match(event, raw.get("match"), where)
    justification = _justification(raw, where, response is Response.AUTO)
    return Indicator(rule_id, description, mitre, event, severity, response, justification, match)


# ------------------------------------------------------- sicurezza dei file
def _check_stat(st: os.stat_result, what: str) -> None:
    if st.st_mode & 0o022:
        raise RuleError(f"{what} scrivibile da gruppo o altri utenti: rifiutato")
    if st.st_uid not in (0, os.geteuid()):
        raise RuleError(f"{what} con proprietario non fidato (uid {st.st_uid}): rifiutato")


def _read_secure(path: str, dir_fd: int | None) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise RuleError(f"impossibile aprire il file ({exc.strerror}); i symlink non sono ammessi") from None
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise RuleError("non è un file regolare")
        _check_stat(st, "file")
        if st.st_size > MAX_FILE_BYTES:
            raise RuleError(f"file troppo grande (massimo {MAX_FILE_BYTES} byte)")
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise RuleError(f"file troppo grande (massimo {MAX_FILE_BYTES} byte)")
    return data


class _Builder:
    def __init__(self) -> None:
        self.chains: list[Chain] = []
        self.indicators: list[Indicator] = []
        self.problems: list[RuleProblem] = []
        self._ids: set[str] = set()

    def problem(self, file: str, rule_id: str | None, message: str) -> None:
        self.problems.append(RuleProblem(file, rule_id, message))

    def add(self, file: str, rule: Chain | Indicator) -> None:
        if rule.id in self._ids:
            self.problem(file, rule.id, "id duplicato: regola scartata")
        elif len(self._ids) >= MAX_RULES:
            self.problem(file, rule.id, f"superato il limite di {MAX_RULES} regole: regola scartata")
        else:
            self._ids.add(rule.id)
            (self.chains if isinstance(rule, Chain) else self.indicators).append(rule)

    def build(self) -> RuleSet:
        return RuleSet(tuple(self.chains), tuple(self.indicators), tuple(self.problems))


def _parse_document(doc: dict, label: str, builder: _Builder) -> None:
    try:
        _check_keys(doc, {"schema", "chain", "indicator"}, "file")
        schema = doc.get("schema")
        if isinstance(schema, bool) or schema != SCHEMA_VERSION:
            raise RuleError(f"file: serve 'schema = {SCHEMA_VERSION}' in cima al file")
        for key in ("chain", "indicator"):
            value = doc.get(key, [])
            if not isinstance(value, list) or not all(isinstance(r, dict) for r in value):
                raise RuleError(f"file: '{key}' deve essere una lista di tabelle")
    except RuleError as exc:
        builder.problem(label, None, str(exc))
        return
    for key, parser in (("chain", _parse_chain), ("indicator", _parse_indicator)):
        for raw in doc.get(key, []):
            rule_id = raw.get("id") if _is_ident(raw.get("id")) else None
            try:
                builder.add(label, parser(raw))
            except RuleError as exc:
                builder.problem(label, rule_id, f"{exc}: regola scartata")


def _load_file(label: str, path: str, dir_fd: int | None, builder: _Builder) -> None:
    try:
        text = _read_secure(path, dir_fd).decode("utf-8")
        doc = tomllib.loads(text)
    except RuleError as exc:
        builder.problem(label, None, str(exc))
    except UnicodeDecodeError:
        builder.problem(label, None, "il file non è UTF-8 valido")
    except tomllib.TOMLDecodeError as exc:
        builder.problem(label, None, f"TOML non valido: {exc}")
    else:
        _parse_document(doc, label, builder)


def load_rules(path: str | os.PathLike[str]) -> RuleSet:
    """Carica un file o una cartella di file .toml.

    Solleva RuleError se il percorso stesso è inaffidabile (non esiste, è un
    symlink, cartella scrivibile da altri): in quel caso non si carica nulla.
    I problemi sui singoli file o regole finiscono invece in RuleSet.problems.
    """
    path = os.fspath(path)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise RuleError(f"{_short(path, 200)}: {exc.strerror}") from None
    if stat.S_ISLNK(st.st_mode):
        raise RuleError(f"{_short(path, 200)}: i symlink non sono ammessi")
    builder = _Builder()
    if stat.S_ISDIR(st.st_mode):
        dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _check_stat(os.fstat(dir_fd), "cartella delle regole")
            names = sorted(n for n in os.listdir(dir_fd) if n.endswith(".toml") and not n.startswith("."))
            for name in names:
                _load_file(name, name, dir_fd, builder)
        finally:
            os.close(dir_fd)
    else:
        _load_file(os.path.basename(path), path, None, builder)
    return builder.build()
