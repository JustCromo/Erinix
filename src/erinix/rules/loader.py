"""Loading and validation of Erinix rules (TOML format).

Security principles (see docs/PLANNING.md):
- rules are ONLY declarative: no code, no eval, no regular expressions
  (no ReDoS): only exact values, prefixes and lists;
- closed schema: any unknown field invalidates the rule;
- a malformed rule is discarded and reported, never executed; the others
  stay active;
- files must belong to root (or to the user running Erinix), must not be
  writable by group/others and must not be symlinks;
- hard limits on sizes, number of rules, steps and lists;
- a rule with response 'auto' must explain why the certainty is absolute.
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
from erinix.core.webnorm import normalize_target

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
    """Invalid rule or rules file."""


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
    """What makes the steps of a chain 'the same story'."""

    PROCESS_TREE = "process_tree"      # the process of step 1 or its descendants
    LOGIN_SESSION = "login_session"    # same login session (loginuid)
    REMOTE_IP = "remote_ip"            # same remote address


_STR, _INT, _BOOL = "str_list", "int_list", "bool"
_PROC = {"exe": _STR, "exe_prefix": _STR, "exe_not": _STR}

# Closed schema: for each event type, the only fields allowed in 'match'.
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
    EventType.WEB_REQUEST: {"contains": _STR, "user_agent_contains": _STR, "method": _STR,
                            "status": _INT, "path": _STR, "path_prefix": _STR, "path_not": _STR},
})

_ABSOLUTE_FIELDS = frozenset({"exe", "exe_not", "parent_exe", "ancestor_exe", "path",
                              "exe_prefix", "path_prefix", "path_not"})

_REMOTE_IP_EVENTS = frozenset({EventType.NET_CONNECT, EventType.NET_ACCEPT, EventType.AUTH_FAILURE,
                               EventType.AUTH_SUCCESS, EventType.WEB_REQUEST})
_AUTH_EVENTS = frozenset({EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS})
_NO_PROCESS_EVENTS = _AUTH_EVENTS | {EventType.WEB_REQUEST}     # events with no process attached
_WEB_TEXT_FIELDS = frozenset({"contains", "user_agent_contains", "path", "path_prefix", "path_not"})
MIN_SUBSTRING = 3          # shorter substrings would match almost everything


# ------------------------------------------------------------------ model
@dataclass(frozen=True, slots=True)
class Step:
    id: str
    event: EventType
    severity: Severity
    response: Response
    count: int
    match: Mapping[str, Any]
    label: str = ""                       # plain-language name of this step, shown in the live timeline


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
    title: str = ""                       # plain-language headline ({remote} is replaced)
    why: str = ""                         # why it matters, in plain language
    next_steps: tuple[str, ...] = ()      # what to do, in plain language
    tag: str = ""                         # the kind of attack, in two or three words (groups incidents)
    area: str = ""                        # what it touches: website, logins or this machine


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
    title: str = ""
    why: str = ""
    next_steps: tuple[str, ...] = ()
    tag: str = ""
    area: str = ""


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


# --------------------------------------------------------------- validators
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
        raise RuleError(f"{where}: must be a non-empty string")
    if len(value) > limit:
        raise RuleError(f"{where}: too long (maximum {limit} characters)")
    if not value.isprintable():
        raise RuleError(f"{where}: contains control characters")
    return value


def _check_keys(table: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(str(k) for k in table if k not in allowed)
    if unknown:
        raise RuleError(f"{where}: fields not allowed: {', '.join(_short(k, 30) for k in unknown)}")


def _enum(cls: type[Enum], value: object, where: str, field: str) -> Any:
    try:
        return cls(value)
    except ValueError:
        allowed = ", ".join(m.value for m in cls)
        raise RuleError(f"{where}: invalid {field} {_short(value, 40)} (allowed: {allowed})") from None


def _str_list(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_LIST_ITEMS:
        raise RuleError(f"{where}: must be a list of 1-{MAX_LIST_ITEMS} strings")
    items = [_text(v, where) for v in value]
    return tuple(dict.fromkeys(items))


def _int_list(value: object, where: str, low: int, high: int) -> tuple[int, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_LIST_ITEMS:
        raise RuleError(f"{where}: must be a list of 1-{MAX_LIST_ITEMS} integers")
    for v in value:
        if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= high:
            raise RuleError(f"{where}: allowed values: integers from {low} to {high}")
    return tuple(dict.fromkeys(value))


def _parse_match(event: EventType, raw: object, where: str) -> Mapping[str, Any]:
    allowed = MATCH_FIELDS.get(event)
    if allowed is None:
        raise RuleError(f"{where}: event {event.value} cannot be used in rules")
    if not isinstance(raw, dict) or not raw:
        raise RuleError(f"{where}: 'match' must be a non-empty table")
    result: dict[str, Any] = {}
    for key, value in raw.items():
        kind = allowed.get(key)
        if kind is None:
            raise RuleError(f"{where}: match field {_short(key, 30)} not allowed for "
                            f"{event.value} (allowed: {', '.join(sorted(allowed))})")
        w = f"{where}, match.{key}"
        if kind == _BOOL:
            if not isinstance(value, bool):
                raise RuleError(f"{w}: must be true or false")
            result[key] = value
        elif kind == _INT:
            low, high = (100, 599) if key == "status" else (0, 65535)
            result[key] = _int_list(value, w, low, high)
        else:
            items = _str_list(value, w)
            if key in _ABSOLUTE_FIELDS and not all(i.startswith("/") for i in items):
                raise RuleError(f"{w}: absolute paths required (starting with '/')")
            if key == "operation" and not set(items) <= FILE_OPERATIONS:
                raise RuleError(f"{w}: allowed operations: {', '.join(sorted(FILE_OPERATIONS))}")
            if event is EventType.WEB_REQUEST:
                if key == "method" and not all(i.isascii() and i.isalpha() and i.isupper() for i in items):
                    raise RuleError(f"{w}: HTTP methods must be upper-case letters (e.g. GET)")
                if key in _WEB_TEXT_FIELDS:
                    # Rule values are normalized exactly like request targets (case, encoding...).
                    items = tuple(dict.fromkeys(normalize_target(i) for i in items))
                    if key in ("contains", "user_agent_contains") and any(len(i.strip()) < MIN_SUBSTRING for i in items):
                        raise RuleError(f"{w}: each text must have at least {MIN_SUBSTRING} characters")
            result[key] = items
    return MappingProxyType(result)


def _common(raw: Mapping[str, Any], where: str) -> tuple[str, tuple[str, ...]]:
    description = ""
    if "description" in raw:
        description = _text(raw["description"], f"{where}, description", MAX_DESCRIPTION)
    mitre_raw = raw.get("mitre", [])
    if not isinstance(mitre_raw, list) or len(mitre_raw) > MAX_LIST_ITEMS:
        raise RuleError(f"{where}: 'mitre' must be a list of identifiers (e.g. T1190)")
    for m in mitre_raw:
        if not _is_mitre(m):
            raise RuleError(f"{where}: invalid MITRE identifier {_short(m, 30)}")
    return description, tuple(dict.fromkeys(mitre_raw))


MAX_TITLE, MAX_WHY, MAX_NEXT_ITEMS, MAX_NEXT, MAX_LABEL, MAX_TAG = 120, 400, 6, 200, 100, 32
AREAS = ("website", "logins", "this machine")


def _plain_text(value: object, where: str, limit: int) -> str:
    """Text shown to people. The only placeholder allowed is {remote}."""
    text = _text(value, where, limit)
    if "{" in text.replace("{remote}", "") or "}" in text.replace("{remote}", ""):
        raise RuleError(f"{where}: the only placeholder allowed is {{remote}}")
    return text


def _human(raw: Mapping[str, Any], where: str) -> tuple[str, str, tuple[str, ...], str, str]:
    """Optional plain-language texts: title, why, next (suggested steps), tag (kind of attack), area (what it touches)."""
    tag = _text(raw["tag"], f"{where}, tag", MAX_TAG) if "tag" in raw else ""
    area = ""
    if "area" in raw:
        area = raw["area"]
        if area not in AREAS:
            raise RuleError(f"{where}: 'area' must be one of: {', '.join(AREAS)}")
    title = _plain_text(raw["title"], f"{where}, title", MAX_TITLE) if "title" in raw else ""
    why = _plain_text(raw["why"], f"{where}, why", MAX_WHY) if "why" in raw else ""
    steps: tuple[str, ...] = ()
    if "next" in raw:
        value = raw["next"]
        if not isinstance(value, list) or not 1 <= len(value) <= MAX_NEXT_ITEMS:
            raise RuleError(f"{where}: 'next' must be a list of 1-{MAX_NEXT_ITEMS} short sentences")
        steps = tuple(_plain_text(item, f"{where}, next", MAX_NEXT) for item in value)
    return title, why, steps, tag, area


def _justification(raw: Mapping[str, Any], where: str, needed: bool) -> str:
    if "justification" not in raw:
        if needed:
            raise RuleError(f"{where}: a rule with response 'auto' must have 'justification' "
                            "(why the certainty is absolute)")
        return ""
    return _text(raw["justification"], f"{where}, justification", MAX_DESCRIPTION)


def _ident(raw: Mapping[str, Any], where: str) -> str:
    value = raw.get("id")
    if not _is_ident(value):
        raise RuleError(f"{where}: 'id' is required (a-z, 0-9, '-', '_', at most 64 characters)")
    return value


def _parse_step(raw: object, index: int, where: str, default: Response, link: Link) -> Step:
    w = f"{where}, step {index}"
    if not isinstance(raw, dict):
        raise RuleError(f"{w}: must be a table")
    _check_keys(raw, {"id", "event", "severity", "response", "count", "match", "label"}, w)
    step_id = _ident(raw, w)
    label = _plain_text(raw["label"], f"{w}, label", MAX_LABEL) if "label" in raw else ""
    event = _enum(EventType, raw.get("event"), w, "event")
    if event not in MATCH_FIELDS:
        raise RuleError(f"{w}: event {event.value} cannot be used in rules")
    if link is Link.REMOTE_IP and event not in _REMOTE_IP_EVENTS:
        raise RuleError(f"{w}: with link 'remote_ip' events must carry a remote address")
    if link in (Link.LOGIN_SESSION, Link.PROCESS_TREE) and event in _NO_PROCESS_EVENTS:
        raise RuleError(f"{w}: with link '{link.value}' events must be tied to a process")
    severity = _enum(Severity, raw.get("severity"), w, "severity")
    response = default if "response" not in raw else _enum(Response, raw["response"], w, "response")
    count = raw.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_COUNT:
        raise RuleError(f"{w}: 'count' must be an integer from 1 to {MAX_COUNT}")
    match = _parse_match(event, raw.get("match"), w)
    return Step(step_id, event, severity, response, count, match, label)


def _parse_chain(raw: dict) -> Chain:
    rule_id = _ident(raw, "chain")
    where = f"chain {rule_id}"
    _check_keys(raw, {"id", "description", "mitre", "window_seconds", "link", "response",
                      "justification", "step", "title", "why", "next", "tag", "area"}, where)
    description, mitre = _common(raw, where)
    title, why, next_steps, tag, area = _human(raw, where)
    window = raw.get("window_seconds")
    if isinstance(window, bool) or not isinstance(window, int) or not MIN_WINDOW <= window <= MAX_WINDOW:
        raise RuleError(f"{where}: 'window_seconds' must be an integer from {MIN_WINDOW} to {MAX_WINDOW}")
    link = _enum(Link, raw.get("link"), where, "link")
    default = Response.REPORT_ONLY if "response" not in raw else _enum(Response, raw["response"], where, "response")
    steps_raw = raw.get("step")
    if not isinstance(steps_raw, list) or not 2 <= len(steps_raw) <= MAX_STEPS:
        raise RuleError(f"{where}: needs 2 to {MAX_STEPS} steps ([[chain.step]]); "
                        "for a single event use [[indicator]]")
    steps = tuple(_parse_step(s, i + 1, where, default, link) for i, s in enumerate(steps_raw))
    ids = [s.id for s in steps]
    if len(set(ids)) != len(ids):
        raise RuleError(f"{where}: step ids must be unique")
    needs_just = default is Response.AUTO or any(s.response is Response.AUTO for s in steps)
    justification = _justification(raw, where, needs_just)
    return Chain(rule_id, description, mitre, window, link, default, justification, steps,
                 title, why, next_steps, tag, area)


def _parse_indicator(raw: dict) -> Indicator:
    rule_id = _ident(raw, "indicator")
    where = f"indicator {rule_id}"
    _check_keys(raw, {"id", "description", "mitre", "event", "severity", "response",
                      "justification", "match", "title", "why", "next", "tag", "area"}, where)
    description, mitre = _common(raw, where)
    title, why, next_steps, tag, area = _human(raw, where)
    event = _enum(EventType, raw.get("event"), where, "event")
    severity = _enum(Severity, raw.get("severity"), where, "severity")
    response = Response.REPORT_ONLY if "response" not in raw else _enum(Response, raw["response"], where, "response")
    match = _parse_match(event, raw.get("match"), where)
    justification = _justification(raw, where, response is Response.AUTO)
    return Indicator(rule_id, description, mitre, event, severity, response, justification, match,
                     title, why, next_steps, tag, area)


# ------------------------------------------------------- file security
def _check_stat(st: os.stat_result, what: str) -> None:
    if st.st_mode & 0o022:
        raise RuleError(f"{what} is writable by group or others: rejected")
    if st.st_uid not in (0, os.geteuid()):
        raise RuleError(f"{what} has an untrusted owner (uid {st.st_uid}): rejected")


def _read_secure(path: str, dir_fd: int | None) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        raise RuleError(f"cannot open the file ({exc.strerror}); symlinks are not allowed") from None
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise RuleError("not a regular file")
        _check_stat(st, "file")
        if st.st_size > MAX_FILE_BYTES:
            raise RuleError(f"file too large (maximum {MAX_FILE_BYTES} bytes)")
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise RuleError(f"file too large (maximum {MAX_FILE_BYTES} bytes)")
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
            self.problem(file, rule.id, "duplicate id: rule discarded")
        elif len(self._ids) >= MAX_RULES:
            self.problem(file, rule.id, f"limit of {MAX_RULES} rules exceeded: rule discarded")
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
            raise RuleError(f"file: 'schema = {SCHEMA_VERSION}' is required at the top of the file")
        for key in ("chain", "indicator"):
            value = doc.get(key, [])
            if not isinstance(value, list) or not all(isinstance(r, dict) for r in value):
                raise RuleError(f"file: '{key}' must be a list of tables")
    except RuleError as exc:
        builder.problem(label, None, str(exc))
        return
    for key, parser in (("chain", _parse_chain), ("indicator", _parse_indicator)):
        for raw in doc.get(key, []):
            rule_id = raw.get("id") if _is_ident(raw.get("id")) else None
            try:
                builder.add(label, parser(raw))
            except RuleError as exc:
                builder.problem(label, rule_id, f"{exc}: rule discarded")


def _load_file(label: str, path: str, dir_fd: int | None, builder: _Builder) -> None:
    try:
        text = _read_secure(path, dir_fd).decode("utf-8")
        doc = tomllib.loads(text)
    except RuleError as exc:
        builder.problem(label, None, str(exc))
    except UnicodeDecodeError:
        builder.problem(label, None, "the file is not valid UTF-8")
    except tomllib.TOMLDecodeError as exc:
        builder.problem(label, None, f"invalid TOML: {exc}")
    else:
        _parse_document(doc, label, builder)


def load_rules(path: str | os.PathLike[str]) -> RuleSet:
    """Load a file or a folder of .toml files.

    Raises RuleError if the path itself is untrustworthy (missing, a symlink, a
    folder writable by others): in that case nothing is loaded. Problems with
    individual files or rules end up in RuleSet.problems instead.
    """
    path = os.fspath(path)
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise RuleError(f"{_short(path, 200)}: {exc.strerror}") from None
    if stat.S_ISLNK(st.st_mode):
        raise RuleError(f"{_short(path, 200)}: symlinks are not allowed")
    builder = _Builder()
    if stat.S_ISDIR(st.st_mode):
        dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _check_stat(os.fstat(dir_fd), "rules folder")
            names = sorted(n for n in os.listdir(dir_fd) if n.endswith(".toml") and not n.startswith("."))
            for name in names:
                _load_file(name, name, dir_fd, builder)
        finally:
            os.close(dir_fd)
    else:
        _load_file(os.path.basename(path), path, None, builder)
    return builder.build()
