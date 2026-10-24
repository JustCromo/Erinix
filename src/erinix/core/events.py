"""Modello evento comune di Erinix.

Ogni sensore (eBPF, auditd, minimale) produce eventi in questo formato:
il motore di correlazione non sa, e non deve sapere, da dove arrivano.

Sicurezza: ogni campo testuale arriva da processi potenzialmente ostili.
Qui viene solo limitato in lunghezza e conservato GREZZO, per mantenere
le prove intatte. L'escape avviene esclusivamente quando si mostra.
"""

from __future__ import annotations

import ipaddress
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Union

# Limiti per i dati non fidati.
MAX_PATH = 4096
MAX_ARG = 4096
MAX_ARGS = 64
MAX_COMM = 16  # TASK_COMM_LEN del kernel (15 caratteri visibili)
MAX_SHORT = 256

# Valore che il kernel usa per "loginuid non impostato" (processi nati da servizi).
AUDIT_UID_UNSET = 4294967295


class Source(str, Enum):
    """Sensore che ha prodotto l'evento: indica quanto fidarsi del dato."""

    EBPF = "ebpf"
    AUDITD = "auditd"
    MINIMAL = "minimal"


class EventType(str, Enum):
    PROCESS_EXEC = "process.exec"
    PROCESS_EXIT = "process.exit"
    NET_CONNECT = "net.connect"
    NET_ACCEPT = "net.accept"
    NET_LISTEN = "net.listen"
    PRIV_UID_CHANGE = "priv.uid_change"
    FILE_ACCESS = "file.access"
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    SENSOR_STARTED = "sensor.started"
    SENSOR_STOPPED = "sensor.stopped"
    SENSOR_MODE = "sensor.mode"
    SENSOR_EVENTS_LOST = "sensor.events_lost"

    @property
    def family(self) -> str:
        return self.value.split(".", 1)[0]


# Eventi che viaggiano sulla corsia riservata: un flood di eventi banali
# non può mai rubare spazio a questi.
CRITICAL_TYPES = frozenset(
    {
        EventType.PROCESS_EXEC,
        EventType.PRIV_UID_CHANGE,
        EventType.NET_CONNECT,
        EventType.NET_ACCEPT,
        EventType.NET_LISTEN,
        EventType.SENSOR_STARTED,
        EventType.SENSOR_STOPPED,
        EventType.SENSOR_MODE,
        EventType.SENSOR_EVENTS_LOST,
    }
)


@dataclass(frozen=True, slots=True)
class Text:
    """Stringa non fidata, limitata in lunghezza ma conservata grezza."""

    value: str
    truncated: bool = False

    @classmethod
    def of(cls, raw: str | bytes | None, limit: int) -> "Text":
        if raw is None:
            return cls("")
        if isinstance(raw, bytes):
            # backslashreplace: nessun byte viene perso o inventato,
            # e il risultato è sempre UTF-8 valido (sicuro per DB e JSON).
            raw = raw[: limit * 4].decode("utf-8", errors="backslashreplace")
        if len(raw) > limit:
            return cls(raw[:limit], True)
        return cls(raw)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class ProcessKey:
    """Identità univoca di un processo: il PID da solo viene riciclato."""

    pid: int
    start_ns: int

    def __post_init__(self) -> None:
        if self.pid <= 0:
            raise ValueError(f"pid non valido: {self.pid}")
        if self.start_ns < 0:
            raise ValueError(f"start_ns non valido: {self.start_ns}")


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    key: ProcessKey
    parent: ProcessKey | None
    uid: int
    euid: int
    loginuid: int | None
    exe: Text
    argv: tuple[Text, ...]
    argv_truncated: bool
    comm: Text

    @classmethod
    def build(
        cls,
        *,
        pid: int,
        start_ns: int,
        uid: int,
        euid: int,
        exe: str | bytes | None,
        argv: list[str | bytes] | tuple[str | bytes, ...] = (),
        comm: str | bytes | None = None,
        ppid: int | None = None,
        parent_start_ns: int | None = None,
        loginuid: int | None = None,
    ) -> "ProcessInfo":
        parent = None
        if ppid is not None and ppid > 0 and parent_start_ns is not None:
            parent = ProcessKey(ppid, parent_start_ns)
        if loginuid == AUDIT_UID_UNSET:
            loginuid = None
        if uid < 0 or euid < 0:
            raise ValueError("uid/euid negativi")
        args = tuple(Text.of(a, MAX_ARG) for a in argv[:MAX_ARGS])
        return cls(
            key=ProcessKey(pid, start_ns),
            parent=parent,
            uid=uid,
            euid=euid,
            loginuid=loginuid,
            exe=Text.of(exe, MAX_PATH),
            argv=args,
            argv_truncated=len(argv) > MAX_ARGS,
            comm=Text.of(comm, MAX_COMM),
        )

    @property
    def from_login_session(self) -> bool:
        """True se il processo discende da un login (SSH, console), non da un servizio."""
        return self.loginuid is not None

    @property
    def name_mismatch(self) -> bool:
        """Il nome dichiarato non corrisponde all'eseguibile visto dal kernel.

        Segnale DEBOLE: è normale per script e interpreti (comm = nome dello
        script, exe = /usr/bin/python3). Va sempre contestualizzato dal motore.
        """
        if not self.exe.value or not self.comm.value:
            return False
        return self.comm.value != os.path.basename(self.exe.value)[: MAX_COMM - 1]


def _ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    return None if value in (None, "") else ipaddress.ip_address(value)


def _port(value: int | None) -> int | None:
    if value is None:
        return None
    if not 0 <= value <= 65535:
        raise ValueError(f"porta non valida: {value}")
    return value


@dataclass(frozen=True, slots=True)
class NetInfo:
    protocol: str
    local_addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    local_port: int | None
    remote_addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    remote_port: int | None

    @classmethod
    def build(cls, *, protocol: str, local_addr=None, local_port=None, remote_addr=None, remote_port=None) -> "NetInfo":
        if protocol not in ("tcp", "udp"):
            raise ValueError(f"protocollo non supportato: {protocol!r}")
        return cls(protocol, _ip(local_addr), _port(local_port), _ip(remote_addr), _port(remote_port))

    @property
    def remote_is_external(self) -> bool:
        """True se il peer non è loopback né link-local."""
        r = self.remote_addr
        return r is not None and not (r.is_loopback or r.is_link_local or r.is_unspecified)


@dataclass(frozen=True, slots=True)
class PrivInfo:
    old_uid: int
    new_uid: int
    old_euid: int
    new_euid: int
    method: Text  # es. "setuid", "sudo", "suid-exec"

    @property
    def became_root(self) -> bool:
        return (self.old_euid != 0 and self.new_euid == 0) or (self.old_uid != 0 and self.new_uid == 0)


FILE_OPERATIONS = frozenset({"read", "write", "exec", "chmod", "chown", "unlink", "rename"})


@dataclass(frozen=True, slots=True)
class FileInfo:
    path: Text
    operation: str

    @classmethod
    def build(cls, *, path: str | bytes, operation: str) -> "FileInfo":
        if operation not in FILE_OPERATIONS:
            raise ValueError(f"operazione non valida: {operation!r}")
        return cls(Text.of(path, MAX_PATH), operation)


@dataclass(frozen=True, slots=True)
class AuthInfo:
    service: Text
    user: Text
    remote_addr: ipaddress.IPv4Address | ipaddress.IPv6Address | None

    @classmethod
    def build(cls, *, service: str, user: str | bytes, remote_addr: str | None = None) -> "AuthInfo":
        return cls(Text.of(service, MAX_SHORT), Text.of(user, MAX_SHORT), _ip(remote_addr))


@dataclass(frozen=True, slots=True)
class SensorInfo:
    mode: Source | None
    detail: Text
    lost: int = 0

    @classmethod
    def build(cls, *, mode: Source | None = None, detail: str = "", lost: int = 0) -> "SensorInfo":
        if lost < 0:
            raise ValueError("lost negativo")
        return cls(mode, Text.of(detail, MAX_SHORT), lost)


Payload = Union[NetInfo, PrivInfo, FileInfo, AuthInfo, SensorInfo]

_PAYLOAD_BY_FAMILY: dict[str, type | None] = {
    "process": None,
    "net": NetInfo,
    "priv": PrivInfo,
    "file": FileInfo,
    "auth": AuthInfo,
    "sensor": SensorInfo,
}

_PROCESS_REQUIRED = frozenset({"process", "priv", "net", "file"})


@dataclass(frozen=True, slots=True)
class Event:
    type: EventType
    source: Source
    process: ProcessInfo | None = None
    payload: Payload | None = None
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    # Due orologi: il monotono ordina senza farsi ingannare da cambi d'ora,
    # quello reale serve solo per mostrare.
    mono_ns: int = field(default_factory=time.monotonic_ns)
    wall_ns: int = field(default_factory=time.time_ns)

    def __post_init__(self) -> None:
        family = self.type.family
        expected = _PAYLOAD_BY_FAMILY[family]
        if expected is None:
            if self.payload is not None:
                raise ValueError(f"{self.type.value} non accetta payload")
        elif not isinstance(self.payload, expected):
            raise ValueError(f"{self.type.value} richiede payload {expected.__name__}")
        if family in _PROCESS_REQUIRED and self.process is None:
            raise ValueError(f"{self.type.value} richiede il contesto del processo")

    @property
    def is_critical(self) -> bool:
        return self.type in CRITICAL_TYPES
