"""Rilevamento delle capacità della macchina e scelta del sensore.

eBPF è il sensore principale; auditd il fallback; la modalità minimale è
l'ultima rete di sicurezza. Qui si decide soltanto IN BASE A CIÒ CHE C'È:
la verifica definitiva (caricare davvero un programma eBPF) spetta al sensore.
"""

from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass
from enum import Enum

MIN_EBPF_KERNEL = (5, 8)
BTF_PATH = "/sys/kernel/btf/vmlinux"
_EXTRA_PATH = "/usr/sbin:/sbin:/usr/local/sbin"


class SensorMode(str, Enum):
    EBPF = "ebpf"
    AUDITD = "auditd"
    MINIMAL = "minimal"


def parse_kernel(release: str) -> tuple[int, int] | None:
    """'6.12.5-arch1-1' -> (6, 12). None se non interpretabile."""
    parts: list[int] = []
    num = ""
    for ch in release:
        if ch.isascii() and ch.isdigit():
            num += ch
        elif ch == "." and num:
            parts.append(int(num))
            num = ""
        else:
            break
        if len(parts) == 2:
            break
    if num and len(parts) < 2:
        parts.append(int(num))
    return (parts[0], parts[1]) if len(parts) >= 2 else None


@dataclass(frozen=True, slots=True)
class Capabilities:
    euid: int
    kernel_release: str
    btf: bool
    auditd_installed: bool
    auditd_running: bool

    @property
    def kernel(self) -> tuple[int, int] | None:
        return parse_kernel(self.kernel_release)

    @property
    def kernel_ok_for_ebpf(self) -> bool:
        k = self.kernel
        return k is not None and k >= MIN_EBPF_KERNEL


@dataclass(frozen=True, slots=True)
class Plan:
    mode: SensorMode          # cosa si può fare ORA
    rootless: bool
    potential: SensorMode     # cosa si potrebbe fare con i privilegi di root
    reason: str


def _best(caps: Capabilities) -> tuple[SensorMode, str]:
    if caps.kernel_ok_for_ebpf and caps.btf:
        return SensorMode.EBPF, f"kernel {caps.kernel_release} con BTF"
    if caps.auditd_installed or caps.auditd_running:
        why = "kernel troppo vecchio" if not caps.kernel_ok_for_ebpf else "BTF assente"
        return SensorMode.AUDITD, f"eBPF non disponibile ({why}): fallback su auditd"
    return SensorMode.MINIMAL, "né eBPF né auditd: solo /proc e log di autenticazione"


def choose(caps: Capabilities) -> Plan:
    potential, reason = _best(caps)
    if caps.euid != 0:
        return Plan(SensorMode.MINIMAL, True, potential,
                    "senza root: solo osservatore (/proc e log accessibili)")
    return Plan(potential, False, potential, reason)


def auditd_running(proc: str = "/proc") -> bool:
    try:
        names = os.listdir(proc)
    except OSError:
        return False
    for name in names:
        if not (name.isascii() and name.isdigit()):
            continue
        try:
            with open(f"{proc}/{name}/comm", "rb") as handle:
                if handle.read(32).strip() == b"auditd":
                    return True
        except OSError:
            continue
    return False


def detect() -> Capabilities:
    path = os.environ.get("PATH", "") + ":" + _EXTRA_PATH
    installed = any(shutil.which(n, path=path) for n in ("auditctl", "auditd"))
    return Capabilities(
        euid=os.geteuid(),
        kernel_release=platform.release(),
        btf=os.path.exists(BTF_PATH),
        auditd_installed=installed,
        auditd_running=auditd_running(),
    )
