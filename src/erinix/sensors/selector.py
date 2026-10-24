"""Detection of the machine's capabilities and choice of the sensor.

eBPF is the main sensor; auditd the fallback; the minimal mode is the last
safety net. Here we decide ONLY BASED ON WHAT IS THERE: the final check (really
loading an eBPF program) belongs to the sensor.
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
    """'6.12.5-arch1-1' -> (6, 12). None if it cannot be parsed."""
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
    mode: SensorMode          # what can be done NOW
    rootless: bool
    potential: SensorMode     # what could be done with root privileges
    reason: str


def _best(caps: Capabilities) -> tuple[SensorMode, str]:
    if caps.kernel_ok_for_ebpf and caps.btf:
        return SensorMode.EBPF, f"kernel {caps.kernel_release} with BTF"
    if caps.auditd_installed or caps.auditd_running:
        why = "kernel too old" if not caps.kernel_ok_for_ebpf else "BTF missing"
        return SensorMode.AUDITD, f"eBPF unavailable ({why}): falling back to auditd"
    return SensorMode.MINIMAL, "neither eBPF nor auditd: only /proc and authentication logs"


def choose(caps: Capabilities) -> Plan:
    potential, reason = _best(caps)
    if caps.euid != 0:
        return Plan(SensorMode.MINIMAL, True, potential,
                    "without root: observer only (/proc and readable logs)")
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
