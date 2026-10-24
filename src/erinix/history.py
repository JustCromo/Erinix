"""Cronologia dei comandi: file privato (0600) e mai di cui non ci si fida.

Non si legge se non è un file regolare dell'utente o se è accessibile ad
altri; non si scrive attraverso un symlink.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

HISTORY_MAX = 500
MAX_LINE = 4096


def history_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "erinix" / "history"


def is_trusted(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077


def read_lines(path: Path, limit: int = HISTORY_MAX) -> list[str]:
    if not is_trusted(path):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = [ln[:MAX_LINE] for ln in text.splitlines() if ln.strip() and ln.isprintable()]
    return lines[-limit:]


def write_lines(path: Path, lines: list[str], limit: int = HISTORY_MAX) -> None:
    try:
        os.makedirs(path.parent, mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines[-limit:]) + ("\n" if lines else ""))
        os.chmod(path, 0o600)
    except OSError:
        pass
