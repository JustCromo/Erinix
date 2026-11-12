"""Command history: a private file (0600) that is never trusted blindly.

It is not read unless it is a regular file owned by the user and not accessible
to others; it is never written through a symlink.
"""

from __future__ import annotations

import os
import pwd
import stat
from pathlib import Path

HISTORY_MAX = 500
MAX_LINE = 4096


def _running_as_root() -> bool:
    return os.geteuid() == 0


def state_dir() -> Path:
    """Where Erinix keeps its private state (history, alert store, server info).

    As root it is ALWAYS root's own home, never $HOME or $XDG_STATE_HOME: `sudo` may keep
    them pointing at the caller's home, and root must never write into a directory that an
    unprivileged user controls (a symlink there would turn the write into a privilege escalation).
    """
    if _running_as_root():
        base = os.path.join(pwd.getpwuid(0).pw_dir, ".local", "state")
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "erinix"


def history_path() -> Path:
    return state_dir() / "history"


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
