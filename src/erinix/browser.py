"""Open Erinix's own local address in the default browser, quietly and exactly once.

`xdg-open` is started with its output thrown away: browsers print graphics and
process warnings that would otherwise land in the user's terminal (or corrupt
the full-screen console). Only our own loopback addresses are ever opened.
"""

from __future__ import annotations

import shutil
import subprocess
import webbrowser
from typing import Callable

URL_PREFIX = "http://127.0.0.1:"
_FORBIDDEN = frozenset(" \t\r\n\"'`\\<>|;&$")


def open_url(url: str, *, which: Callable[[str], str | None] = shutil.which,
             popen: Callable[..., object] = subprocess.Popen,
             fallback: Callable[[str], bool] = webbrowser.open) -> bool:
    if not url.startswith(URL_PREFIX) or any(c in _FORBIDDEN for c in url) or len(url) > 300:
        return False
    exe = which("xdg-open")
    if exe:
        try:
            popen([exe, url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  start_new_session=True, close_fds=True)
            return True
        except OSError:
            pass
    try:
        return bool(fallback(url))
    except webbrowser.Error:
        return False
