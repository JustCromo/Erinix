"""Normalization of web request targets, so rules compare ONE canonical form.

Attackers hide payloads with percent-encoding (even twice), mixed case,
look-alike Unicode characters, NUL bytes, odd whitespace and SQL comments.
The normalized form removes those tricks before any rule looks at it.

It is a heuristic, not a WAF: it lowers the effort-to-evade bar, it does not
make evasion impossible. No regular expressions are used (no ReDoS).
"""

from __future__ import annotations

import unicodedata
from urllib.parse import unquote

MAX_ROUNDS = 3          # percent-decoding passes (catches double/triple encoding)
MAX_COMMENTS = 64       # SQL comments stripped per target (bounded work)
_SPACES = "\t\r\n\x0b\x0c"


def _strip_comments(text: str) -> str:
    """Replace /* ... */ with a space (SQL comment obfuscation like un/**/ion)."""
    for _ in range(MAX_COMMENTS):
        start = text.find("/*")
        if start == -1:
            break
        end = text.find("*/", start + 2)
        if end == -1:
            break
        text = text[:start] + " " + text[end + 2:]
    return text


def _collapse_spaces(text: str) -> str:
    """Collapse whitespace runs, keeping ONE space at the edges if there was one.

    Edge spaces matter: a rule such as "; cat " must not turn into ";cat".
    """
    core = " ".join(text.split())
    return (" " if text[:1].isspace() else "") + core + (" " if text[-1:].isspace() and core else "")


def normalize_target(raw: str, limit: int = 4096) -> str:
    text = raw[:limit]
    for _ in range(MAX_ROUNDS):
        if "%" not in text:
            break
        decoded = unquote(text, errors="replace")
        if decoded == text:
            break
        text = decoded
    text = text.replace("+", " ")
    text = unicodedata.normalize("NFKC", text)
    text = _strip_comments(text)
    text = "".join(" " if c in _SPACES else c for c in text if c != "\x00" and (c.isprintable() or c in _SPACES))
    return _collapse_spaces(text.casefold())[:limit]
