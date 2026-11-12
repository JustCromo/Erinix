"""Caddy access log (JSON) -> WebInfo.

Security notes
- The client address is `client_ip` (Caddy derives it using ONLY the trusted
  proxies configured in Caddy) or `remote_ip`. X-Forwarded-For and similar
  headers sent by the client are never read: they can be forged.
- Lines are size-limited; JSON nesting bombs are caught; every field is
  type-checked.
- Lines that are not access records (Caddy runtime logs mixed in the same
  stream, for example in Docker) are ignored, not treated as errors.
"""

from __future__ import annotations

import ipaddress
import json

from erinix.core.events import WebInfo

MAX_LINE = 65536
MAX_DEPTH = 32          # a real Caddy access record nests about 4 levels; more is hostile


class LogParseError(ValueError):
    """The line looked like a record of interest but is malformed."""


def _addr(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return None


def _user_agent(headers: object) -> str:
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == "user-agent":
            if isinstance(value, list) and value and isinstance(value[0], str):
                return value[0]
            if isinstance(value, str):
                return value
    return ""


def _too_deep(text: str) -> bool:
    """True if the JSON nests deeper than MAX_DEPTH (string contents do not count).

    Done BEFORE parsing so the result is the same on every Python version: some
    versions raise RecursionError on deep nesting, others parse it happily.
    """
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return True
        elif char in "]}":
            depth -= 1
    return False


def parse_caddy_line(line: str) -> WebInfo | None:
    """Return the request, None if the line is not an access record, or raise LogParseError."""
    if len(line) > MAX_LINE:
        raise LogParseError("line too long")
    text = line.strip()
    if not text:
        return None
    if not text.startswith("{"):
        raise LogParseError("not a JSON object")
    if _too_deep(text):
        raise LogParseError("JSON nested too deeply")
    try:
        record = json.loads(text)
    except (ValueError, RecursionError):
        raise LogParseError("invalid JSON") from None
    if not isinstance(record, dict):
        raise LogParseError("not a JSON object")
    request = record.get("request")
    status = record.get("status")
    logger = record.get("logger")
    if not isinstance(request, dict) or status is None:
        return None
    if isinstance(logger, str) and not logger.startswith("http.log.access"):
        return None                                  # e.g. http.log.error: not an access record
    address = _addr(request.get("client_ip")) or _addr(request.get("remote_ip"))
    if address is None:
        raise LogParseError("missing or invalid client address")
    uri = request.get("uri")
    host = request.get("host", "")
    if not isinstance(uri, str) or not isinstance(host, str):
        raise LogParseError("invalid request fields")
    size = record.get("size")
    try:
        return WebInfo.build(remote_addr=address, method=request.get("method", ""), target=uri,
                             status=status, host=host, user_agent=_user_agent(request.get("headers")),
                             size=size if isinstance(size, int) and not isinstance(size, bool) else None)
    except ValueError as exc:
        raise LogParseError(str(exc)) from None
