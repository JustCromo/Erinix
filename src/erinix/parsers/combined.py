"""Apache / nginx "combined" access log line -> WebInfo.

    203.0.113.5 - - [12/Nov/2026:10:00:00 +0100] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"

Same rules as the Caddy parser: everything is hostile text (the request target and the user agent are typed by
the visitor), lines are bounded, and one bad line never stops the others. The pattern has no nested repetition,
so no line can make it slow. Behind a proxy this log shows the proxy's address, not the visitor's: that is a
configuration matter (log the real client address), and Erinix says so in the docs rather than guessing from headers.
"""

from __future__ import annotations

import re

from erinix.core.events import WebInfo
from erinix.parsers.web import LogParseError

MAX_LINE = 16384

_LINE = re.compile(
    r'(?P<ip>[0-9A-Fa-f:.]{2,45}) \S{1,64} \S{1,64} \[[^\]\n]{1,64}\] '
    r'"(?P<method>[A-Za-z]{1,16}) (?P<target>[^ "\n]{1,4096})(?: [^"\n]{0,32})?" '
    r'(?P<status>\d{3}) (?P<size>\d{1,12}|-)'
    r'(?: "(?P<referer>[^"\n]{0,2048})" "(?P<agent>[^"\n]{0,1024})")?')


def parse_combined_line(line: str) -> WebInfo | None:
    """The request, None for an empty line, or LogParseError for anything that is not a combined access line."""
    if len(line) > MAX_LINE:
        raise LogParseError("line too long")
    text = line.strip()
    if not text:
        return None
    match = _LINE.fullmatch(text)
    if match is None:
        raise LogParseError("not a combined access log line")
    size = match["size"]
    try:
        return WebInfo.build(remote_addr=match["ip"], method=match["method"], target=match["target"], status=int(match["status"]),
                             user_agent=match["agent"] or "", size=None if size == "-" else int(size))
    except ValueError as exc:
        raise LogParseError(str(exc)) from None
