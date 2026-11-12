"""Parsers that turn log lines into Erinix events.

Log lines are UNTRUSTED text: parts of them (user names, URLs, user agents) are
chosen by whoever is attacking. Parsers never use regular expressions, never
trust a field just because it looks right, and fail loudly (LogParseError)
instead of guessing.
"""

from erinix.parsers.auth import SshEvent, extract_ssh_message, parse_ssh_line, parse_ssh_message
from erinix.parsers.web import LogParseError, parse_caddy_line

__all__ = ["LogParseError", "SshEvent", "extract_ssh_message", "parse_caddy_line",
           "parse_ssh_line", "parse_ssh_message"]
