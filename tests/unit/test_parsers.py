import json

import pytest

from erinix.core.events import EventType
from erinix.parsers import LogParseError, extract_ssh_message, parse_caddy_line, parse_ssh_line, parse_ssh_message
from erinix.parsers.web import MAX_LINE


def caddy(**over):
    request = {"remote_ip": "192.168.50.31", "client_ip": "192.168.50.31", "method": "GET", "host": "r.lan",
               "uri": "/p?id=1", "headers": {"User-Agent": ["curl/8.5"]}}
    request.update(over.pop("request", {}))
    record = {"level": "info", "logger": "http.log.access.log0", "request": request, "size": 10, "status": 200}
    record.update(over)
    return json.dumps(record)


# ------------------------------------------------------------------- Caddy
def test_caddy_access_line():
    w = parse_caddy_line(caddy())
    assert (str(w.remote_addr), w.method, w.host.value, w.target.value, w.status, w.size) == \
        ("192.168.50.31", "GET", "r.lan", "/p?id=1", 200, 10)
    assert w.user_agent.value == "curl/8.5"


def test_client_ip_is_preferred_and_forged_headers_are_ignored():
    line = caddy(request={"remote_ip": "10.0.0.5", "client_ip": "192.168.50.31",
                          "headers": {"X-Forwarded-For": ["6.6.6.6"], "X-Real-Ip": ["7.7.7.7"], "User-Agent": ["u"]}})
    assert str(parse_caddy_line(line).remote_addr) == "192.168.50.31"
    only_remote = caddy(request={"client_ip": "not-an-ip", "headers": {"X-Forwarded-For": ["6.6.6.6"]}})
    assert str(parse_caddy_line(only_remote).remote_addr) == "192.168.50.31"


def test_caddy_ipv6_and_user_agent_variants():
    assert str(parse_caddy_line(caddy(request={"client_ip": "[2001:db8::1]"})).remote_addr) == "2001:db8::1"
    assert parse_caddy_line(caddy(request={"headers": {"user-agent": "plain"}})).user_agent.value == "plain"
    assert parse_caddy_line(caddy(request={"headers": "oops"})).user_agent.value == ""


def test_non_access_lines_are_ignored_not_errors():
    assert parse_caddy_line("") is None and parse_caddy_line("   ") is None
    assert parse_caddy_line(json.dumps({"level": "info", "msg": "serving initial configuration"})) is None
    assert parse_caddy_line(caddy(logger="http.log.error.log0")) is None
    assert parse_caddy_line(json.dumps({"request": "x", "status": 200})) is None


@pytest.mark.parametrize("line", [
    "not json", "[1, 2]", '{"unterminated": ', "x" * (MAX_LINE + 1),
    '{"a":' + "[" * 30000 + "]" * 30000 + "}",                                   # nesting bomb
    caddy(status="200"), caddy(status=700), caddy(status=True),
    caddy(request={"client_ip": "999.1.1.1", "remote_ip": "also bad"}), caddy(request={"remote_ip": None, "client_ip": None}),
    caddy(request={"method": "G E T"}), caddy(request={"method": 5}), caddy(request={"uri": 5}),
    caddy(request={"host": ["a"]}),
])
def test_malformed_access_records_raise(line):
    with pytest.raises(LogParseError):
        parse_caddy_line(line)


def test_huge_uri_is_truncated_not_rejected():
    w = parse_caddy_line(caddy(request={"uri": "/" + "A" * 20000}))
    assert w.target.truncated and len(w.target.value) == 4096


def test_bool_size_is_not_a_size():
    assert parse_caddy_line(caddy(size=True)).size is None


# -------------------------------------------------------------------- sshd
HDR = "Nov 12 10:00:00 pi sshd-session[812]: "


@pytest.mark.parametrize("message,kind,user,ip", [
    ("Failed password for root from 203.0.113.50 port 4444 ssh2", EventType.AUTH_FAILURE, "root", "203.0.113.50"),
    ("Failed password for invalid user admin from 203.0.113.50 port 4444 ssh2", EventType.AUTH_FAILURE, "admin", "203.0.113.50"),
    ("Failed publickey for ivan from 10.0.0.2 port 22 ssh2: RSA SHA256:abc", EventType.AUTH_FAILURE, "ivan", "10.0.0.2"),
    ("Invalid user oracle from 198.51.100.7 port 5000", EventType.AUTH_FAILURE, "oracle", "198.51.100.7"),
    ("Accepted password for ivan from 10.0.0.2 port 51234 ssh2", EventType.AUTH_SUCCESS, "ivan", "10.0.0.2"),
    ("Accepted publickey for ivan from 2001:db8::1 port 51234 ssh2: ED25519 SHA256:abc", EventType.AUTH_SUCCESS, "ivan", "2001:db8::1"),
])
def test_ssh_messages(message, kind, user, ip):
    e = parse_ssh_message(message)
    assert (e.kind, e.info.user.value, str(e.info.remote_addr), e.info.service.value) == (kind, user, ip, "sshd")
    assert parse_ssh_line(HDR + message).kind is kind


@pytest.mark.parametrize("message", [
    "Connection closed by authenticating user root 10.0.0.9 port 22 [preauth]", "Received disconnect from 10.0.0.9 port 22:11",
    "Server listening on 0.0.0.0 port 22.", "pam_unix(sshd:session): session opened for user root", "",
])
def test_uninteresting_ssh_messages_are_ignored(message):
    assert parse_ssh_message(message) is None


def test_log_injection_in_user_name_blames_the_real_source():
    msg = "Failed password for invalid user x from 198.51.100.9 port 22 ssh2 from 203.0.113.50 port 4444 ssh2"
    e = parse_ssh_message(msg)
    assert str(e.info.remote_addr) == "203.0.113.50"
    assert "198.51.100.9" in e.info.user.value                       # the fake tail stays in the user name, harmless
    deeper = "Failed password for x from 1.1.1.1 port 1 from 2.2.2.2 port 2 from 203.0.113.50 port 4444 ssh2"
    assert str(parse_ssh_message(deeper).info.remote_addr) == "203.0.113.50"


def test_forged_tail_is_never_used_when_the_real_tail_is_broken():
    with pytest.raises(LogParseError):
        parse_ssh_message("Failed password for x from 198.51.100.9 port 22 ssh2 from not-an-ip port 4444 ssh2")
    for bad in ("Failed password for root", "Failed password for root from 10.0.0.1 port", "Failed password for root from 10.0.0.1 port 99999 ssh2",
                "Accepted password for root from 10.0.0.1 port abc ssh2"):
        with pytest.raises(LogParseError):
            parse_ssh_message(bad)


def test_lines_from_other_programs_cannot_pretend_to_be_sshd():
    forged = "Nov 12 10:00:00 pi sudo[5]: x : sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert extract_ssh_message(forged) is None and parse_ssh_line(forged) is None
    assert parse_ssh_line("Nov 12 10:00:00 pi cron[5]: Failed password for root from 1.2.3.4 port 22 ssh2") is None
    assert parse_ssh_line("Failed password for root from 1.2.3.4 port 22 ssh2") is None       # no syslog header
    assert parse_ssh_line("Nov 12 10:00:00 pi notsshd[5]: Failed password for root from 1.2.3.4 port 22 ssh2") is None
    assert parse_ssh_line("Nov 12 10:00:00 pi sshd[x]: Failed password for root from 1.2.3.4 port 22 ssh2") is None
    assert parse_ssh_line("Nov 12 10:00:00 pi sshd[5] Failed password for root from 1.2.3.4 port 22 ssh2") is None


def test_syslog_header_variants():
    msg = "Failed password for root from 203.0.113.50 port 4444 ssh2"
    for header in ("Nov  2 10:00:00 pi sshd[812]: ", "2026-11-12T10:00:00.123456+01:00 pi sshd-session[7]: ",
                   "2026-11-12T10:00:00Z pi sshd[7]: "):
        assert parse_ssh_line(header + msg).kind is EventType.AUTH_FAILURE


def test_ssh_user_names_are_bounded():
    e = parse_ssh_message("Failed password for " + "u" * 5000 + " from 203.0.113.50 port 4444 ssh2")
    assert len(e.info.user.value) == 256 and e.info.user.truncated


def test_overlong_ssh_messages_are_rejected_not_cut():
    with pytest.raises(LogParseError):
        parse_ssh_message("Failed password for " + "u" * 9000 + " from 203.0.113.50 port 4444 ssh2")


# ------------------------------------------------ nesting limit (same on every Python)
@pytest.mark.parametrize("bomb", [
    '{"a":' + "[" * 30000 + "]" * 30000 + "}",
    "[" * 20000 + "]" * 20000,
    '{"a":' * 5000 + "1" + "}" * 5000,
    '{"request":' + '{"x":[' * 3000 + "1" + "]}" * 3000 + "}",
    "{" + '"a":[' * 40 + "1" + "]" * 40 + "}",
])
def test_deep_nesting_is_rejected_identically_on_every_python(bomb):
    with pytest.raises(LogParseError):
        parse_caddy_line(bomb)


def test_nesting_error_says_why():
    with pytest.raises(LogParseError, match="nested too deeply"):
        parse_caddy_line('{"a":' + "[" * 30000 + "]" * 30000 + "}")


def test_brackets_inside_strings_do_not_count_as_nesting():
    agent = "[" * 500 + '\\"' + "{" * 500
    w = parse_caddy_line(caddy(request={"headers": {"User-Agent": [agent]}}))
    assert w is not None and w.user_agent.truncated                     # kept (bounded), not rejected
    assert parse_caddy_line(json.dumps({"msg": "[" * 5000})) is None    # valid JSON, not an access record


def test_realistic_nesting_is_accepted():
    line = caddy(request={"tls": {"version": 772, "cipher_suite": 4865, "proto": "h2", "server_name": "r.lan"},
                          "headers": {"User-Agent": ["x"], "Accept": ["a", "b"]}})
    assert parse_caddy_line(line) is not None
