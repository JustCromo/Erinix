import time

import pytest

from erinix.core.events import MAX_PATH, WebInfo
from erinix.core.webnorm import normalize_target


@pytest.mark.parametrize("raw,expected", [
    ("/p?id=1 UNION SELECT x", "/p?id=1 union select x"),                 # case
    ("/p?id=1%20UNION%20SELECT", "/p?id=1 union select"),                 # percent-encoding
    ("/p?id=1%2520union%2520select", "/p?id=1 union select"),             # double encoding
    ("/p?id=1%252520union", "/p?id=1 union"),                             # triple encoding
    ("/p?q=a+b", "/p?q=a b"),                                             # form encoding
    ("/p?id=1%09union%0aselect", "/p?id=1 union select"),                 # tabs / newlines
    ("/p?id=1   union      select", "/p?id=1 union select"),              # whitespace runs
    ("/p?id=un/**/ion/**/sel/**/ect", "/p?id=un ion sel ect"),            # comments split words...
    ("/p?id=1/**/union/**/select", "/p?id=1 union select"),               # ...but not when used as spaces
    ("/p?id=uni%00on select", "/p?id=union select"),                      # NUL bytes
    ("/p?x=%EF%BC%87%20or%201=1", "/p?x=' or 1=1"),                       # full-width apostrophe (NFKC)
    ("/%2e%2e/%2e%2e/etc/passwd", "/../../etc/passwd"),                   # encoded dots
    ("/p?x=%zz%", "/p?x=%zz%"),                                           # broken escapes are left alone
])
def test_normalization_removes_evasion_tricks(raw, expected):
    assert normalize_target(raw) == expected


def test_edge_spaces_are_kept_for_rule_values():
    assert normalize_target("; cat ") == "; cat "
    assert normalize_target("  ; cat   ") == " ; cat "


def test_output_is_bounded():
    assert len(normalize_target("a" * 50_000)) <= 4096
    assert len(normalize_target("%41" * 10_000)) <= 4096


def test_adversarial_inputs_stay_fast():
    nasty = ["/**/" * 1000, "%25" * 1000 + "41", "/*" * 2000, "\u2000" * 4000, "%" * 4000, "+" * 4000]
    start = time.monotonic()
    for text in nasty:
        normalize_target(text)
    assert time.monotonic() - start < 1.0


def test_webinfo_rejects_bad_values():
    ok = dict(remote_addr="10.0.0.1", method="GET", target="/", status=200)
    WebInfo.build(**ok)
    for field, bad in (("remote_addr", "999.1.1.1"), ("remote_addr", ""), ("method", "G E T"), ("method", ""),
                       ("method", "A" * 17), ("method", "GET\x00"), ("status", 99), ("status", 600),
                       ("status", "200"), ("status", True), ("size", -1), ("target", 5)):
        with pytest.raises(ValueError):
            WebInfo.build(**{**ok, field: bad})


def test_webinfo_bounds_hostile_text_and_keeps_it_raw():
    w = WebInfo.build(remote_addr="::1", method="get", target="/" + "A" * 9000, status=404,
                      user_agent="x" * 1000, host="h" * 1000)
    assert w.method == "GET" and w.target.truncated and len(w.target.value) == MAX_PATH
    assert len(w.user_agent.value) == 256 and len(w.host.value) == 256
    raw = WebInfo.build(remote_addr="10.0.0.1", method="GET", target="/<script>%00", status=200)
    assert raw.target.value == "/<script>%00"                      # evidence stays raw
    assert raw.decoded == "/<script>"                               # rules see the normalized form
