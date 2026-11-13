import subprocess
import webbrowser

import pytest

from erinix.browser import open_url

URL = "http://127.0.0.1:8421/#login=" + "a" * 43


def test_opens_once_with_all_output_thrown_away():
    calls = []
    fallback = []
    ok = open_url(URL, which=lambda n: "/usr/bin/xdg-open", popen=lambda *a, **k: calls.append((a, k)), fallback=lambda u: fallback.append(u))
    assert ok and len(calls) == 1 and fallback == []
    (argv,), kw = calls[0]
    assert argv == ["/usr/bin/xdg-open", URL]
    assert kw["stdout"] == kw["stderr"] == kw["stdin"] == subprocess.DEVNULL and kw["start_new_session"] is True


def test_falls_back_when_xdg_open_is_missing_or_fails():
    seen = []
    assert open_url(URL, which=lambda n: None, fallback=lambda u: seen.append(u) or True) and seen == [URL]

    def boom(*a, **k):
        raise OSError("no")
    seen.clear()
    assert open_url(URL, which=lambda n: "/x", popen=boom, fallback=lambda u: seen.append(u) or True) and seen == [URL]
    assert open_url(URL, which=lambda n: None, fallback=lambda u: (_ for _ in ()).throw(webbrowser.Error("x"))) is False


@pytest.mark.parametrize("bad", ["https://evil.example.com/", "http://127.0.0.1.evil.com/", "http://localhost:8421/", "file:///etc/passwd",
                                 "javascript:alert(1)", "--help", "http://127.0.0.1:1/ -x", "http://127.0.0.1:1/\nx", "http://127.0.0.1:1/;id",
                                 "http://127.0.0.1:1/$(id)", "http://127.0.0.1:1/" + "a" * 400, ""])
def test_only_our_own_local_addresses_are_ever_opened(bad):
    def nope(*a, **k):
        raise AssertionError("must not run anything")
    assert open_url(bad, which=lambda n: "/usr/bin/xdg-open", popen=nope, fallback=nope) is False
