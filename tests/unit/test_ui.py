import ipaddress

import pytest

from erinix.core.events import ProcessKey
from erinix.engine import Alert
from erinix.rules import Response, Severity
from erinix.ui.render import banner, display_width, panel, progress, safe, Seg, strip_ansi, table
from erinix.ui.theme import Theme, detect_color_level, detect_unicode
from erinix.ui.views import alert_panel


class Tty:
    encoding = "utf-8"

    def isatty(self):
        return True


class Pipe:
    encoding = "utf-8"

    def isatty(self):
        return False


def lines_fit(text, width):
    return all(display_width(strip_ansi(line)) <= width for line in text.splitlines())


def test_safe_escapes_control_characters():
    out = safe("a\x1b[31mb\nc\x00d")
    assert "\x1b" not in out and "\n" not in out and "\x00" not in out
    assert "\\x1b" in out


def test_display_width_wide_and_combining():
    assert display_width("abc") == 3
    assert display_width("漢") == 2
    assert display_width("e\u0301") == 1


def test_table_fits_width_and_truncates():
    t = Theme(0, True, width=50)
    out = table(t, ["Regola", "Dettaglio"], [["x" * 80, "y" * 80], ["corta", "ok"]])
    assert lines_fit(out, 50) and "…" in out


def test_table_ascii_fallback_has_no_unicode():
    t = Theme(0, False, width=60)
    out = table(t, ["A", "B"], [[Seg("ciao", "ok"), "x"]])
    assert out.isascii() and "+" in out and "|" in out


def test_table_never_passes_hostile_escapes():
    t = Theme(3, True, width=80)
    out = table(t, ["Nome"], [["x\x1b[31mROSSO\x1b[0m"], [Seg("y\x07", "bad")]])
    assert "x\x1b[31m" not in out and "\x07" not in out


def test_colored_output_equals_plain_after_strip():
    rows = [[Seg("web-rce", "accent", True), Seg(" CRITICAL ", "crit", True), "ok"]]
    plain = table(Theme(0, True, 80), ["Regola", "Gravità", "Altro"], rows)
    colored = table(Theme(3, True, 80), ["Regola", "Gravità", "Altro"], rows)
    assert colored != plain and strip_ansi(colored) == plain


def test_table_rejects_ragged_rows():
    with pytest.raises(ValueError):
        table(Theme(0, True, 80), ["A", "B"], [["solo uno"]])


def test_panel_lines_have_equal_width():
    t = Theme(0, True, width=60)
    out = panel(t, [Seg("titolo")], [[Seg("riga")], [Seg("x" * 200)]], right=[Seg("rev 2")])
    assert {display_width(line) for line in out.splitlines()} == {60}


def test_color_detection():
    tty, pipe = Tty(), Pipe()
    assert detect_color_level(pipe, {"TERM": "xterm"}) == 0
    assert detect_color_level(tty, {"TERM": "xterm", "NO_COLOR": "1"}) == 0
    assert detect_color_level(tty, {"TERM": "dumb"}) == 0
    assert detect_color_level(tty, {"TERM": "xterm"}) == 1
    assert detect_color_level(tty, {"TERM": "xterm-256color"}) == 2
    assert detect_color_level(tty, {"TERM": "xterm", "COLORTERM": "truecolor"}) == 3
    assert detect_color_level(pipe, {"ERINIX_COLOR": "always", "COLORTERM": "24bit"}) == 3
    assert detect_color_level(tty, {"ERINIX_COLOR": "never", "COLORTERM": "truecolor"}) == 0


def test_unicode_detection():
    assert detect_unicode(Tty())
    class Ascii:
        encoding = "ANSI_X3.4-1968"
    assert not detect_unicode(Ascii())


def test_paint_levels_and_prompt_guards():
    assert "38;2;226;122;63" in Theme(3).paint("x", "accent")
    assert "38;5;173" in Theme(2).paint("x", "accent")
    assert Theme(1).paint("x", "accent").startswith("\x1b[33m")
    assert "48;2;" in Theme(3).paint("x", "crit")
    assert Theme(0).paint("x", "accent") == "x"
    wrapped = Theme(3).paint("x", "accent", prompt=True)
    assert wrapped.startswith("\001") and wrapped.endswith("\002")


def make_alert(sev, kind="chain", complete=False):
    return Alert(alert_id="a", revision=2, rule_id="web-rce-revshell", kind=kind, severity=sev,
                 response=Response.AUTO, steps_done=2, steps_total=3, step_id="shell-connects-outbound",
                 complete=complete, mitre=("T1190",), description="desc", evidence=(),
                 process=ProcessKey(900, 20), anchor=ProcessKey(900, 20),
                 remote_addr=ipaddress.ip_address("10.0.0.5"), mono_ns=0, wall_ns=0)


@pytest.mark.parametrize("level", [0, 3])
@pytest.mark.parametrize("sev", list(Severity))
def test_alert_panel_renders_every_severity(sev, level):
    out = alert_panel(Theme(level, True, 80), make_alert(sev))
    plain = strip_ansi(out)
    assert sev.value.upper() in plain and "10.0.0.5" in plain and "2/3" in plain
    assert lines_fit(out, 80)


def test_alert_panel_other_kinds():
    t = Theme(0, True, 80)
    assert "indicatore" in alert_panel(t, make_alert(Severity.HIGH, kind="indicator"))
    eng = make_alert(Severity.CRITICAL, kind="engine")
    assert "web-rce-revshell" in alert_panel(t, eng)


def test_progress_and_banner():
    t = Theme(0, True, 80)
    assert "".join(s.text for s in progress(t, 2, 5)) == "██░░░"
    lines = banner(t, "0.1.0")
    assert len(lines) == 4 and "E R I N I X" in lines[1] and "0.1.0" in lines[2]
