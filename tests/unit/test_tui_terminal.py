import base64
import io
import os

import pytest

from erinix.tui import terminal as t


# ---------------------------------------------------------------- tokenizer
def test_tokenize_plain_and_csi():
    assert t.tokenize("ab\x1b[A\x1b[1;5C\r") == (["a", "b", "\x1b[A", "\x1b[1;5C", "\r"], "")


def test_tokenize_ss3_and_alt():
    assert t.tokenize("\x1bOH\x1bb") == (["\x1bOH", "\x1bb"], "")


def test_tokenize_incomplete_is_kept():
    assert t.tokenize("a\x1b[1;") == (["a"], "\x1b[1;")
    assert t.tokenize("\x1b") == ([], "\x1b")
    assert t.tokenize("\x1bO") == ([], "\x1bO")


def test_tokenize_malformed_csi_does_not_swallow_text():
    tokens, rest = t.tokenize("\x1b[\x01x")
    assert rest == "" and "x" in tokens


def test_tokenize_mouse_and_paste_markers():
    tokens, _ = t.tokenize("\x1b[<0;10;5M\x1b[<0;10;5m\x1b[200~hi\x1b[201~")
    assert tokens == ["\x1b[<0;10;5M", "\x1b[<0;10;5m", t.PASTE_START, "h", "i", t.PASTE_END]


# ---------------------------------------------------------------- KeyReader
def make_reader():
    r, w = os.pipe()
    return t.KeyReader(r), w, r


def test_reader_handles_split_utf8_character():
    reader, w, r = make_reader()
    try:
        os.write(w, b"\xc3")
        os.write(w, b"\xa0x")
        assert reader.read(timeout=0.5) == "à" and reader.read(timeout=0.5) == "x"
    finally:
        os.close(w), os.close(r)


def test_reader_timeout_and_lone_escape():
    reader, w, r = make_reader()
    try:
        assert reader.read(timeout=0.01) is None
        os.write(w, b"\x1b")
        assert reader.read(timeout=0.5) == "\x1b"        # lone ESC, after a short wait
        os.write(w, b"\x1b[A")
        assert reader.read(timeout=0.5) == "\x1b[A"
    finally:
        os.close(w), os.close(r)


def test_reader_eof():
    reader, w, r = make_reader()
    os.close(w)
    try:
        with pytest.raises(EOFError):
            reader.read(timeout=0.5)
    finally:
        os.close(r)


# -------------------------------------------------------------------- mouse
def test_parse_mouse():
    press = t.parse_mouse("\x1b[<0;12;7M")
    assert (press.x, press.y, press.left, press.released, press.motion) == (12, 7, True, False, False)
    assert t.parse_mouse("\x1b[<0;12;7m").released
    drag = t.parse_mouse("\x1b[<32;13;7M")
    assert drag.motion and drag.left
    assert t.parse_mouse("\x1b[<64;1;1M").wheel_up
    down = t.parse_mouse("\x1b[<65;1;1M")
    assert down.wheel and not down.wheel_up and not down.left
    assert t.parse_mouse("\x1b[<0;0;5M") is None
    assert t.parse_mouse("\x1b[A") is None
    assert t.parse_mouse("\x1b[<99999999;1;1M") is None


# ---------------------------------------------------------------- selection
LINES = ["first line", "\x1b[31msecond\x1b[0m line", "漢字 wide", "last"]


def test_selection_columns_and_bounds():
    sel = t.Selection((2, 5), (0, 3))
    assert sel.bounds == ((0, 3), (2, 5))
    assert sel.columns(0) == (3, None) and sel.columns(1) == (0, None) and sel.columns(2) == (0, 5)
    assert sel.columns(3) is None and not sel.is_empty and t.Selection((1, 1), (1, 1)).is_empty


def test_extract_single_and_multi_line():
    assert t.extract_selected_text(LINES, t.Selection((0, 0), (0, 4))) == "first"
    assert t.extract_selected_text(LINES, t.Selection((0, 6), (1, 5))) == "line\nsecond"
    assert "\x1b" not in t.extract_selected_text(LINES, t.Selection((1, 0), (1, 20)))


def test_extract_wide_characters_and_bounds():
    assert t.extract_selected_text(LINES, t.Selection((2, 0), (2, 3))) == "漢字"
    assert t.extract_selected_text(LINES, t.Selection((0, 0), (99, 0))) == ""
    assert t.extract_selected_text(LINES, t.Selection((0, 2), (0, 2))) == ""


def test_highlight_keeps_colors_and_survives_resets():
    out = t.highlight_columns("\x1b[31mred\x1b[0m blue", 2, 8)
    assert t.strip_ansi(out) == "red blue"
    assert "\x1b[31m" in out and "\x1b[7m" in out and "\x1b[27m" in out
    assert out.index("\x1b[0m") < out.rindex("\x1b[7m")     # reverse re-enabled after the reset


def test_highlight_range_and_wide():
    out = t.highlight_columns("abcdef", 1, 3)
    assert out == "a\x1b[7mbc\x1b[27mdef"
    assert t.highlight_columns("漢字", 0, 1).startswith("\x1b[7m漢")


def test_clip_ansi_line():
    clipped = t.clip_ansi_line("\x1b[31mabcdefghij\x1b[0m", 4)
    assert t.visible_width(clipped) == 4 and clipped.endswith(t.RESET) and "\x1b[31m" in clipped
    assert t.clip_ansi_line("hello", 10) == "hello"
    assert t.visible_width(t.clip_ansi_line("漢字漢字", 5)) <= 5


def test_clipboard_osc52_and_limit():
    out = io.StringIO()
    assert t.copy_to_clipboard(out, "àb")
    payload = out.getvalue().split(";")[-1].rstrip("\x1b\\")
    assert base64.b64decode(payload).decode() == "àb" and out.getvalue().startswith("\x1b]52;c;")
    big = io.StringIO()
    assert not t.copy_to_clipboard(big, "x" * (t.MAX_CLIPBOARD_BYTES + 1)) and big.getvalue() == ""
    assert not t.copy_to_clipboard(io.StringIO(), "")


def test_fullscreen_enters_and_always_restores():
    out = io.StringIO()
    with pytest.raises(RuntimeError):
        with t.fullscreen(out):
            raise RuntimeError("boom")
    text = out.getvalue()
    assert text.startswith(t.ALT_ON + t.MOUSE_ON + t.PASTE_ON)
    assert text.endswith(t.RESET + t.PASTE_OFF + t.MOUSE_OFF + t.CURSOR_SHOW + t.ALT_OFF)
