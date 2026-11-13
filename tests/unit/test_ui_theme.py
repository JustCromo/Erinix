

def test_ascii_mode_on_request_and_never_wider_than_the_terminal(monkeypatch):
    import io
    import os

    from erinix.ui import theme as th

    class Utf8(io.StringIO):
        encoding = "utf-8"

    assert th.detect_unicode(Utf8(), {}) is True
    assert th.detect_unicode(Utf8(), {"ERINIX_ASCII": "1"}) is False
    assert th.Theme.from_stream(Utf8(), {"ERINIX_ASCII": "1"}).glyph("ok") != th.Theme(0, True).glyph("ok")
    for columns in (20, 35, 50, 80, 105, 300):
        monkeypatch.setattr("shutil.get_terminal_size", lambda default, c=columns: os.terminal_size((c, 24)))
        assert th.Theme(0, True).width == min(columns, 120)
