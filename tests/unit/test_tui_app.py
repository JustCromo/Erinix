import base64
import io
from pathlib import Path

import pytest

from erinix.commands.builtin import build_registry
from erinix.commands.registry import Command
from erinix.tui import terminal as t
from erinix.tui.app import MAX_OUTPUT_LINES, TuiApp, sanitize_line
from erinix.tui.welcome import SessionInfo
from erinix.ui.theme import Theme

REPO_RULES = str(Path(__file__).resolve().parents[2] / "rules")
SESSION = SessionInfo(1000, "minimale", "eBPF (CO-RE)", True, "sudo /opt/erinix")
ROOT_SESSION = SessionInfo(0, "eBPF (CO-RE)", "eBPF (CO-RE)", False, "sudo erinix")


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def make_app(session=SESSION, registry=None, history=None, color=3, clock=None):
    size = [130, 40]                                  # dimensione "del terminale", modificabile
    app = TuiApp(registry or build_registry(), theme=Theme(color, True, 120), out=io.StringIO(),
                 session=session, session_fn=lambda: session, history=history,
                 clock=clock or Clock(), size_fn=lambda: (size[0], size[1]))
    app.size = size
    return app


def type_line(app, text, enter=True):
    for ch in text:
        app.handle_token(ch)
    if enter:
        app.handle_token("\r")


def doc_text(app):
    return "\n".join(t.strip_ansi(line) for line in app.lines)


def frame(app, cols=130, rows=40):
    app.size[:] = [cols, rows]
    return app.render_frame(cols, rows)


# -------------------------------------------------------------- sanitizzazione
def test_sanitize_line_keeps_colors_only():
    assert sanitize_line("\x1b[31mok\x1b[0m") == "\x1b[31mok\x1b[0m"
    evil = sanitize_line("a\x1b]52;c;ZXZpbA==\x07b\x1b[2Jc\x1b[1;1Hd\x00\te")
    assert "\x1b]" not in evil and "\x1b[2J" not in evil and "\x1b[1;1H" not in evil
    assert "\x07" not in evil and "\x00" not in evil


def test_hostile_command_output_never_reaches_the_terminal():
    reg = build_registry()
    reg.add(Command("evil", "x", "evil", "Prove",
                    lambda ctx, args: ctx.say("ciao\x1b]52;c;ZXZpbA==\x07\x1b[2J\x1b[31mrosso\x1b[0m") or 0))
    app = make_app(registry=reg)
    type_line(app, "evil")
    out = frame(app)
    assert "\x1b]" not in out and "\x1b[2J" not in out and "rosso" in t.strip_ansi(out)


# ------------------------------------------------------------------- disegno
def test_frame_shows_welcome_prompt_and_status():
    out = t.strip_ansi(frame(make_app()))
    for word in ("ERINIX", "AVVIO RAPIDO", "SESSIONE", "ROOTLESS", "erinix ▸", "sensore minimale",
                 "PUNTE ALTE"):
        assert word in out
    assert "sudo /opt/erinix" in out


def test_root_session_text():
    out = t.strip_ansi(frame(make_app(session=ROOT_SESSION)))
    assert "ROOT" in out and "Completi" in out and "Avvia con" not in out


def test_narrow_terminal_hides_mascot_but_keeps_info():
    app = make_app()
    out = t.strip_ansi(app.render_frame(80, 30))
    assert "AVVIO RAPIDO" in out and "PUNTE ALTE" not in out


def test_no_color_terminal_uses_text_fallback():
    out = frame(make_app(color=0))
    assert "38;2" not in out and "38;5" not in out and "48;" not in out
    assert "AVVIO RAPIDO" in t.strip_ansi(out)


def test_prompt_cursor_is_positioned_and_visible():
    app = make_app()
    type_line(app, "abc", enter=False)
    out = frame(app)
    assert out.endswith(t.CURSOR_SHOW) and "\x1b[" in out


def test_long_input_scrolls_horizontally_and_keeps_cursor_in_view():
    app = make_app()
    type_line(app, "x" * 300, enter=False)
    out = app.render_frame(60, 30)
    import re
    row, col = map(int, re.findall(r"\x1b\[(\d+);(\d+)H(?:\x1b\[\?25h)", out)[-1])
    assert col <= 60


# ---------------------------------------------------------------- comandi
def test_command_output_and_echo():
    app = make_app()
    type_line(app, "version")
    text = doc_text(app)
    assert "erinix ▸ version" in text and "erinix 0.1.0" in text


def test_unknown_command_and_syntax_error():
    app = make_app()
    type_line(app, "doctr")
    type_line(app, "echo 'aperta")
    text = doc_text(app)
    assert "Intendevi 'doctor'" in text and "sintassi non valida" in text


def test_clear_and_exit_and_ctrl_d():
    app = make_app()
    type_line(app, "version")
    type_line(app, "clear")
    assert app.lines == [] and not app.done
    app.handle_token("\x04")
    assert app.done
    app2 = make_app()
    type_line(app2, "exit")
    assert app2.done
    app3 = make_app()
    type_line(app3, "abc", enter=False)
    app3.handle_token("\x01")
    app3.handle_token("\x04")
    assert app3.editor.text == "bc" and not app3.done


def test_ctrl_c_and_ctrl_l():
    app = make_app()
    type_line(app, "boh", enter=False)
    app.handle_token("\x03")
    assert app.editor.text == "" and "^C" in doc_text(app)
    app.handle_token("\x0c")
    assert app.lines == []


def test_command_errors_do_not_crash_the_console():
    reg = build_registry()

    def boom(ctx, args):
        raise ValueError("rotto")

    reg.add(Command("boom", "x", "boom", "Prove", boom))
    app = make_app(registry=reg)
    type_line(app, "boom")
    type_line(app, "version")
    text = doc_text(app)
    assert "errore interno (ValueError)" in text and "erinix 0.1.0" in text


def test_sensitive_commands_stay_out_of_history():
    reg = build_registry()
    reg.add(Command("secret", "x", "secret", "Prove", lambda ctx, a: 0, sensitive=True))
    app = make_app(registry=reg)
    type_line(app, "secret")
    type_line(app, "version")
    assert app.editor.history == ["version"]


def test_replay_streams_into_the_screen():
    app = make_app()
    type_line(app, f"replay admin --fast --rules {REPO_RULES}")
    text = doc_text(app)
    assert "Amministratore al lavoro" in text and "Nessun alert" in text


def test_output_buffer_is_bounded():
    app = make_app()
    for i in range(MAX_OUTPUT_LINES + 50):
        app.append_line(str(i))
    assert len(app.lines) == MAX_OUTPUT_LINES and app.lines[-1] == str(MAX_OUTPUT_LINES + 49)


# ------------------------------------------------------------------ editing
def test_history_and_arrows():
    app = make_app(history=["help", "doctor"])
    app.handle_token("\x1b[A")
    assert app.editor.text == "doctor"
    app.handle_token("\x1b[A")
    app.handle_token("\x1b[B")
    assert app.editor.text == "doctor"
    app.handle_token("\x1b[D")
    app.handle_token("\x7f")
    assert app.editor.text == "doctr"


def test_tab_completion():
    app = make_app()
    type_line(app, "doc", enter=False)
    app.handle_token("\t")
    assert app.editor.text == "doctor "
    app.editor.kill_line()
    type_line(app, "rules ", enter=False)
    app.handle_token("\t")                       # list/validate: nessun prefisso comune oltre al vuoto
    assert "list" in doc_text(app) and "validate" in doc_text(app)
    app.editor.kill_line()
    type_line(app, "rules v", enter=False)
    app.handle_token("\t")
    assert app.editor.text == "rules validate "


def test_unknown_keys_are_ignored():
    app = make_app()
    for tok in ("\x1b[Z", "\x1b[1;2P", "\x1b[I", "\x00"):
        app.handle_token(tok)
    assert app.editor.text == ""


# ------------------------------------------------------------------- incolla
def test_paste_never_executes_and_newlines_become_spaces():
    app = make_app()
    app.handle_token(t.PASTE_START)
    for ch in "version\nrules list\r\n":
        app.handle_token(ch)
    app.handle_token("\x1b[A")          # sequenze dentro l'incolla: ignorate
    app.handle_token(t.PASTE_END)
    assert app.editor.text == "version rules list " and app.lines == []
    app.handle_token("\r")
    assert "erinix 0.1.0" not in doc_text(app) or "version rules list" in doc_text(app)


def test_paste_is_length_limited():
    app = make_app()
    app.handle_token(t.PASTE_START)
    for _ in range(9000):
        app.handle_token("x")
    app.handle_token(t.PASTE_END)
    assert len(app.editor.text) <= 4096


# ------------------------------------------------------------------- scorrere
def fill(app, n=80):
    for i in range(n):
        app.append_line(f"riga {i}")
    frame(app, rows=30)


def mouse(app, button, x, y, up=False):
    app.handle_token(f"\x1b[<{button};{x};{y}{'m' if up else 'M'}")


def test_wheel_and_page_scroll():
    app = make_app()
    fill(app)
    assert "riga 79" in t.strip_ansi(frame(app, rows=30))
    mouse(app, 64, 5, 5)
    mouse(app, 64, 5, 5)
    assert app.scroll == 6 and "riga 79" not in t.strip_ansi(frame(app, rows=30))
    mouse(app, 65, 5, 5)
    assert app.scroll == 3
    app.handle_token("\x1b[5~")
    assert app.scroll > 3
    app.handle_token("\x1b[6~")
    app.handle_token("\x1b[6~")
    assert app.scroll == 0
    mouse(app, 64, 5, 5)
    app.handle_token("a")                      # scrivere riporta in fondo
    assert app.scroll == 0


def test_scroll_is_clamped():
    app = make_app()
    for _ in range(100):
        mouse(app, 64, 1, 1)
    frame(app, rows=30)
    assert app.scroll <= len(app._doc)


# --------------------------------------------------------------------- mouse
def test_drag_selection_copies_to_clipboard_and_flashes():
    clock = Clock()
    app = make_app(clock=clock)
    app.append_line("prima riga di prova")
    app.append_line("seconda riga")
    out = frame(app)
    row = app._doc.index("prima riga di prova") - app._top + 1
    mouse(app, 0, 1, row)
    mouse(app, 32, 5, row)
    assert "\x1b[7m" in frame(app)                         # evidenziata mentre si trascina
    mouse(app, 0, 5, row, up=True)
    written = app.out.getvalue()
    payload = written.split("\x1b]52;c;")[-1].split("\x1b\\")[0]
    assert base64.b64decode(payload).decode() == "prima"
    assert "copiato" in t.strip_ansi(frame(app))
    clock.now += 10
    assert "copiato" not in t.strip_ansi(frame(app))


def test_click_without_drag_copies_nothing_and_key_clears_selection():
    app = make_app()
    app.append_line("testo")
    frame(app)
    mouse(app, 0, 2, 3)
    mouse(app, 0, 2, 3, up=True)
    assert "\x1b]52" not in app.out.getvalue()
    mouse(app, 0, 1, 3)
    mouse(app, 32, 4, 3)
    app.handle_token("a")
    assert app.selection is None


def test_resize_clears_selection():
    app = make_app()
    frame(app, cols=130)
    mouse(app, 0, 1, 2)
    mouse(app, 32, 6, 2)
    assert app.selection is not None
    frame(app, cols=100)
    assert app.selection is None


# ---------------------------------------------------------------- cronologia
def test_history_file_roundtrip(tmp_path, monkeypatch):
    from erinix import history as h

    path = tmp_path / "erinix" / "history"
    h.write_lines(path, ["help", "doctor"])
    assert h.read_lines(path) == ["help", "doctor"]
    path.chmod(0o644)
    assert h.read_lines(path) == []              # accessibile ad altri: ignorato


# ----------------------------------------------------------- ridimensionamento
def panel_widths(app):
    return {t.visible_width(line) for line in app.lines if t.strip_ansi(line).startswith("╭─ ")}


def test_tables_redraw_wider_when_the_terminal_grows_again():
    app = make_app()
    frame(app, cols=60, rows=40)
    type_line(app, "help")
    narrow = doc_text(app)
    assert "…" in narrow and "Elenco dei comandi" not in narrow     # tabella stretta: testo troncato
    frame(app, cols=130, rows=40)
    wide = doc_text(app)
    assert "Elenco dei comandi" in wide and "Rigioca un attacco simulato e mostra gli alert" in wide
    frame(app, cols=60, rows=40)
    assert "Elenco dei comandi" not in doc_text(app)                 # e si restringe di nuovo
    box = [t.strip_ansi(line) for line in app.lines if t.strip_ansi(line)[:1] in "╭│├╰"]
    assert box and all(t.visible_width(line) <= 60 for line in box)      # le tabelle si adattano


def test_alert_panels_follow_the_terminal_width():
    app = make_app()
    frame(app, cols=130, rows=40)
    type_line(app, f"replay revshell --fast --rules {REPO_RULES}")
    assert panel_widths(app) == {120}                                # massimo di lettura
    frame(app, cols=90, rows=40)
    assert panel_widths(app) == {90}
    frame(app, cols=110, rows=40)
    assert panel_widths(app) == {110}


def test_plain_text_lines_are_never_lost_when_shrinking():
    app = make_app()
    frame(app, cols=130, rows=40)
    type_line(app, "help")
    long_line = "In console scrivi i comandi senza 'erinix' davanti."
    frame(app, cols=60, rows=40)
    assert "In console scrivi i comandi" in doc_text(app)
    assert long_line in doc_text(app)                                # la riga intera resta nel documento


def test_broken_block_does_not_crash_the_console():
    app = make_app()

    def broken(width):
        raise ValueError("rotto")

    app.append_block(broken)
    assert "errore di visualizzazione (ValueError)" in doc_text(app)
    frame(app, cols=100, rows=30)
    type_line(app, "version")
    assert "erinix 0.1.0" in doc_text(app)


def test_block_output_is_sanitized():
    app = make_app()
    app.append_block(lambda w: "ok\x1b]52;c;ZXZpbA==\x07\x1b[2Jfine")
    out = frame(app)
    text = t.strip_ansi(out)
    assert "\x1b]" not in out and "\x1b[2J" not in out and "\x07" not in out
    assert "ok" in text and "fine" in text


def test_selection_is_cleared_when_resizing_with_blocks():
    app = make_app()
    frame(app, cols=130)
    type_line(app, "help")
    frame(app, cols=130)
    mouse(app, 0, 1, 2)
    mouse(app, 32, 6, 2)
    assert app.selection is not None
    frame(app, cols=100)
    assert app.selection is None
