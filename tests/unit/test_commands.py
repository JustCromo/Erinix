import os
import stat

import pytest

from erinix.cli import main
from erinix.commands.builtin import build_registry
from erinix.commands.registry import Context, UsageError, parse_args
from erinix.console import Console, history_path, load_history, save_history
from erinix.demo.scenarios import SCENARIOS
from pathlib import Path

REPO_RULES = str(Path(__file__).resolve().parents[2] / "rules")


def run(capsys, *argv):
    code = main(["--no-color", *argv])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_help_lists_commands(capsys):
    code, out, _ = run(capsys, "help")
    assert code == 0
    for word in ("doctor", "rules validate", "rules list", "replay", "In arrivo"):
        assert word in out


def test_bare_erinix_without_tty_prints_help(capsys):
    code = main([])
    out = capsys.readouterr().out
    assert code == 0 and "Comando" in out


def test_version(capsys):
    assert run(capsys, "--version")[:2] == (0, "erinix 0.1.0\n")
    assert run(capsys, "version")[:2] == (0, "erinix 0.1.0\n")


def test_unknown_command_suggests(capsys):
    code, _, err = run(capsys, "doctr")
    assert code == 2 and "Intendevi 'doctor'" in err


def test_group_without_subcommand(capsys):
    code, _, err = run(capsys, "rules")
    assert code == 2 and "validate" in err and "list" in err


def test_usage_errors(capsys):
    assert run(capsys, "rules", "list", "a", "b")[0] == 2
    assert run(capsys, "replay", "--boh")[0] == 2
    assert run(capsys, "replay", "--rules")[0] == 2
    assert run(capsys, "replay", "inventato", "--rules", REPO_RULES)[0] == 2


def test_parse_args():
    pos, flags, opts = parse_args(["x", "--fast", "--rules", "p"], flags=("--fast",), options=("--rules",))
    assert (pos, flags, opts) == (["x"], {"--fast"}, {"--rules": "p"})
    with pytest.raises(UsageError):
        parse_args(["--rules"], options=("--rules",))


def test_rules_list(capsys):
    code, out, _ = run(capsys, "rules", "list", REPO_RULES)
    assert code == 0 and "web-rce-revshell" in out and "catena" in out and "0 problemi" in out


def test_doctor(capsys):
    code, out, _ = run(capsys, "doctor", "--rules", REPO_RULES)
    assert code == 0 and "Sensore in uso ora" in out and "Privilegi" in out


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_replay_scenarios_behave_as_expected(capsys, name):
    code, out, _ = run(capsys, "replay", name, "--fast", "--rules", REPO_RULES)
    assert code == 0, out
    if SCENARIOS[name].expect_alerts:
        assert "CRITICAL" in out or "HIGH" in out
    else:
        assert "Nessun alert" in out


def test_replay_revshell_shows_progression(capsys):
    _, out, _ = run(capsys, "replay", "revshell", "--fast", "--rules", REPO_RULES)
    assert out.index("MEDIUM") < out.index("HIGH") < out.index("CRITICAL")
    assert "(completa)" in out and "10.0.0.5" in out


def test_replay_missing_rules(capsys, tmp_path):
    assert run(capsys, "replay", "--rules", str(tmp_path / "nope"))[0] == 2


def test_complete():
    reg = build_registry()
    assert "doctor" in reg.complete("") and "exit" in reg.complete("")
    assert reg.complete("rules ") == ["list", "validate"]
    assert "revshell" in reg.complete("replay ")


def make_console(lines):
    feed = iter(lines)

    def fake_input(prompt):
        try:
            return next(feed)
        except StopIteration:
            raise EOFError

    return Console(build_registry(), Context.from_env(False), input_fn=fake_input)


def test_console_loop(capsys):
    assert make_console(["help", "doctr", "", "rules", "version", "exit", "help"]).run() == 0
    out, err = capsys.readouterr().out, capsys.readouterr().err
    assert "E R I N I X" in out and "erinix 0.1.0" in out


def test_console_reports_errors_and_survives(capsys):
    make_console(["doctr", "echo 'aperta", "x" * 5000, "rules", "exit"]).run()
    err = capsys.readouterr().err
    assert "comando sconosciuto" in err and "sintassi non valida" in err and "troppo lunga" in err


def test_console_ctrl_d_exits(capsys):
    assert make_console([]).run() == 0


class FakeReadline:
    def __init__(self):
        self.loaded, self.saved = [], []

    def read_history_file(self, path):
        self.loaded.append(path)

    def write_history_file(self, path):
        self.saved.append(path)


def test_history_is_private_and_untrusted_files_are_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    path = history_path()
    rl = FakeReadline()
    save_history(rl, path)
    assert rl.saved and stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    load_history(rl, path)
    assert rl.loaded
    rl2 = FakeReadline()
    path.chmod(0o644)                      # accessibile ad altri: non ci si fida
    load_history(rl2, path)
    assert rl2.loaded == []


def test_history_refuses_symlink(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    path = history_path()
    path.parent.mkdir(parents=True)
    target = tmp_path / "bersaglio"
    target.write_text("non toccare")
    path.symlink_to(target)
    save_history(FakeReadline(), path)
    assert target.read_text() == "non toccare"


def test_default_rules_path_falls_back_to_the_checkout(capsys, monkeypatch):
    from erinix.commands import builtin

    monkeypatch.setattr(builtin, "DEFAULT_RULES_DIR", "/nonexistent/erinix/rules")
    code, out, _ = run(capsys, "rules", "list")
    assert code == 0 and "web-rce-revshell" in out and "regole" in out
    code, out, _ = run(capsys, "rules", "validate")
    assert code == 0 and "0 problemi" in out
    assert run(capsys, "replay", "admin", "--fast")[0] == 0


def test_explicit_missing_rules_path_still_fails(capsys, tmp_path):
    code, _, err = run(capsys, "rules", "list", str(tmp_path / "nope"))
    assert code == 2 and "nope" in err


def test_context_emit_without_emitter_uses_theme_width(capsys):
    from erinix.commands.registry import Context

    ctx = Context.from_env(False)
    ctx.emit(lambda width: f"larghezza={width}")
    assert f"larghezza={ctx.theme.width}" in capsys.readouterr().out
    seen = []
    ctx.emitter = seen.append
    ctx.emit(lambda width: "x")
    assert len(seen) == 1 and capsys.readouterr().out == ""
