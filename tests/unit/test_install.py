import os
import subprocess

import pytest

from erinix import install as inst
from erinix.install import InstallError, install_app, uninstall_app

PY = "/home/u/.venv/bin/python"


def fake_which(*present):
    return lambda name: f"/usr/bin/{name}" if name in present else None


def run_install(home, **kw):
    calls = []
    kw.setdefault("which", fake_which("kitty", "update-desktop-database"))
    kw.setdefault("env", {"PATH": f"{home}/.local/bin:/usr/bin"})
    result = install_app(home, python=PY, run=lambda *a, **k: calls.append(a[0]), **kw)
    return result, calls


def test_installs_launcher_menu_entry_and_icons(tmp_path):
    result, calls = run_install(tmp_path)
    launcher = tmp_path / ".local/bin/erinix"
    desktop = (tmp_path / ".local/share/applications/erinix.desktop").read_text()
    assert os.access(launcher, os.X_OK) and oct(launcher.stat().st_mode & 0o777) == "0o755"
    assert f'exec "{PY}" -m erinix.cli "$@"' in launcher.read_text() and launcher.read_text().startswith("#!/bin/sh")
    assert f"Exec=kitty --class erinix --title Erinix {launcher}" in desktop and "Icon=erinix" in desktop and "Terminal=false" in desktop
    assert f"Exec={launcher} ui" in desktop and "Categories=System;Security;Monitor;" in desktop
    assert (tmp_path / ".local/share/icons/hicolor/scalable/apps/erinix.svg").read_text().startswith("<svg")
    assert (tmp_path / ".local/share/icons/hicolor/256x256/apps/erinix.png").read_bytes().startswith(b"\x89PNG")
    assert result.terminal == "kitty" and len(result.written) == 4 and result.notes == []
    assert calls == [["update-desktop-database", "-q", str(tmp_path / ".local/share/applications")]]


def test_the_launcher_really_runs_erinix(tmp_path):
    import sys

    install_app(tmp_path, python=sys.executable, which=fake_which(), env={"PATH": ""}, run=lambda *a, **k: None)
    out = subprocess.run([str(tmp_path / ".local/bin/erinix"), "--version"], capture_output=True, text=True, timeout=30)
    assert out.stdout.strip().startswith("erinix ")


def test_terminal_choice(tmp_path):
    env = {"PATH": "", "TERMINAL": "/usr/bin/foot"}
    result, _ = run_install(tmp_path, which=fake_which("kitty", "foot"), env=env)
    assert result.terminal == "foot"                                  # $TERMINAL wins
    result, _ = run_install(tmp_path, terminal="kitty", which=fake_which("kitty", "foot"), env=env)
    assert result.terminal == "kitty"                                 # explicit choice wins
    with pytest.raises(InstallError, match="not installed"):
        run_install(tmp_path, terminal="konsole", which=fake_which("kitty"))
    with pytest.raises(InstallError, match="unknown terminal"):
        run_install(tmp_path, terminal="evilterm; rm -rf ~")
    result, _ = run_install(tmp_path, which=fake_which(), env={"PATH": ""})
    assert result.terminal is None and "Terminal=true" in (tmp_path / ".local/share/applications/erinix.desktop").read_text()
    assert any("default" in n or "No known terminal" in n for n in result.notes)


def test_warns_when_local_bin_is_not_in_path(tmp_path):
    result, _ = run_install(tmp_path, env={"PATH": "/usr/bin"})
    assert any("PATH" in n for n in result.notes)


def test_never_overwrites_files_that_are_not_ours_without_force(tmp_path):
    launcher = tmp_path / ".local/bin/erinix"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/bin/sh\necho my own script\n")
    with pytest.raises(InstallError, match="not made by Erinix"):
        run_install(tmp_path)
    assert launcher.read_text().endswith("my own script\n")
    run_install(tmp_path, force=True)
    assert inst.MARKER in launcher.read_text()
    run_install(tmp_path)                                             # our own file: replaced without force


def test_symlinks_at_the_target_are_refused(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("precious")
    launcher = tmp_path / ".local/bin/erinix"
    launcher.parent.mkdir(parents=True)
    launcher.symlink_to(victim)
    with pytest.raises(InstallError, match="symlink"):
        run_install(tmp_path, force=True)
    assert victim.read_text() == "precious"


@pytest.mark.parametrize("bad", ['/home/u/my env/bin/python', "/home/u/$(id)/python", "/home/u/py\nExec=evil", '/home/u/"x"/python', "/home/u/;rm/python", ""])
def test_unsafe_paths_are_rejected(tmp_path, bad):
    with pytest.raises(InstallError, match="not safe|characters"):
        install_app(tmp_path, python=bad, which=fake_which(), env={"PATH": ""}, run=lambda *a, **k: None)
    assert not (tmp_path / ".local/share/applications/erinix.desktop").exists()


def test_uninstall_removes_only_what_erinix_made(tmp_path):
    run_install(tmp_path)
    foreign = tmp_path / ".local/share/icons/hicolor/256x256/apps/other.png"
    foreign.write_bytes(b"x")
    removed = uninstall_app(tmp_path)
    assert len(removed) == 4 and foreign.exists() and not (tmp_path / ".local/bin/erinix").exists()
    assert uninstall_app(tmp_path) == []
    launcher = tmp_path / ".local/bin/erinix"
    launcher.write_text("not ours")
    assert uninstall_app(tmp_path) == [] and launcher.exists()


def test_update_tools_failures_do_not_break_install(tmp_path):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("x", 1)

    result = install_app(tmp_path, python=PY, which=fake_which("kitty", "update-desktop-database"), env={"PATH": ""}, run=boom)
    assert len(result.written) == 4
