import json
import re
from pathlib import Path

import pytest

from erinix import palettes as P
from erinix.cli import main
from erinix.store import Store
from erinix.ui.theme import Theme

SEVERITY = ("ok", "low", "medium", "high", "critical")
REQUIRED = {"bg", "card", "card_2", "text", "muted", "faint", "border", "primary", "on_primary", "accent", "medium_text", "shadow",
            *SEVERITY, *(f"on_{s}" for s in SEVERITY)}
HEX = re.compile(r"^#[0-9a-f]{6}$")
COLOR = re.compile(r"^(#[0-9a-f]{6}|rgba\(\d{1,3}, ?\d{1,3}, ?\d{1,3}, ?\.?\d+\))$")
STATIC = Path(P.__file__).parent / "web" / "static"


@pytest.fixture(autouse=True)
def private_state(tmp_path, monkeypatch):
    monkeypatch.setattr("erinix.history._running_as_root", lambda: False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("ERINIX_THEME", raising=False)


@pytest.mark.parametrize("variant", list(P.VARIANTS))
def test_every_variant_is_complete_and_made_of_plain_colours(variant):
    c = P.VARIANTS[variant]
    assert set(c) == REQUIRED
    assert all(COLOR.match(v) for v in c.values()), {k: v for k, v in c.items() if not COLOR.match(v)}


@pytest.mark.parametrize("variant", list(P.VARIANTS))
def test_every_variant_is_readable(variant):
    c = P.VARIANTS[variant]
    for surface in ("bg", "card", "card_2"):
        for label, fg, need in (("text", "text", 7), ("secondary text", "muted", 4.5), ("faint text", "faint", 4.5),
                                ("links and titles", "primary", 4.5)):
            assert P.contrast(c[fg], c[surface]) >= need, (variant, surface, label, round(P.contrast(c[fg], c[surface]), 2))
        for sev in ("ok", "low", "medium_text", "high", "critical"):                 # as text on a surface
            assert P.contrast(c[sev], c[surface]) >= 4, (variant, surface, sev, round(P.contrast(c[sev], c[surface]), 2))
    assert P.contrast(c["on_primary"], c["primary"]) >= 4.5                      # the label of a button
    for sev in SEVERITY:                                                         # solid badges: the label on its fill
        assert P.contrast(c[f"on_{sev}"], c[sev]) >= 4.5, (variant, sev, round(P.contrast(c[f"on_{sev}"], c[sev]), 2))
    assert P.contrast(c["border"], c["bg"]) >= 1.1                               # borders are thin but visible


@pytest.mark.parametrize("variant", list(P.VARIANTS))
def test_severity_colours_stay_distinct(variant):
    c = P.VARIANTS[variant]
    assert len({c[s] for s in SEVERITY}) == 5


@pytest.mark.parametrize("variant", list(P.VARIANTS))
def test_no_green_anywhere(variant):
    """Green belongs to Nemirix: no colour of the palette may be greenish."""
    import colorsys

    for name, value in P.VARIANTS[variant].items():
        if not value.startswith("#"):
            continue
        r, g, b = (int(value[i:i + 2], 16) / 255 for i in (1, 3, 5))
        hue, sat, _ = colorsys.rgb_to_hls(r, g, b)[0] * 360, colorsys.rgb_to_hls(r, g, b)[2], 0
        assert not (75 <= hue <= 170 and sat > 0.12), (variant, name, value, round(hue))


def test_contrast_maths():
    assert P.contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert P.contrast("#777777", "#777777") == pytest.approx(1.0)


def test_css_has_both_variants_and_the_system_decides_by_default():
    css = P.css()
    assert css.count(":root {") == 1 and ':root[data-theme="light"]' in css and ':root[data-theme="dark"]' in css
    assert "@media (prefers-color-scheme: dark)" in css and ':root:not([data-theme="light"])' in css
    assert css.count("--bg:") == 4 and "color-scheme: light dark" in css
    for banned in ("url(", "@import", "expression(", "javascript:", "<", "behavior"):
        assert banned not in css
    assert css.count("{") == css.count("}")


def test_the_style_is_flat_and_self_contained():
    """No liquid glass, no glow: solid cards with thin borders. And nothing is loaded from outside."""
    for name in ("style.css", "app.js", "index.html", "icons.svg"):
        text = (STATIC / name).read_text()
        for banned in ("backdrop-filter", "blur(", "text-shadow", "radial-gradient", "@import", "https://fonts", "//cdn"):
            assert banned not in text, (name, banned)
    css = (STATIC / "style.css").read_text()
    assert "glass" not in css and "neon" not in css and "drop-shadow" not in css
    assert 'font-family: "Nunito"' in css and (STATIC / "fonts" / "nunito-latin.woff2").read_bytes()[:4] == b"wOF2"
    assert (STATIC / "fonts" / "NUNITO-OFL.txt").exists()                                  # the font licence travels with the font


def test_the_default_exists_and_unknown_names_are_refused():
    assert P.DEFAULT in P.MODES and P.is_known("light") and P.is_known("dark") and P.is_known("auto")
    for junk in (None, 5, "", "../etc", 'dark"; }', "DARK", ["dark"], "dark\n", "dark ", "cacao"):
        assert not P.is_known(junk)


def test_picker_info():
    info = P.info()
    assert [i["name"] for i in info] == list(P.MODES) and all(len(i["swatch"]) == 4 and all(HEX.match(s) for s in i["swatch"]) for i in info)


# ------------------------------------------------------------ stored choice
def test_stored_name(monkeypatch):
    assert P.stored_name() == P.DEFAULT                                         # no store yet
    with Store() as s:
        s.set_meta("theme", "dark")
    assert P.stored_name() == "dark"
    with Store() as s:
        s.set_meta("theme", "evil; }")
    assert P.stored_name() == P.DEFAULT
    monkeypatch.setenv("ERINIX_THEME", "light")
    assert P.stored_name() == "light"                                           # an environment override wins
    monkeypatch.setenv("ERINIX_THEME", "nonsense")
    assert P.stored_name() == P.DEFAULT


# ------------------------------------------------------------------ console
def test_console_roles_come_from_the_dark_variant():
    roles = P.console_roles()
    assert set(roles) == {"accent", "brown", "border", "dim", "ok", "warn", "bad"}
    for rgb, idx, sgr in roles.values():
        assert all(0 <= v <= 255 for v in rgb) and 16 <= idx <= 231 and 30 <= sgr <= 97
    assert roles["accent"][0] == (0xB9, 0xB4, 0xFF)
    assert P.console_roles("light") == P.console_roles("dark")                  # terminals are dark: the setting does not change them


def test_theme_paints_with_the_stone_palette():
    stone, plain = Theme(3, True, palette="auto"), Theme(3, True)
    assert "38;2;185;180;255" in stone.paint("x", "accent") and "38;2;226;122;63" in plain.paint("x", "accent")
    assert Theme(0, True, palette="auto").paint("x", "accent") == "x"             # no colour, no change
    assert "38;5;" in Theme(2, True, palette="auto").paint("x", "accent")
    assert Theme.from_stream(palette="auto")._roles == P.console_roles()


# ------------------------------------------------------------------ command
def run(capsys, *argv):
    code = main(["--no-color", *argv])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_theme_command_lists_and_marks_the_current_one(capsys):
    code, out, _ = run(capsys, "theme")
    assert code == 0 and all(n in out for n in P.MODES) and "…" not in out
    assert next(l for l in out.splitlines() if "auto" in l).startswith("✔")
    data = json.loads(run(capsys, "theme", "--json")[1])
    assert data["current"] == "auto" and len(data["themes"]) == 3


def test_theme_command_sets_it_for_everyone(capsys):
    code, out, _ = run(capsys, "theme", "Dark")
    assert code == 0 and "dark" in out
    with Store(readonly=True) as s:
        assert s.get_meta("theme") == "dark"
    assert json.loads(run(capsys, "theme", "--json")[1])["current"] == "dark"


@pytest.mark.parametrize("bad", ["nope", "../etc/passwd", "dark;rm", "\x1b[31mred", "a" * 500, "cacao"])
def test_theme_command_refuses_unknown_names_and_stores_nothing(capsys, bad):
    code, out, err = run(capsys, "theme", bad)
    assert code == 2 and "unknown appearance" in err and "\x1b" not in err and len(err) < 300
    assert P.stored_name() == P.DEFAULT
