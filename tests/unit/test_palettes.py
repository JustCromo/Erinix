import json
import re

import pytest

from erinix import palettes as P
from erinix.cli import main
from erinix.store import Store
from erinix.ui.theme import Theme

REQUIRED = {"bg_0", "bg_1", "aura_1", "aura_2", "aura_3", "text", "muted", "faint", "accent", "accent_2", "accent_ink", "moss", "bark",
            "low", "medium", "high", "critical", "glass_hi", "glass", "glass_soft", "edge", "hl", "shadow", "ink_soft"}
HEX = re.compile(r"^#[0-9a-f]{6}$")
COLOR = re.compile(r"^(#[0-9a-f]{6}|rgba\(\d{1,3},\d{1,3},\d{1,3},\.?\d+\))$")


@pytest.fixture(autouse=True)
def private_state(tmp_path, monkeypatch):
    monkeypatch.setattr("erinix.history._running_as_root", lambda: False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv("ERINIX_PALETTE", raising=False)


@pytest.mark.parametrize("name", list(P.PALETTES))
def test_every_palette_is_complete_and_made_of_plain_colours(name):
    p = P.PALETTES[name]
    assert set(p.colors) == REQUIRED and re.fullmatch(r"[a-z]+", p.name) and p.label and p.blurb
    assert all(COLOR.match(v) for v in p.colors.values()), {k: v for k, v in p.colors.items() if not COLOR.match(v)}


@pytest.mark.parametrize("name", list(P.PALETTES))
def test_every_palette_is_readable(name):
    c = P.PALETTES[name].colors
    for label, fg, bg, need in (("text on page", c["text"], c["bg_1"], 7), ("text on top", c["text"], c["bg_0"], 7),
                                ("secondary text", c["muted"], c["bg_1"], 4.5), ("faint text", c["faint"], c["bg_1"], 3.2),
                                ("button label", c["accent_ink"], c["accent"], 4.5), ("accent", c["accent"], c["bg_1"], 3),
                                ("section titles", c["bark"], c["bg_1"], 3)):
        assert P.contrast(fg, c_bg := bg) >= need, (name, label, round(P.contrast(fg, c_bg), 2))
    for sev in ("low", "medium", "high", "critical"):
        assert P.contrast(c[sev], c["bg_1"]) >= 3, (name, sev)


def test_severity_colours_stay_distinct_in_every_palette():
    for p in P.PALETTES.values():
        reds = {p.colors[s] for s in ("low", "medium", "high", "critical")}
        assert len(reds) == 4


def test_contrast_maths():
    assert P.contrast("#000000", "#ffffff") == pytest.approx(21.0)
    assert P.contrast("#777777", "#777777") == pytest.approx(1.0)


def test_css_covers_every_palette_and_is_inert():
    css = P.css()
    assert css.count(":root {") == 1 and all(f':root[data-palette="{n}"]' in css for n in P.PALETTES)
    assert css.count("--bg-0:") == len(P.PALETTES) + 1
    for banned in ("url(", "@import", "expression(", "javascript:", "<", "behavior"):
        assert banned not in css
    assert css.count("{") == css.count("}")


def test_the_default_exists_and_unknown_names_fall_back():
    assert P.DEFAULT in P.PALETTES and P.get("nope").name == P.DEFAULT and P.get(None).name == P.DEFAULT
    for junk in (None, 5, "", "../etc", 'cacao"; }', "CACAO", ["cacao"], "cacao\n", "cacao "):
        assert not P.is_known(junk)
    assert P.is_known("latte")


def test_picker_info():
    info = P.info()
    assert [i["name"] for i in info] == list(P.PALETTES) and all(len(i["swatch"]) == 4 and all(HEX.match(s) for s in i["swatch"]) for i in info)
    assert next(i for i in info if i["name"] == "latte")["dark"] is False


# ------------------------------------------------------------ stored choice
def test_stored_name(monkeypatch):
    assert P.stored_name() == P.DEFAULT                                         # no store yet
    with Store() as s:
        s.set_meta("palette", "nebbia")
    assert P.stored_name() == "nebbia"
    with Store() as s:
        s.set_meta("palette", "evil; }")
    assert P.stored_name() == P.DEFAULT
    monkeypatch.setenv("ERINIX_PALETTE", "prugna")
    assert P.stored_name() == "prugna"                                          # an environment override wins
    monkeypatch.setenv("ERINIX_PALETTE", "nonsense")
    assert P.stored_name() == P.DEFAULT


# ------------------------------------------------------------------ console
def test_console_roles_follow_the_palette():
    for name in P.PALETTES:
        roles = P.console_roles(name)
        assert set(roles) == {"accent", "brown", "border", "dim", "ok", "warn", "bad"}
        for rgb, idx, sgr in roles.values():
            assert all(0 <= v <= 255 for v in rgb) and 16 <= idx <= 231 and 30 <= sgr <= 97
    assert P.console_roles("nebbia")["accent"][0] == (0x7F, 0xD6, 0xC2)
    assert P.console_roles("latte") == P.console_roles("cacao")                 # the light palette borrows its dark sibling for the terminal


def test_theme_paints_with_the_chosen_palette():
    nebbia, plain = Theme(3, True, palette="nebbia"), Theme(3, True)
    assert "38;2;127;214;194" in nebbia.paint("x", "accent") and "38;2;226;122;63" in plain.paint("x", "accent")
    assert Theme(0, True, palette="nebbia").paint("x", "accent") == "x"          # no colour, no change
    assert "38;5;" in Theme(2, True, palette="prugna").paint("x", "accent")
    assert Theme.from_stream(palette="autunno")._roles == P.console_roles("autunno")


# ------------------------------------------------------------------ command
def run(capsys, *argv):
    code = main(["--no-color", *argv])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def test_palette_command_lists_and_marks_the_current_one(capsys):
    code, out, _ = run(capsys, "palette")
    assert code == 0 and all(n in out for n in P.PALETTES) and "…" not in out
    assert next(l for l in out.splitlines() if "cacao" in l).startswith("✔")
    data = json.loads(run(capsys, "palette", "--json")[1])
    assert data["current"] == "cacao" and len(data["palettes"]) == 7


def test_palette_command_sets_it_for_everyone(capsys):
    code, out, _ = run(capsys, "palette", "Nebbia")
    assert code == 0 and "Nebbia e sabbia" in out
    with Store(readonly=True) as s:
        assert s.get_meta("palette") == "nebbia"
    assert json.loads(run(capsys, "palette", "--json")[1])["current"] == "nebbia"


@pytest.mark.parametrize("bad", ["nope", "../etc/passwd", "cacao;rm", "\x1b[31mred", "a" * 500])
def test_palette_command_refuses_unknown_names_and_stores_nothing(capsys, bad):
    code, out, err = run(capsys, "palette", bad)
    assert code == 2 and "unknown palette" in err and "\x1b" not in err and len(err) < 300
    assert P.stored_name() == P.DEFAULT
