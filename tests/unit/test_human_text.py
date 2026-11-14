"""Plain-language texts on rules: validation, delivery to alerts, and the shipped rules' quality."""

from pathlib import Path

import pytest

from erinix.engine import Correlator
from erinix.rules import load_rules
from erinix.demo.scenarios import SCENARIOS

RULES = Path(__file__).resolve().parents[2] / "rules"


def write(tmp_path, body):
    f = tmp_path / "r.toml"
    f.write_text("schema = 1\n" + body, encoding="utf-8")
    f.chmod(0o600)
    return load_rules(f)


IND = '[[indicator]]\nid = "t"\nevent = "web.request"\nseverity = "low"\n{extra}\n[indicator.match]\ncontains = ["union select"]\n'


def test_valid_texts_load(tmp_path):
    rs = write(tmp_path, IND.format(extra='title = "Hello {remote}"\nwhy = "Because."\nnext = ["One", "Two {remote}"]'))
    ind = rs.indicators[0]
    assert rs.problems == () and ind.title == "Hello {remote}" and ind.why == "Because." and ind.next_steps == ("One", "Two {remote}")


@pytest.mark.parametrize("extra,fragment", [
    ('title = "Bad {user}"', "placeholder"), ('why = "x {0} y"', "placeholder"), ('title = "}"', "placeholder"),
    ('title = ""', "non-empty"), ('title = 5', "non-empty"), ('title = "' + "a" * 121 + '"', "too long"),
    ('why = "' + "a" * 401 + '"', "too long"), ('title = "line\\nbreak"', "control characters"),
    ('next = "one string"', "list of 1-6"), ('next = []', "list of 1-6"), ('next = ["a", "b", "c", "d", "e", "f", "g"]', "list of 1-6"),
    ('next = [5]', "non-empty"), ('next = ["' + "a" * 201 + '"]', "too long"), ('next = ["{x}"]', "placeholder"),
])
def test_bad_texts_discard_the_rule(tmp_path, extra, fragment):
    rs = write(tmp_path, IND.format(extra=extra))
    assert not rs.indicators and len(rs.problems) == 1 and fragment in rs.problems[0].message


def test_chains_take_the_same_fields(tmp_path):
    chain = '''[[chain]]
id = "c"
window_seconds = 60
link = "remote_ip"
title = "Chain for {remote}"
why = "Why."
next = ["Do it"]
[[chain.step]]
id = "a"
event = "web.request"
severity = "low"
[chain.step.match]
status = [404]
[[chain.step]]
id = "b"
event = "web.request"
severity = "high"
[chain.step.match]
status = [200]
'''
    rs = write(tmp_path, chain)
    assert rs.problems == () and rs.chains[0].title == "Chain for {remote}" and rs.chains[0].next_steps == ("Do it",)


def test_alerts_carry_the_texts():
    rs = load_rules(RULES)
    c = Correlator(rs)
    alerts = [a for e in sorted(SCENARIOS["web"].build(), key=lambda e: e.mono_ns) for a in c.process(e)]
    assert alerts and all(a.title and a.why and a.next_steps for a in alerts)
    assert any("{remote}" in a.title for a in alerts)


def test_every_shipped_rule_explains_itself_in_plain_language():
    rs = load_rules(RULES)
    for rule in (*rs.chains, *rs.indicators):
        assert 20 <= len(rule.title) <= 120 and len(rule.why) >= 40 and 2 <= len(rule.next_steps) <= 6, rule.id
        jargon = ("T1", "regex", "pid", "uid", "euid", "syscall", "TOML")
        assert not any(j in rule.title + rule.why for j in jargon), rule.id        # no technical terms in the headline text
        assert rule.title[0].isupper() and not rule.title.endswith("."), rule.id


def test_overload_alert_is_readable_too():
    from erinix.engine.correlator import Correlator as C
    rs = load_rules(RULES)
    c = C(rs, max_per_rule=1)
    out = []
    from erinix.core.events import AuthInfo, Event, EventType, Source
    for i, ip in enumerate(("10.0.0.1", "10.0.0.2", "10.0.0.3")):
        event = Event(EventType.AUTH_FAILURE, Source.LOG, payload=AuthInfo.build(service="sshd", user="root", remote_addr=ip),
                      mono_ns=i * 1_000_000_000)
        out += c.process(event)
    overload = [a for a in out if a.kind == "engine"]
    assert overload and overload[0].title and overload[0].why and overload[0].next_steps


# ------------------------------------------------------------ step labels
STEP = '''[[chain]]
id = "c"
window_seconds = 60
link = "remote_ip"
[[chain.step]]
id = "a"
{label}event = "web.request"
severity = "low"
[chain.step.match]
status = [404]
[[chain.step]]
id = "b"
event = "web.request"
severity = "high"
[chain.step.match]
status = [200]
'''


def test_step_labels_load(tmp_path):
    rs = write(tmp_path, STEP.format(label='label = "Looking around"\n'))
    assert rs.problems == () and [s.label for s in rs.chains[0].steps] == ["Looking around", ""]


@pytest.mark.parametrize("label,fragment", [("{x}", "placeholder"), ("", "non-empty"), ("a" * 101, "too long"), ("line\\nbreak", "control characters")])
def test_bad_step_labels_discard_the_rule(tmp_path, label, fragment):
    rs = write(tmp_path, STEP.format(label=f'label = "{label}"\n'))
    assert not rs.chains and fragment in rs.problems[0].message


def test_a_label_must_be_a_string(tmp_path):
    rs = write(tmp_path, STEP.format(label="label = 5\n"))
    assert not rs.chains and len(rs.problems) == 1


def test_every_step_of_every_shipped_chain_has_a_plain_label():
    for chain in load_rules(RULES).chains:
        for step in chain.steps:
            assert 8 <= len(step.label) <= 60 and step.label[0].isupper() and not step.label.endswith("."), (chain.id, step.id)
            assert not any(j in step.label for j in ("T1", "pid", "uid", "syscall", "regex")), (chain.id, step.id)


# ------------------------------------------------------------- tag and area
@pytest.mark.parametrize("extra,ok", [('tag = "SQL injection"\narea = "website"', True), ('area = "logins"', True), ('area = "this machine"', True),
                                      ('tag = ""', False), ('tag = 5', False), ('tag = "' + "a" * 33 + '"', False), ('tag = "line\\nbreak"', False),
                                      ('area = "everywhere"', False), ('area = "Website"', False), ('area = ""', False), ('area = 3', False)])
def test_tag_and_area_validation(tmp_path, extra, ok):
    rs = write(tmp_path, IND.format(extra=extra))
    assert bool(rs.indicators) == ok and (rs.problems == () if ok else len(rs.problems) == 1)


def test_chains_take_tag_and_area_too(tmp_path):
    body = STEP.format(label="").replace('link = "remote_ip"\n', 'link = "remote_ip"\ntag = "Scanning"\narea = "website"\n')
    rs = write(tmp_path, body)
    assert rs.problems == () and rs.chains[0].tag == "Scanning" and rs.chains[0].area == "website"


def test_every_shipped_rule_has_a_tag_and_an_area():
    rs = load_rules(RULES)
    for rule in (*rs.chains, *rs.indicators):
        assert 3 <= len(rule.tag) <= 32 and rule.tag[0].isupper() and rule.area in ("website", "logins", "this machine"), rule.id
    assert len({r.tag for r in (*rs.chains, *rs.indicators)}) >= 8
