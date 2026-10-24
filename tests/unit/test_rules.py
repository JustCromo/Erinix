import os
from pathlib import Path

import pytest

from erinix.cli import main
from erinix.core.events import EventType
from erinix.rules import Link, Response, RuleError, Severity, load_rules

REPO_RULES = Path(__file__).resolve().parents[2] / "rules"

GOOD_CHAIN = """
schema = 1
[[chain]]
id = "c1"
window_seconds = 60
link = "process_tree"
response = "interactive"
[[chain.step]]
id = "s1"
event = "process.exec"
severity = "low"
[chain.step.match]
exe = ["/usr/bin/bash"]
[[chain.step]]
id = "s2"
event = "net.connect"
severity = "high"
[chain.step.match]
remote_external = true
"""


def write(tmp_path, text, name="r.toml", mode=0o600):
    f = tmp_path / name
    f.write_text(text, encoding="utf-8")
    f.chmod(mode)
    return f


def only_problem(tmp_path, text):
    rs = load_rules(write(tmp_path, text))
    assert not rs.chains and not rs.indicators
    assert len(rs.problems) == 1
    return rs.problems[0].message


def test_shipped_rules_are_valid():
    rs = load_rules(REPO_RULES)
    assert rs.problems == ()
    ids = {c.id for c in rs.chains} | {i.id for i in rs.indicators}
    assert {"web-rce-revshell", "ssh-bruteforce-success", "shadow-written-by-unexpected-process"} <= ids


def test_valid_chain_parsed(tmp_path):
    rs = load_rules(write(tmp_path, GOOD_CHAIN))
    assert rs.problems == ()
    c = rs.chains[0]
    assert c.link is Link.PROCESS_TREE and c.response is Response.INTERACTIVE
    assert c.steps[0].event is EventType.PROCESS_EXEC and c.steps[1].severity is Severity.HIGH
    assert c.steps[0].match["exe"] == ("/usr/bin/bash",)


def test_response_defaults_to_report_only(tmp_path):
    rs = load_rules(write(tmp_path, GOOD_CHAIN.replace('response = "interactive"\n', "")))
    assert rs.chains[0].response is Response.REPORT_ONLY


def test_unknown_match_field_rejected_regex_impossible(tmp_path):
    bad = GOOD_CHAIN.replace('exe = ["/usr/bin/bash"]', 'exe_regex = [".*"]')
    assert "not allowed" in only_problem(tmp_path, bad)


def test_unknown_rule_key_rejected(tmp_path):
    bad = GOOD_CHAIN.replace('link = "process_tree"', 'link = "process_tree"\nrun = "rm -rf /"')
    assert "fields not allowed" in only_problem(tmp_path, bad)


def test_auto_requires_justification(tmp_path):
    bad = GOOD_CHAIN.replace('severity = "high"', 'severity = "high"\nresponse = "auto"')
    assert "justification" in only_problem(tmp_path, bad)
    ok = bad.replace('response = "interactive"', 'response = "interactive"\njustification = "certain"')
    assert load_rules(write(tmp_path, ok, "ok.toml")).problems == ()


def test_chain_needs_two_steps(tmp_path):
    one = GOOD_CHAIN.split("[[chain.step]]")
    assert "indicator" in only_problem(tmp_path, "[[chain.step]]".join(one[:2]))


def test_event_not_usable_in_rules(tmp_path):
    bad = GOOD_CHAIN.replace('event = "net.connect"', 'event = "sensor.started"')
    assert "cannot be used" in only_problem(tmp_path, bad)


def test_link_remote_ip_needs_remote_events(tmp_path):
    bad = GOOD_CHAIN.replace("process_tree", "remote_ip")
    assert "remote_ip" in only_problem(tmp_path, bad)


def test_window_and_count_bounds_and_bool_is_not_int(tmp_path):
    assert "window_seconds" in only_problem(tmp_path, GOOD_CHAIN.replace("window_seconds = 60", "window_seconds = 0"))
    assert "window_seconds" in only_problem(tmp_path, GOOD_CHAIN.replace("window_seconds = 60", "window_seconds = true"))
    assert "count" in only_problem(tmp_path, GOOD_CHAIN.replace('severity = "low"', 'severity = "low"\ncount = true'))


def test_paths_must_be_absolute_and_printable(tmp_path):
    assert "absolute" in only_problem(tmp_path, GOOD_CHAIN.replace("/usr/bin/bash", "bash"))
    assert "control characters" in only_problem(tmp_path, GOOD_CHAIN.replace("/usr/bin/bash", "/usr/bin/ba\\nsh"))


def test_invalid_operation_and_port(tmp_path):
    ind = """
schema = 1
[[indicator]]
id = "i1"
event = "file.access"
severity = "high"
[indicator.match]
path = ["/etc/shadow"]
operation = ["rm -rf"]
"""
    assert "allowed operations" in only_problem(tmp_path, ind)
    port = GOOD_CHAIN.replace("remote_external = true", "remote_port = [70000]")
    assert "integers" in only_problem(tmp_path, port)


def test_indicator_ok(tmp_path):
    ind = """
schema = 1
[[indicator]]
id = "i1"
event = "priv.uid_change"
severity = "critical"
[indicator.match]
became_root = true
"""
    rs = load_rules(write(tmp_path, ind))
    assert rs.problems == () and rs.indicators[0].response is Response.REPORT_ONLY


def test_bad_rule_discarded_others_survive(tmp_path):
    second = GOOD_CHAIN.replace("schema = 1", "").replace('id = "c1"', 'id = "c2"')
    second = second.replace('exe = ["/usr/bin/bash"]', "bogus = 1")  # c2 is invalid
    rs = load_rules(write(tmp_path, GOOD_CHAIN + second))
    assert [c.id for c in rs.chains] == ["c1"]
    assert len(rs.problems) == 1 and rs.problems[0].rule_id == "c2"


def test_duplicate_id_discarded(tmp_path):
    rs = load_rules(write(tmp_path, GOOD_CHAIN + GOOD_CHAIN.replace("schema = 1", "")))
    assert len(rs.chains) == 1 and "duplicate" in rs.problems[0].message


def test_schema_required(tmp_path):
    assert "schema" in only_problem(tmp_path, GOOD_CHAIN.replace("schema = 1", "schema = 2"))


def test_invalid_toml_and_encoding(tmp_path):
    rs = load_rules(write(tmp_path, "this is = = not toml"))
    assert "TOML" in rs.problems[0].message
    f = tmp_path / "bin.toml"
    f.write_bytes(b"\xff\xfe\x00")
    f.chmod(0o600)
    assert "UTF-8" in load_rules(f).problems[0].message


def test_oversized_file_rejected(tmp_path):
    f = write(tmp_path, "# " + "a" * (1024 * 1024 + 10))
    assert "too large" in load_rules(f).problems[0].message


def test_world_writable_file_rejected(tmp_path):
    f = write(tmp_path, GOOD_CHAIN, mode=0o666)
    rs = load_rules(f)
    assert not rs.chains and "writable" in rs.problems[0].message


def test_symlink_rejected(tmp_path):
    real = write(tmp_path, GOOD_CHAIN, "real.toml")
    link = tmp_path / "link.toml"
    link.symlink_to(real)
    with pytest.raises(RuleError):
        load_rules(link)
    d = tmp_path / "d"
    d.mkdir()
    (d / "x.toml").symlink_to(real)
    assert load_rules(d).problems and not load_rules(d).chains


def test_world_writable_directory_rejected(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    write(d, GOOD_CHAIN)
    d.chmod(0o777)
    with pytest.raises(RuleError):
        load_rules(d)


def test_directory_loading_ignores_other_files(tmp_path):
    d = tmp_path / "rules"
    d.mkdir()
    write(d, GOOD_CHAIN, "a.toml")
    write(d, "garbage", "notes.txt")
    write(d, "garbage", ".hidden.toml")
    rs = load_rules(d)
    assert len(rs.chains) == 1 and rs.problems == ()


def test_cli_validate_ok_and_errors(tmp_path, capsys):
    assert main(["rules", "validate", str(REPO_RULES)]) == 0
    assert "0 problems" in capsys.readouterr().out
    bad = write(tmp_path, GOOD_CHAIN.replace("exe =", "nope ="))
    assert main(["rules", "validate", str(bad)]) == 1
    assert main(["rules", "validate", str(tmp_path / "missing")]) == 2


def test_cli_output_is_sanitized(tmp_path, capsys):
    d = tmp_path / "rules"
    d.mkdir()
    write(d, "not toml = =", "evil\x1b[31m.toml")  # hostile file name
    assert main(["rules", "validate", str(d)]) == 1
    out = capsys.readouterr().out
    assert "\x1b" not in out and "evil" in out
