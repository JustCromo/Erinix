import ipaddress
from pathlib import Path

import pytest

from erinix.core.events import (
    AuthInfo, Event, EventType, FileInfo, NetInfo, PrivInfo, ProcessInfo, SensorInfo, Source, Text,
)
from erinix.engine import Correlator
from erinix.engine.matching import matches
from erinix.core.process_tree import ProcessTree
from erinix.rules import Response, Severity, load_rules

REPO_RULES = Path(__file__).resolve().parents[2] / "rules"
SEC = 1_000_000_000
BF = "ssh-bruteforce-success"
REVSHELL = "web-rce-revshell"


@pytest.fixture(scope="module")
def rules():
    rs = load_rules(REPO_RULES)
    assert rs.problems == ()
    return rs


def proc(pid, start, ppid=None, pstart=None, exe="/usr/bin/bash", loginuid=None, uid=33, argv=None):
    return ProcessInfo.build(pid=pid, start_ns=start, uid=uid, euid=uid, exe=exe,
                             argv=argv or [exe or ""], comm=(exe or "").rsplit("/", 1)[-1], ppid=ppid,
                             parent_start_ns=pstart, loginuid=loginuid)


def t(sec):
    return int(sec * SEC)


def exec_ev(p, sec):
    return Event(EventType.PROCESS_EXEC, Source.EBPF, process=p, mono_ns=t(sec))


def connect_ev(p, ip, port, sec):
    pl = NetInfo.build(protocol="tcp", remote_addr=ip, remote_port=port)
    return Event(EventType.NET_CONNECT, Source.EBPF, process=p, payload=pl, mono_ns=t(sec))


def root_ev(p, sec):
    return Event(EventType.PRIV_UID_CHANGE, Source.EBPF, process=p,
                 payload=PrivInfo(33, 0, 33, 0, Text("setuid")), mono_ns=t(sec))


def auth_ev(kind, ip, sec, service="sshd"):
    return Event(kind, Source.AUDITD, payload=AuthInfo.build(service=service, user="root", remote_addr=ip),
                 mono_ns=t(sec))


def shadow_ev(p, sec, op="write"):
    return Event(EventType.FILE_ACCESS, Source.EBPF, process=p,
                 payload=FileInfo.build(path="/etc/shadow", operation=op), mono_ns=t(sec))


APACHE = proc(500, 10, 1, 0, "/usr/sbin/apache2")
SHELL = proc(900, 20, 500, 10)


# ------------------------------------------------------------ revshell chain
def test_revshell_progressive_single_alert(rules):
    c = Correlator(rules)
    assert c.process(exec_ev(APACHE, 1)) == []

    (a1,) = c.process(exec_ev(SHELL, 2))
    assert (a1.rule_id, a1.revision, a1.steps_done, a1.steps_total) == (REVSHELL, 1, 1, 3)
    assert a1.severity is Severity.MEDIUM and a1.response is Response.INTERACTIVE
    assert not a1.complete and a1.anchor == SHELL.key

    (a2,) = c.process(connect_ev(SHELL, "10.0.0.5", 4444, 3))
    assert a2.alert_id == a1.alert_id and a2.revision == 2        # same alert, updated
    assert a2.severity is Severity.HIGH and a2.response is Response.AUTO
    assert a2.remote_addr == ipaddress.ip_address("10.0.0.5")

    (a3,) = c.process(root_ev(SHELL, 4))
    assert a3.alert_id == a1.alert_id and a3.complete and a3.steps_done == 3
    assert a3.severity is Severity.CRITICAL and len(a3.evidence) == 3
    assert a3.remote_addr == ipaddress.ip_address("10.0.0.5")      # remembered from the previous step


def test_descendant_process_counts_for_the_chain(rules):
    c = Correlator(rules)
    c.process(exec_ev(APACHE, 1))
    c.process(exec_ev(SHELL, 2))
    nc = proc(950, 30, 900, 20, "/usr/bin/nc")
    (a,) = c.process(connect_ev(nc, "10.0.0.5", 4444, 3))
    assert a.steps_done == 2


def test_pid_reuse_does_not_join_chain(rules):
    c = Correlator(rules)
    c.process(exec_ev(APACHE, 1))
    c.process(exec_ev(SHELL, 2))
    other = proc(900, 999, 1, 0)                 # same PID, different start time
    assert c.process(connect_ev(other, "10.0.0.5", 4444, 3)) == []


def test_service_alone_or_admin_session_is_quiet(rules):
    c = Correlator(rules)
    c.process(exec_ev(APACHE, 1))
    assert c.process(connect_ev(APACHE, "93.184.216.34", 443, 2)) == []   # the web server connecting out: normal
    sshd = proc(700, 5, 1, 0, "/usr/sbin/sshd", uid=0)
    admin = proc(1200, 50, 700, 5, loginuid=1000, uid=1000)
    c.process(exec_ev(sshd, 3))
    assert c.process(exec_ev(admin, 4)) == []
    assert c.process(connect_ev(admin, "93.184.216.34", 443, 5)) == []
    assert c.process(root_ev(admin, 6)) == []


def test_chain_expires_then_restarts(rules):
    c = Correlator(rules)
    c.process(exec_ev(APACHE, 1))
    (first,) = c.process(exec_ev(SHELL, 2))
    assert c.process(connect_ev(SHELL, "10.0.0.5", 4444, 2 + 601)) == []     # beyond the window
    new_shell = proc(1500, 700, 500, 10)
    (again,) = c.process(exec_ev(new_shell, 700))
    assert again.revision == 1 and again.alert_id != first.alert_id


# --------------------------------------------------------------- brute force
def fails(c, ip, times):
    out = []
    for sec in times:
        out += c.process(auth_ev(EventType.AUTH_FAILURE, ip, sec))
    return out


def test_bruteforce_then_success(rules):
    c = Correlator(rules)
    ip = "203.0.113.7"
    assert fails(c, ip, [0, 1, 2, 3]) == []
    (a1,) = fails(c, ip, [4])
    assert a1.steps_done == 1 and a1.severity is Severity.MEDIUM and a1.remote_addr == ipaddress.ip_address(ip)
    (a2,) = c.process(auth_ev(EventType.AUTH_SUCCESS, ip, 10))
    assert a2.alert_id == a1.alert_id and a2.complete and a2.severity is Severity.CRITICAL


def test_success_without_failures_is_quiet(rules):
    assert Correlator(rules).process(auth_ev(EventType.AUTH_SUCCESS, "203.0.113.7", 1)) == []


def test_sliding_window_slow_attacker_not_counted(rules):
    c = Correlator(rules)
    assert fails(c, "203.0.113.7", [0, 100, 200, 300, 400, 500, 600]) == []   # at most 4 inside the window


def test_sliding_window_counts_burst_after_old_events(rules):
    c = Correlator(rules)
    fails(c, "203.0.113.7", [0, 1])
    assert len(fails(c, "203.0.113.7", [200, 201, 202])) == 1                  # 5 within 300 s


def test_failures_from_different_ips_do_not_mix(rules):
    c = Correlator(rules)
    assert fails(c, "203.0.113.7", [0, 1, 2]) == [] and fails(c, "203.0.113.8", [3, 4, 5]) == []


# --------------------------------------------------------------- indicator
def test_indicator_fires_once_per_process(rules):
    c = Correlator(rules)
    vim = proc(2000, 5, exe="/usr/bin/vim")
    (a,) = c.process(shadow_ev(vim, 1))
    assert a.kind == "indicator" and a.severity is Severity.HIGH and a.complete
    assert c.process(shadow_ev(vim, 2)) == [] and c.stats.suppressed_duplicates == 1   # counted


def test_indicator_ignores_standard_tools_and_reads(rules):
    c = Correlator(rules)
    assert c.process(shadow_ev(proc(2001, 5, exe="/usr/bin/passwd"), 1)) == []
    assert c.process(shadow_ev(proc(2002, 5, exe="/usr/bin/vim"), 2, op="read")) == []
    assert c.process(shadow_ev(proc(2003, 5, exe=None), 3)) == []   # unknown exe: not "unexpected"


# ------------------------------------------------------------------- flood
def test_flood_is_bounded_declared_and_never_evicts_advanced(rules):
    c = Correlator(rules, max_per_rule=50)
    victim = "198.51.100.1"
    assert len(fails(c, victim, [0, 1, 2, 3, 4])) == 1                 # chain already advanced
    alerts = []
    base = int(ipaddress.ip_address("192.0.2.0"))
    for i in range(500):
        ip = str(ipaddress.ip_address(base + i % 250 + 1)) if i < 250 else f"100.64.{i // 250}.{i % 250 + 1}"
        alerts += c.process(Event(EventType.AUTH_FAILURE, Source.AUDITD,
                                  payload=AuthInfo.build(service="sshd", user="x", remote_addr=ip),
                                  mono_ns=5 * SEC + i * 1_000_000))
    assert c._count[BF] <= 50
    assert c.stats.evicted_instances > 0
    overload = [a for a in alerts if a.kind == "engine"]
    assert len(overload) == 1 and overload[0].severity is Severity.CRITICAL    # declared, once
    (done,) = c.process(auth_ev(EventType.AUTH_SUCCESS, victim, 10))
    assert done.complete                                                         # the chain survived


def test_flood_with_only_advanced_instances_refuses_and_counts(rules):
    c = Correlator(rules, max_per_rule=2)
    for i, ip in enumerate(["198.51.100.1", "198.51.100.2"]):
        assert len(fails(c, ip, [i * 10 + k for k in range(5)])) == 1
    out = fails(c, "198.51.100.3", [30])
    assert c.stats.refused_instances == 1 and len(out) == 1 and out[0].kind == "engine"
    assert c._count[BF] == 2


# ------------------------------------------------------------------ misc
def test_sensor_and_exit_events_do_not_crash(rules):
    c = Correlator(rules)
    s = Event(EventType.SENSOR_STARTED, Source.EBPF, payload=SensorInfo.build(mode=Source.EBPF), mono_ns=t(1))
    assert c.process(s) == []
    c.process(exec_ev(SHELL, 2))
    assert c.process(Event(EventType.PROCESS_EXIT, Source.EBPF, process=SHELL, mono_ns=t(3))) == []
    assert not c.tree.is_alive(SHELL.key)


def test_stale_instances_are_swept(rules):
    c = Correlator(rules)
    fails(c, "203.0.113.7", [0])
    assert c.open_instances == 1
    c.process(auth_ev(EventType.AUTH_FAILURE, "203.0.113.9", 1000))    # much later: sweep
    assert c.open_instances == 1                                       # only the last one remains


# --------------------------------------------------------------- matching
def test_matching_parent_ancestor_argv_prefix():
    tree = ProcessTree()
    tree.on_exec(APACHE)
    tree.on_exec(SHELL)
    cmd = proc(950, 30, 900, 20, "/usr/bin/find", argv=["find", "/", "-perm", "-4000"])
    tree.on_exec(cmd)
    ev = exec_ev(cmd, 1)
    assert matches({"parent_exe": ("/usr/bin/bash",)}, ev, tree)
    assert matches({"ancestor_exe": ("/usr/sbin/apache2",)}, ev, tree)
    assert not matches({"parent_exe": ("/usr/sbin/apache2",)}, ev, tree)
    assert matches({"argv_has": ("-perm",), "exe_prefix": ("/usr/bin/",)}, ev, tree)
    assert not matches({"argv_has": ("-perm",), "exe": ("/bin/ls",)}, ev, tree)   # all conditions must hold
    assert not matches({"made_up_field": True}, ev, tree)                       # fails closed
