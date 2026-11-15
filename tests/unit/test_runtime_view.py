import io
import json
import os
import time

import pytest

from erinix import config as cfg
from erinix.engine import Correlator
from erinix.runtime import AgentLock, AgentRuntime
from erinix.rules import load_rules
from erinix.commands.builtin import default_rules_path
from erinix.sensors import procview
from erinix.sensors.netproc import Socket
from erinix.sensors.procfs import ProcRecord


def rec(pid=10, **kw):
    base = dict(pid=pid, ppid=1, start_ticks=5, uid=1000, euid=1000, comm="nc", exe="/usr/bin/nc", argv=("nc", "-l"))
    base.update(kw)
    return ProcRecord(**base)


SOCK = Socket("tcp", "0.0.0.0", 22, "0.0.0.0", 0, "0A", 0, 777)


def test_snapshot_roundtrip():
    line = procview.encode_snapshot({10: rec()}, [SOCK], {777: 10})
    procs, socks, owners = procview.decode_snapshot(line)
    assert procs[10].comm == "nc" and socks[0].lport == 22 and owners == {777: 10}


@pytest.mark.parametrize("mutate", [
    lambda d: d.update(procs=[[1, 1, 1, 1, 1, "x" * 999, "/x", []]]),          # comm too long
    lambda d: d.update(procs=[[True, 1, 1, 1, 1, "x", "/x", []]]),              # bool pid
    lambda d: d.update(procs=[[1, 1, 1, 1, 1, "x", "/x", ["a"] * 500]]),        # too many args
    lambda d: d.update(socks=[["tcp", "not-an-ip", 1, "0.0.0.0", 0, "0A", 0, 1]]),
    lambda d: d.update(socks=[["udp", "0.0.0.0", 1, "0.0.0.0", 0, "0A", 0, 1]]),
    lambda d: d.update(socks=[["tcp", "0.0.0.0", 70000, "0.0.0.0", 0, "0A", 0, 1]]),
    lambda d: d.update(owners={"abc": 1}),
    lambda d: d.update(owners={"1": -5}),
    lambda d: d.pop("procs"),
])
def test_hostile_snapshots_are_rejected(mutate):
    data = json.loads(procview.encode_snapshot({10: rec()}, [SOCK], {777: 10}))
    mutate(data)
    assert procview.decode_snapshot(json.dumps(data)) is None


@pytest.mark.parametrize("line", ["", "nope", "[]", "{}", '{"t":"snap"}', '{"t":"other"}'])
def test_garbage_lines_are_rejected(line):
    assert procview.decode_snapshot(line) is None


def test_remote_view_goes_stale_and_counts_bad_lines():
    now = [0.0]
    good = procview.encode_snapshot({10: rec()}, [SOCK], {})
    stream = io.StringIO('{"t":"hello","uid":0,"note":""}\n' + "garbage\n" + good + "\n")
    view = procview.RemoteView(stream, clock=lambda: now[0], stale_after=5).start()
    view._thread.join(2)
    assert view.privileged and view.bad_lines == 1 and 10 in view.scan()
    now[0] = 100.0
    assert view.scan() == {} and not view.alive


def test_remote_view_oversized_line_stops_the_reader():
    class Endless:
        def readline(self, n=-1):
            return "x" * n
    view = procview.RemoteView(Endless()).start()
    view._thread.join(2)
    assert view.closed and "oversized" in view.note


def test_helper_emits_hello_then_snapshots(tmp_path):
    out = io.StringIO()
    r, w = os.pipe()                                  # an open pipe: the "parent" has not gone away
    stdin = os.fdopen(r)
    procview.helper_main(out, interval=0.0, stop=iter([False, False, True]).__next__, sleep=lambda s: None, stdin=stdin)
    os.close(w)                                       # the reader thread sees EOF; only then can we close our end
    time.sleep(0.1)
    stdin.close()
    lines = out.getvalue().splitlines()
    assert json.loads(lines[0])["t"] == "hello" and json.loads(lines[0])["uid"] == os.geteuid()
    snaps = [l for l in lines[1:] if l.startswith('{"t":"snap"')]
    assert snaps and all(procview.decode_snapshot(l) is not None for l in snaps)
    assert any(l.startswith('{"t":"assess"') and procview.decode_assessment(l) for l in lines)


class FakeHelper:
    def __init__(self, view, ok=True):
        self.view, self.ok, self.error, self.stopped = view, ok, "no sudo", False

    def start(self):
        return self.ok

    def stop(self):
        self.stopped = True


def test_elevated_helper_refuses_a_non_root_peer():
    class P:
        stdin = io.StringIO()
        stdout = io.StringIO('{"t":"hello","uid":1000,"note":""}\n' + procview.encode_snapshot({1: rec(1)}, [], {}) + "\n")
        def terminate(self): pass
        def wait(self, timeout=None): return 0
    h = procview.ElevatedHelper(popen=lambda *a, **k: P())
    assert not h.start(wait=1) and "not running as root" in h.error


def test_elevated_helper_reports_failure_to_start():
    def boom(*a, **k):
        raise OSError(2, "No such file")
    h = procview.ElevatedHelper(popen=boom)
    assert not h.start() and "cannot start" in h.error


def test_lock_allows_one_agent(tmp_path):
    a, b = AgentLock(tmp_path / "l"), AgentLock(tmp_path / "l")
    assert a.acquire() and not b.acquire()
    a.release()
    assert b.acquire()
    b.release()


def test_runtime_second_instance_is_a_viewer(tmp_path):
    ruleset = load_rules(default_rules_path(None))
    config = cfg.Config(sources=[], interval=0.1)
    first = AgentRuntime(ruleset=ruleset, config=config, db_path=tmp_path / "e.db", lock=AgentLock(tmp_path / "l"))
    second = AgentRuntime(ruleset=ruleset, config=config, db_path=tmp_path / "e.db", lock=AgentLock(tmp_path / "l"))
    try:
        assert first.start() == "agent"
        assert second.start() == "viewer"
        time.sleep(0.4)
        assert first.agent.events >= 0 and not first.error
    finally:
        first.stop()
        second.stop()
    assert first.lock.fd is None


def _assessment():
    from erinix.assessment import Env, run_assessment
    return run_assessment(Env(root="/nonexistent-erinix-root", proc="/nonexistent-proc", euid=0))


def test_assessment_roundtrip_over_the_pipe():
    result = _assessment()
    got = procview.decode_assessment(procview.encode_assessment(result))
    assert got and got["score"] == result["score"] and len(got["checks"]) == len(result["checks"])


@pytest.mark.parametrize("mutate", [
    lambda d: d["data"].update(score=101),
    lambda d: d["data"].update(score="80"),
    lambda d: d["data"]["checks"][0].update(state="rm -rf"),
    lambda d: d["data"]["checks"][0].update(detail="x" * 5000),
    lambda d: d["data"]["checks"][0].pop("fix"),
    lambda d: d["data"].update(checks="no"),
    lambda d: d["data"]["counts"].update(fail=-1),
])
def test_hostile_assessment_is_rejected(mutate):
    data = json.loads(procview.encode_assessment(_assessment()))
    mutate(data)
    assert procview.decode_assessment(json.dumps(data)) is None


def test_remote_view_keeps_the_latest_assessment():
    line = procview.encode_assessment(_assessment())
    view = procview.RemoteView(io.StringIO('{"t":"hello","uid":0,"note":""}\n' + line + "\n" + '{"t":"assess","data":5}\n')).start()
    view._thread.join(2)
    assert view.assessment and view.assessment["checks"] and view.bad_lines == 1


def test_real_helper_process_end_to_end():
    """Starts the helper as a real subprocess (as the current user) and reads its snapshots and its assessment."""
    import subprocess
    import sys
    h = procview.ElevatedHelper(argv=[sys.executable, "-m", "erinix", "helper"], require_root=False,
                                popen=lambda argv, **kw: subprocess.Popen(argv, env={**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "..", "src")}, **kw))
    try:
        assert h.start(wait=10), h.error
        end = time.time() + 10
        while time.time() < end and h.view.assessment is None:
            time.sleep(0.05)
        assert os.getpid() in h.view.scan() and h.view.assessment
        h.view.nudge()
    finally:
        h.stop()
    assert h.process is None


def test_failed_helper_says_why():
    import subprocess
    import sys
    h = procview.ElevatedHelper(argv=[sys.executable, "-c", "import sys; sys.stderr.write('sudo: a password is required'); sys.exit(1)"])
    assert not h.start(wait=5) and "password is required" in h.error
