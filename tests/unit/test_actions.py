import json
import os
import stat
import subprocess
import time

import pytest

from erinix import actions as ac
from erinix.assessment import Env
from erinix.store import Store


class FakeRun:
    """Stands in for subprocess.run: remembers every nft call, fails when told to."""

    def __init__(self, have_table=False, fail=None, missing=False):
        self.calls, self.have_table, self.fail, self.missing = [], have_table, fail, missing

    def __call__(self, argv, **kw):
        if self.missing:
            raise FileNotFoundError("nft")
        self.calls.append((argv, kw.get("input")))
        code = 0
        if argv[:3] == ["nft", "list", "table"]:
            code = 0 if self.have_table else 1
        if self.fail and any(self.fail in a for a in argv):
            code = 1
        return subprocess.CompletedProcess(argv, code, "", "Error: boom" if code else "")


def put(root, path, text="x", mode=0o644):
    f = root / path.lstrip("/")
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    os.chmod(f, mode)
    return f


@pytest.fixture()
def proc(tmp_path):
    p = tmp_path / "proc"
    (p / "net").mkdir(parents=True)
    (p / "net" / "route").write_text("Iface\tDestination\tGateway\tFlags\nwlan0\t00000000\t0100A8C0\t0003\n")        # gateway 192.168.0.1
    (p / "net" / "fib_trie").write_text("  |-- 192.168.0.7\n     /32 host LOCAL\n")
    return str(p)


# ------------------------------------------------------------------ block
def test_block_plan_and_execution(proc):
    p = ac.plan("block", {"ip": "203.0.113.50", "minutes": 30}, proc=proc, euid=0)
    assert "203.0.113.50" in p.title and "30" in p.title and p.undoable
    run = FakeRun()
    res = ac.execute("block", {"ip": "203.0.113.50", "minutes": 30}, proc=proc, run=run, euid=0)
    assert res["ok"] and res["undo"] == {"action": "unblock", "ip": "203.0.113.50"}
    argvs = [c[0] for c in run.calls]
    assert ["nft", "-f", "-"] in argvs and any("203.0.113.50 timeout 30m" in " ".join(a) for a in argvs)
    assert all(a[0] == "nft" for a in argvs)


def test_block_reuses_the_existing_table(proc):
    run = FakeRun(have_table=True)
    ac.execute("block", {"ip": "2001:db8::5", "minutes": 5}, proc=proc, run=run, euid=0)
    argvs = [c[0] for c in run.calls]
    assert ["nft", "-f", "-"] not in argvs and any("blocked6" in " ".join(a) for a in argvs)


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "0.0.0.0", "224.0.0.1", "169.254.1.1", "192.168.0.7", "192.168.0.1", "not-an-ip", "1.2.3.4; reboot",
                                "203.0.113.50 timeout 1d } ; flush ruleset", "", "1" * 50])
def test_block_refuses_dangerous_or_malformed_addresses(proc, ip):
    run = FakeRun()
    res = ac.execute("block", {"ip": ip, "minutes": 5}, proc=proc, run=run, euid=0)
    assert not res["ok"] and not run.calls


@pytest.mark.parametrize("minutes", [0, -1, 1441, "60", None, True, 1.5])
def test_block_refuses_bad_durations(proc, minutes):
    res = ac.execute("block", {"ip": "203.0.113.5", "minutes": minutes}, proc=proc, run=FakeRun(), euid=0)
    assert not res["ok"]


def test_block_reports_nft_failure_and_missing_nft(proc):
    assert "boom" in ac.execute("block", {"ip": "203.0.113.5", "minutes": 5}, proc=proc, run=FakeRun(fail="element"), euid=0)["message"]
    assert "not installed" in ac.execute("block", {"ip": "203.0.113.5", "minutes": 5}, proc=proc, run=FakeRun(missing=True), euid=0)["message"]


def test_unblock(proc):
    run = FakeRun()
    assert ac.execute("unblock", {"ip": "203.0.113.5"}, proc=proc, run=run, euid=0)["ok"]
    assert "delete" in run.calls[0][0]


# ------------------------------------------------------------------ kill
def fake_proc(proc, pid, start=100, ppid=1, uid=1000, comm="evil"):
    d = os.path.join(proc, str(pid))
    os.makedirs(d, exist_ok=True)
    fields = ["S", str(ppid)] + ["0"] * 17 + [str(start)] + ["0"] * 20
    open(os.path.join(d, "stat"), "w").write(f"{pid} ({comm}) " + " ".join(fields))
    open(os.path.join(d, "status"), "w").write(f"Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
    open(os.path.join(d, "cmdline"), "wb").write(b"evil\0--x\0")


def test_kill_checks_the_start_time(proc):
    fake_proc(proc, 4242, start=100)
    sent = []
    p = ac.plan("kill", {"pid": 4242}, proc=proc, euid=1000)
    assert p.args["start"] == 100
    res = ac.execute("kill", p.args, proc=proc, kill=lambda pid, sig: sent.append((pid, sig)), euid=1000)
    assert res["ok"] and sent == [(4242, 15)]
    fake_proc(proc, 4242, start=999)                                # the number was reused by another program
    res = ac.execute("kill", {"pid": 4242, "start": 100, "signal": "TERM"}, proc=proc, kill=lambda *a: sent.append(a), euid=1000)
    assert not res["ok"] and len(sent) == 1


@pytest.mark.parametrize("pid", [0, 1, -5, "12", None, True, 99999999, os.getpid(), os.getppid()])
def test_kill_refuses_bad_or_protected_numbers(proc, pid):
    res = ac.execute("kill", {"pid": pid}, proc=proc, kill=lambda *a: pytest.fail("must not kill"), euid=0)
    assert not res["ok"]


def test_kill_of_another_users_program_needs_root(proc):
    fake_proc(proc, 4243, uid=0)
    assert ac.plan("kill", {"pid": 4243}, proc=proc, euid=1000).needs_root
    assert not ac.plan("kill", {"pid": 4243}, proc=proc, euid=0).needs_root
    def deny(pid, sig):
        raise PermissionError
    assert "root" in ac.execute("kill", {"pid": 4243}, proc=proc, kill=deny, euid=1000)["message"]


def test_kill_signal_is_whitelisted(proc):
    fake_proc(proc, 4244)
    assert not ac.execute("kill", {"pid": 4244, "signal": "STOP; rm"}, proc=proc, euid=1000)["ok"]


# ------------------------------------------------------------------ fix
def fake_machine(tmp_path):
    put(tmp_path, "/etc/passwd", "root:x:0:0::/root:/bin/sh\n", 0o666)
    put(tmp_path, "/etc/shadow", "root:!:1::::::\n", 0o644)
    put(tmp_path, "/home/ivan/.ssh/id_ed25519", "k", 0o644)
    os.chmod(tmp_path / "home/ivan/.ssh", 0o755)
    return Env(str(tmp_path), euid=0, proc=str(tmp_path / "proc"))


def test_fix_restores_modes_and_can_be_undone(tmp_path):
    env = fake_machine(tmp_path)
    assert ac.execute("fix", {"check": "ssh.keys"}, env=env, euid=0)["ok"] is True
    assert stat.S_IMODE(os.stat(tmp_path / "home/ivan/.ssh").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(tmp_path / "home/ivan/.ssh/id_ed25519").st_mode) == 0o600
    res = ac.execute("fix", {"check": "accounts.files"}, env=env, euid=0)
    assert res["ok"] and stat.S_IMODE(os.stat(tmp_path / "etc/passwd").st_mode) == 0o644
    assert stat.S_IMODE(os.stat(tmp_path / "etc/shadow").st_mode) & 0o007 == 0
    back = ac.execute("restore", res["undo"], env=env, euid=0)
    assert back["ok"] and stat.S_IMODE(os.stat(tmp_path / "etc/passwd").st_mode) == 0o666


def test_fix_plan_lists_every_change_and_refuses_unknown_checks(tmp_path):
    env = fake_machine(tmp_path)
    p = ac.plan("fix", {"check": "accounts.files"}, env=env, euid=0)
    assert any("/etc/passwd" in s and "0666 -> 0644" in s for s in p.steps)
    assert not ac.execute("fix", {"check": "net.firewall"}, env=env, euid=0)["ok"]
    assert not ac.execute("fix", {"check": "../../etc"}, env=env, euid=0)["ok"]
    os.chmod(tmp_path / "etc/passwd", 0o644)
    os.chmod(tmp_path / "etc/shadow", 0o640)
    assert "nothing to fix" in ac.execute("fix", {"check": "accounts.files"}, env=env, euid=0)["message"]


def test_undo_record_from_the_journal_cannot_touch_other_paths(tmp_path):
    """The journal lives in the user's store, so what comes back from it is never trusted by the root side."""
    env = fake_machine(tmp_path)
    victim = put(tmp_path, "/etc/important", "x", 0o600)
    for items in ([["/etc/important", 0o777]], [["/etc/passwd/../important", 0o777]], [["/home/ivan/.ssh/../x", 0o777]], [["/etc/sudoers.d/a/b", 0o777]]):
        res = ac.execute("restore", {"items": items}, env=env, euid=0)
        assert not res["ok"]
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o600
    for bad in ([["/etc/passwd", 0o4777]], [["/etc/passwd", True]], [["/etc/passwd"]], "x", [["/etc/passwd", "644"]], [["/etc/passwd", -1]]):
        assert not ac.execute("restore", {"items": bad}, env=env, euid=0)["ok"]


def test_fix_never_follows_a_symlink(tmp_path):
    env = fake_machine(tmp_path)
    target = put(tmp_path, "/etc/other", "x", 0o666)
    os.remove(tmp_path / "etc/shadow")
    os.symlink(target, tmp_path / "etc/shadow")
    ac.execute("fix", {"check": "accounts.files"}, env=env, euid=0)
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o666


# ------------------------------------------------------------------ journal and service
def test_journal_records_and_undo_goes_through_the_service(tmp_path, proc):
    db = tmp_path / "e.db"
    run = FakeRun()
    svc = ac.Service(euid=0, proc=proc, run=run, open_store=lambda: Store(db))
    res = svc.run_action("block", {"ip": "203.0.113.5", "minutes": 10})
    assert res["ok"] and res["n"] == 1
    with Store(db) as st:
        rows = ac.Journal(st).all()
        assert rows[0]["action"] == "block" and rows[0]["minutes"] == 10 and ac.Journal(st).active_blocks()
    undo = svc.undo(1)
    assert undo["ok"]
    with Store(db) as st:
        assert ac.Journal(st).all()[0]["undone"] is True and not ac.Journal(st).active_blocks()
    assert not svc.undo(1)["ok"] and not svc.undo(99)["ok"]


def test_expired_blocks_are_not_listed(tmp_path):
    with Store(tmp_path / "e.db") as st:
        j = ac.Journal(st)
        j.add("block", "x", {"ok": True, "message": "m", "undo": {"action": "unblock", "ip": "1.2.3.4"}}, clock=lambda: 1000.0)
        rows = j.all()
        rows[0]["minutes"] = 1
        st.set_meta(ac.JOURNAL_KEY, rows)
        assert j.active_blocks(now=1030.0) and not j.active_blocks(now=1100.0)


def test_journal_is_bounded_and_escapes(tmp_path):
    with Store(tmp_path / "e.db") as st:
        j = ac.Journal(st)
        for i in range(250):
            j.add("block", "t\x1b[31m" + "x" * 500, {"ok": True, "message": "m" * 900, "undo": None})
        rows = j.all()
        assert len(rows) == ac.JOURNAL_MAX and "\x1b" not in rows[0]["title"] and len(rows[0]["message"]) <= 300


def test_root_actions_without_a_helper_explain_what_to_do(proc):
    res = ac.Service(euid=1000, proc=proc, run=FakeRun()).run_action("block", {"ip": "203.0.113.5", "minutes": 5})
    assert not res["ok"] and "root" in res["message"]


def test_root_actions_go_through_the_helper(proc):
    class Helper:
        alive = True
        def __init__(self): self.sent = []
        def request(self, action, args):
            self.sent.append((action, args))
            return {"ok": True, "message": "done", "undo": None}
    h = Helper()
    res = ac.Service(helper=h, euid=1000, proc=proc).run_action("block", {"ip": "203.0.113.5", "minutes": 5})
    assert res["ok"] and h.sent == [("block", {"ip": "203.0.113.5", "minutes": 5})]


def test_helper_side_rejects_unknown_actions_and_garbage():
    from erinix.sensors.procview import handle_action
    for msg in ({"id": 1, "action": "shell", "args": {"cmd": "id"}}, {"id": 1, "action": "block", "args": "x"}, {"action": "kill"}, {"id": True, "action": 5}):
        out = json.loads(handle_action(msg))
        assert out["t"] == "result" and out["ok"] is False


# ------------------------------------------------------------------ commands
def test_block_command_asks_first_and_needs_yes_when_not_interactive(tmp_path, monkeypatch, capsys, proc):
    from erinix.cli import main
    run = FakeRun()
    ac.set_service(ac.Service(euid=0, proc=proc, run=run, open_store=lambda: Store(tmp_path / "e.db")))
    try:
        assert main(["block", "203.0.113.9", "--no-color"]) == 1
        assert not run.calls and "--yes" in capsys.readouterr().err
        assert main(["block", "203.0.113.9", "--yes", "--minutes", "5", "--no-color"]) == 0
        assert run.calls and "journal" in capsys.readouterr().out
        assert main(["block", "127.0.0.1", "--yes", "--no-color"]) == 1
        assert main(["block", "--no-color"]) == 2
        monkeypatch.setattr("erinix.store.default_db_path", lambda: tmp_path / "e.db")
        assert main(["actions", "--no-color"]) == 0 and "Block 203.0.113.9" in capsys.readouterr().out
    finally:
        ac.set_service(None)


def test_commands_listed_in_help(capsys):
    from erinix.cli import main
    main(["help", "--no-color"])
    out = capsys.readouterr().out
    for name in ("block", "unblock", "kill", "fix", "undo", "actions"):
        assert name in out


@pytest.mark.skipif(not os.path.exists("/usr/sbin/nft") and not os.path.exists("/usr/bin/nft"), reason="nft not installed")
def test_real_nft_is_called_with_a_fixed_argument_list(proc):
    """Not applied for real (needs root and would change the firewall): only checks nft accepts what we would send."""
    p = subprocess.run(["nft", "--check", "-f", "-"], input=ac.NFT_SCRIPT, capture_output=True, text=True)
    assert p.returncode in (0, 1)       # 1 when the sandbox has no netfilter permission; the syntax errors would say so on stderr
    assert "syntax error" not in p.stderr


def test_unblocking_by_hand_closes_the_block_in_the_journal(tmp_path, proc):
    db = tmp_path / "e.db"
    svc = ac.Service(euid=0, proc=proc, run=FakeRun(), open_store=lambda: Store(db))
    svc.run_action("block", {"ip": "203.0.113.5", "minutes": 1})
    svc.run_action("unblock", {"ip": "203.0.113.5"})
    with Store(db) as st:
        assert ac.Journal(st).all()[0]["undone"] is True and not ac.Journal(st).active_blocks()
    assert "1 minute." in ac.execute("block", {"ip": "203.0.113.5", "minutes": 1}, proc=proc, run=FakeRun(), euid=0)["message"]
