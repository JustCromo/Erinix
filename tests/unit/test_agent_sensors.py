"""Real-agent sensors: /proc, network tables, log sources, settings and the loop. Everything runs on fake /proc trees."""

from __future__ import annotations

import os
import time

import pytest

from erinix import config as cfg
from erinix.agent import Agent
from erinix.core.events import EventType
from erinix.parsers.combined import parse_combined_line
from erinix.parsers.web import LogParseError
from erinix.sensors import logsrc, netproc, procfs


def make_proc(root, pid, *, comm="prog", ppid=1, uid=1000, euid=None, cmd=("prog", "-x"), start=100, exe="/usr/bin/prog"):
    d = root / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "stat").write_text(f"{pid} ({comm}) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 {start} 0 0\n")
    (d / "status").write_text(f"Name:\t{comm}\nUid:\t{uid}\t{uid if euid is None else euid}\t{uid}\t{uid}\n")
    (d / "cmdline").write_bytes(b"\0".join(c.encode() for c in cmd) + b"\0")
    if exe:
        try:
            os.symlink(exe, d / "exe")
        except FileExistsError:
            pass
    return d


# ----------------------------------------------------------------------------- procfs
def test_read_process_handles_hostile_names(tmp_path):
    make_proc(tmp_path, 10, comm="a) S 1 (b", cmd=("evil", "x\ny"))
    rec = procfs.read_process(10, str(tmp_path))
    assert rec is not None and rec.pid == 10 and rec.ppid == 1 and rec.comm == "a) S 1 (b"


def test_kernel_threads_and_garbage_are_skipped(tmp_path):
    make_proc(tmp_path, 2, comm="kthreadd", cmd=(), exe=None)
    (tmp_path / "3").mkdir()
    (tmp_path / "3" / "stat").write_text("not a stat line")
    assert procfs.scan(str(tmp_path)) == {}


def test_process_sensor_baseline_then_new_program(tmp_path):
    make_proc(tmp_path, 10)
    sensor = procfs.ProcessSensor(str(tmp_path))
    assert sensor.poll() == []                                   # the first look only learns what already runs
    make_proc(tmp_path, 11, cmd=("nc", "-e", "/bin/sh"), start=200)
    events = sensor.poll()
    assert [e.type for e in events] == [EventType.PROCESS_EXEC]
    assert sensor.poll() == []                                   # reported once


def test_pid_reuse_is_a_new_program(tmp_path):
    make_proc(tmp_path, 10, start=100)
    sensor = procfs.ProcessSensor(str(tmp_path))
    sensor.poll()
    make_proc(tmp_path, 10, start=900)
    assert len(sensor.poll()) == 1


def test_user_becoming_root_is_reported(tmp_path):
    make_proc(tmp_path, 10, uid=1000, euid=1000)
    sensor = procfs.ProcessSensor(str(tmp_path))
    sensor.poll()
    make_proc(tmp_path, 10, uid=1000, euid=0)
    assert [e.type for e in sensor.poll()] == [EventType.PRIV_UID_CHANGE]


def test_own_helpers_are_not_news(tmp_path):
    sensor = procfs.ProcessSensor(str(tmp_path))
    make_proc(tmp_path, 10)
    sensor.poll()
    make_proc(tmp_path, 11, ppid=os.getpid(), start=300)
    assert sensor.poll() == []


def test_flood_of_programs_is_capped(tmp_path):
    sensor = procfs.ProcessSensor(str(tmp_path))
    make_proc(tmp_path, 10)
    sensor.poll()
    for pid in range(100, 100 + procfs.MAX_NEW_PER_POLL + 20):
        make_proc(tmp_path, pid, start=pid)
    events = sensor.poll()
    assert len(events) == procfs.MAX_NEW_PER_POLL + 1
    assert events[-1].type == EventType.SENSOR_EVENTS_LOST


def test_missing_proc_is_reported_not_fatal(tmp_path):
    sensor = procfs.ProcessSensor(str(tmp_path / "nope"))
    assert sensor.poll() == [] and sensor.error


# ----------------------------------------------------------------------------- netproc
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def row(local, remote, state, uid=1000, inode=5000):
    return f"   0: {local} {remote} {state} 00000000:00000000 00:00000000 00000000  {uid}        0 {inode} 1 0 100 0 0 10 0\n"


def test_parse_table_v4_and_v6_and_garbage():
    text = (HEADER + row("0100007F:1F90", "00000000:0000", "0A") + row("0100007F:1F90", "0201A8C0:C350", "01")
            + "garbage line\n" + row("ZZZZ:1F90", "00000000:0000", "0A"))
    socks = netproc.parse_table(text)
    assert [(s.local, s.lport, s.state) for s in socks] == [("127.0.0.1", 8080, "0A"), ("127.0.0.1", 8080, "01")]
    assert socks[1].remote == "192.168.1.2" and socks[1].rport == 50000


def test_ipv4_mapped_v6_address():
    assert netproc._addr("0000000000000000FFFF00000100007F") == "127.0.0.1"


def test_socket_table_is_bounded():
    text = HEADER + "".join(row("0100007F:1F90", "00000000:0000", "0A", inode=i) for i in range(netproc.MAX_SOCKETS + 50))
    assert len(netproc.parse_table(text)) == netproc.MAX_SOCKETS


def make_net(root, rows):
    (root / "net").mkdir(exist_ok=True)
    (root / "net" / "tcp").write_text(HEADER + "".join(rows))
    (root / "net" / "tcp6").write_text(HEADER)


def test_network_sensor_connect_and_listen(tmp_path):
    make_proc(tmp_path, 10, comm="curl", cmd=("curl", "x"))
    fd = tmp_path / "10" / "fd"
    fd.mkdir()
    os.symlink("socket:[777]", fd / "3")
    procs = procfs.ProcessSensor(str(tmp_path))
    procs.poll()
    net = netproc.NetworkSensor(procs, str(tmp_path))
    make_net(tmp_path, [])
    assert net.poll() == []
    make_net(tmp_path, [row("0100007F:9C40", "0100007F:0050", "01", inode=777)])
    events = net.poll()
    assert [e.type for e in events] == [EventType.NET_CONNECT]
    listening, connections = net.inventory()
    assert connections and connections[0]["remote"].startswith("127.0.0.1")


def test_connection_with_unknown_program_makes_no_event(tmp_path):
    procs = procfs.ProcessSensor(str(tmp_path))
    make_proc(tmp_path, 10)
    procs.poll()
    net = netproc.NetworkSensor(procs, str(tmp_path))
    make_net(tmp_path, [])
    net.poll()
    make_net(tmp_path, [row("0100007F:9C40", "0100007F:0050", "01", inode=999)])
    assert net.poll() == []                                      # nobody can be named: say nothing, invent nothing


# ----------------------------------------------------------------------------- combined parser
LINE = '203.0.113.5 - - [12/Nov/2026:10:00:00 +0100] "GET /index.php?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"'


def test_combined_line_parses():
    info = parse_combined_line(LINE)
    assert str(info.remote_addr) == "203.0.113.5" and info.status == 200 and "index.php" in info.decoded


def test_combined_rejects_garbage_and_huge_lines():
    for bad in ("hello world", "1.2.3.4 - - [x] GET / 200", "A" * 20000):
        with pytest.raises(LogParseError):
            parse_combined_line(bad)


def test_combined_is_not_slow_on_hostile_input():
    started = time.perf_counter()
    for payload in ('1.1.1.1 ' + '- ' * 3000, '1.1.1.1 - - [' + 'a' * 5000, LINE[:60] + '"' * 5000):
        try:
            parse_combined_line(payload)
        except LogParseError:
            pass
    assert time.perf_counter() - started < 0.5


# ----------------------------------------------------------------------------- log sources
def test_file_tail_follows_rotation_and_truncation(tmp_path):
    log = tmp_path / "access.log"
    log.write_text(LINE + "\n")                                  # old content: not replayed
    tail = logsrc.FileTail("web", str(log), "combined")
    assert tail.poll() == [] and tail.state == "ok"
    with log.open("a") as fh:
        fh.write(LINE + "\n")
    assert len(tail.poll()) == 1
    os.rename(log, tmp_path / "access.log.1")
    log.write_text(LINE + "\n" + LINE + "\n")
    assert len(tail.poll()) == 2                                 # new file read from its first line
    log.write_text(LINE + "\n")                                  # truncated in place
    assert len(tail.poll()) == 1
    assert tail.status()["understood"] == 4


def test_file_tail_missing_then_appearing(tmp_path):
    log = tmp_path / "later.log"
    tail = logsrc.FileTail("web", str(log), "combined")
    assert tail.poll() == [] and tail.state == "blind" and "does not exist" in tail.detail
    log.write_text(LINE + "\n")
    assert len(tail.poll()) == 1 and tail.state == "ok"


def test_file_tail_counts_unreadable_lines_and_survives_binary(tmp_path):
    log = tmp_path / "a.log"
    log.write_text("")
    tail = logsrc.FileTail("web", str(log), "combined")
    tail.poll()
    with log.open("ab") as fh:
        fh.write(b"\xff\xfe\x00junk\n" + LINE.encode() + b"\n" + b"x" * 70000 + b"\n" + LINE.encode() + b"\n")
    assert len(tail.poll()) == 2
    st = tail.status()
    assert st["understood"] == 2 and st["ignored"] >= 1


def test_file_tail_permission_is_explained(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    log = tmp_path / "x.log"
    log.write_text("")
    log.chmod(0)
    tail = logsrc.FileTail("web", str(log), "combined")
    tail.poll()
    assert tail.state == "blind" and "permission" in tail.detail


def test_command_tail_reads_and_reports_missing_program(tmp_path):
    tail = logsrc.CommandTail("t", ["sh", "-c", f"echo '{LINE}'; sleep 1"], "combined")
    events = []
    end = time.time() + 3
    while not events and time.time() < end:
        events = tail.poll()
        time.sleep(0.05)
    tail.close()
    assert len(events) == 1
    missing = logsrc.CommandTail("t", ["definitely-not-installed-xyz"], "combined")
    missing.poll()
    assert missing.state == "blind" and "not installed" in missing.detail


# ----------------------------------------------------------------------------- settings
def test_config_parses_a_full_file():
    c = cfg.parse_config('[agent]\ninterval=1\n[[source]]\nkind="docker"\ncontainer="caddy"\nformat="caddy"\n'
                         '[[source]]\nkind="journal"\ntag=["sshd"]\nformat="ssh"\n[[source]]\nkind="file"\npath="/var/log/a.log"\nformat="combined"\n')
    assert c.interval == 1.0 and [s.kind for s in c.sources] == ["docker", "journal", "file"]
    assert c.sources[0].build().argv == ["docker", "logs", "-f", "--since", "0s", "caddy"]


@pytest.mark.parametrize("text", [
    '[[source]]\nkind="docker"\ncontainer="-v /:/x"\nformat="caddy"\n',          # option injection
    '[[source]]\nkind="docker"\ncontainer="a;rm -rf /"\nformat="caddy"\n',
    '[[source]]\nkind="journal"\nunit="--output=x"\nformat="ssh"\n',
    '[[source]]\nkind="journal"\nformat="ssh"\n',
    '[[source]]\nkind="file"\npath="relative.log"\nformat="ssh"\n',
    '[[source]]\nkind="file"\npath="/a\\u0000b"\nformat="ssh"\n',
    '[[source]]\nkind="shell"\ncommand="id"\nformat="ssh"\n',                     # no arbitrary commands
    '[[source]]\nkind="file"\npath="/a"\nformat="ssh"\nextra=1\n',
    '[x]\na=1', '[agent]\ninterval=0\n', '[agent]\ninterval=true\n', '[agent]\nfoo=1\n', 'not toml ===',
    '[[source]]\nname="a"\nkind="file"\npath="/a"\nformat="ssh"\n[[source]]\nname="a"\nkind="file"\npath="/b"\nformat="ssh"\n',
])
def test_config_refuses_bad_input(text):
    with pytest.raises(cfg.ConfigError):
        cfg.parse_config(text)


def test_config_source_limit():
    text = "".join(f'[[source]]\nname="s{i}"\nkind="file"\npath="/a{i}"\nformat="ssh"\n' for i in range(cfg.MAX_SOURCES + 1))
    with pytest.raises(cfg.ConfigError):
        cfg.parse_config(text)


def test_config_file_must_be_private(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text("[agent]\n")
    f.chmod(0o666)
    with pytest.raises(cfg.ConfigError, match="written by others"):
        cfg.check_private_file(f)
    f.chmod(0o600)
    cfg.check_private_file(f)
    link = tmp_path / "l.toml"
    link.symlink_to(f)
    with pytest.raises(cfg.ConfigError):
        cfg.check_private_file(link)


def test_explicit_wrong_path_is_an_error_and_missing_means_detect(tmp_path, monkeypatch):
    with pytest.raises(cfg.ConfigError):
        cfg.load(str(tmp_path / "nope.toml"))
    monkeypatch.setenv("ERINIX_CONFIG", str(tmp_path / "also-nope.toml"))
    monkeypatch.setattr(cfg, "config_paths", lambda: [])
    c, origin = cfg.load(detector=lambda: cfg.Config(detected=True))
    assert c.detected and origin == "detected automatically"


def test_detect_picks_only_what_exists(monkeypatch):
    monkeypatch.setattr(cfg, "can_read_journal", lambda: (False, "not in group"))
    c = cfg.detect(files_exist=lambda p: p in ("/var/log/auth.log", "/var/log/nginx/access.log"),
                   docker=lambda: ([("web", "caddy:2"), ("db", "postgres:16")], ""))
    assert [(s.kind, s.format) for s in c.sources] == [("file", "ssh"), ("file", "combined"), ("docker", "caddy")]


def test_detect_explains_what_it_cannot_read(monkeypatch):
    monkeypatch.setattr(cfg, "can_read_journal", lambda: (False, "join the systemd-journal group"))
    monkeypatch.setattr(cfg.shutil, "which", lambda name: "/usr/sbin/sshd" if name == "sshd" else None)
    c = cfg.detect(files_exist=lambda p: False, docker=lambda: ([], "Docker is not usable"))
    assert any("journal" in n for n in c.notes) and any("Docker" in n for n in c.notes)


# ----------------------------------------------------------------------------- agent
class Boom:
    name = "boom"
    error = ""

    def poll(self):
        raise RuntimeError("x")


def test_agent_isolates_a_broken_source(tmp_path):
    from erinix.engine import Correlator
    from erinix.recorder import Recorder
    from erinix.rules import load_rules
    from erinix.store import Store
    from erinix.commands.builtin import default_rules_path

    store = Store(tmp_path / "e.db")
    agent = Agent(store, Recorder(store, Correlator(load_rules(default_rules_path(None)))), cfg.Config(processes=False, network=False),
                  proc=str(tmp_path))
    log = tmp_path / "a.log"
    log.write_text("")
    agent.logs = [logsrc.FileTail("web", str(log), "combined")]
    agent.processes = Boom()
    agent.start()
    agent.processes = None                                       # the next look publishes a normal picture
    with log.open("a") as fh:
        fh.write(LINE + "\n")
    agent._inventory_at = 0
    assert agent.step() == 1
    assert store.get_meta("mode") == "live"
    names = {s["name"]: s for s in store.get_meta("sources")}
    assert names["web"]["state"] == "ok" and names["web"]["understood"] == 1
    assert store.get_meta("inventory")["host"]["name"]
    result = agent.run(duration=0.2, sleep=lambda s: time.sleep(0.01))
    assert result["events"] == 1
