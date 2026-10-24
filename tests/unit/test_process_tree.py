from erinix.core.events import ProcessInfo, ProcessKey
from erinix.core.process_tree import ProcessTree


def p(pid, start, ppid=None, pstart=None, exe="/usr/bin/bash"):
    return ProcessInfo.build(pid=pid, start_ns=start, uid=0, euid=0, exe=exe,
                             ppid=ppid, parent_start_ns=pstart)


def build_chain():
    t = ProcessTree()
    t.on_exec(p(1, 0))                          # systemd
    t.on_exec(p(500, 10, 1, 0, "/usr/sbin/apache2"))
    t.on_exec(p(900, 20, 500, 10))              # shell spawned by the web server
    t.on_exec(p(950, 30, 900, 20, "/usr/bin/nc"))
    return t


def test_descendant():
    t = build_chain()
    assert t.is_descendant(ProcessKey(950, 30), ProcessKey(500, 10))
    assert not t.is_descendant(ProcessKey(500, 10), ProcessKey(950, 30))


def test_pid_reuse_does_not_inherit_chain():
    t = build_chain()
    # Same PID 900 but a different start time: it is another process.
    assert not t.is_descendant(ProcessKey(900, 999), ProcessKey(500, 10))


def test_exec_updates_image_keeps_parent():
    t = build_chain()
    t.on_exec(p(900, 20, exe="/usr/bin/python3"))  # execve without parent info
    assert t.get(ProcessKey(900, 20)).exe.value == "/usr/bin/python3"
    assert t.is_descendant(ProcessKey(900, 20), ProcessKey(500, 10))


def test_cycle_is_safe():
    t = ProcessTree()
    t.on_exec(p(2, 2, 3, 3))
    t.on_exec(p(3, 3, 2, 2))
    assert len(t.ancestors(ProcessKey(2, 2))) <= 2


def test_eviction_prefers_exited_and_counts_live():
    t = ProcessTree(max_entries=2)
    t.on_exec(p(10, 1))
    t.on_exec(p(11, 1))
    t.on_exit(ProcessKey(10, 1), 5)
    t.on_exec(p(12, 1))
    assert ProcessKey(10, 1) not in t and t.evicted_live == 0
    t.on_exec(p(13, 1))
    assert len(t) == 2 and t.evicted_live == 1
