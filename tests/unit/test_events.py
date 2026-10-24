import pytest

from erinix.core.events import (
    AUDIT_UID_UNSET, MAX_ARGS, MAX_COMM, Event, EventType, FileInfo, NetInfo,
    PrivInfo, ProcessInfo, ProcessKey, SensorInfo, Source, Text,
)


def proc(**kw):
    base = dict(pid=100, start_ns=1, uid=33, euid=33, exe="/usr/bin/bash", argv=["bash"], comm="bash")
    base.update(kw)
    return ProcessInfo.build(**base)


def test_text_is_bounded_and_raw():
    t = Text.of("<script>" + "a" * 50, 10)
    assert t.value == "<script>aa" and t.truncated  # nessun escape: dato grezzo


def test_text_invalid_bytes_never_crash():
    t = Text.of(b"ok\xff\xfe", 100)
    assert t.value == "ok\\xff\\xfe"
    t.value.encode("utf-8")  # sempre UTF-8 valido


def test_process_key_rejects_invalid_pid():
    with pytest.raises(ValueError):
        ProcessKey(0, 1)


def test_argv_limited():
    p = proc(argv=["x"] * (MAX_ARGS + 5))
    assert len(p.argv) == MAX_ARGS and p.argv_truncated


def test_loginuid_unset_means_service():
    assert not proc(loginuid=AUDIT_UID_UNSET).from_login_session
    assert proc(loginuid=1000).from_login_session


def test_name_mismatch():
    assert proc(exe="/tmp/x", comm="sshd").name_mismatch
    assert not proc(exe="/usr/sbin/sshd", comm="sshd").name_mismatch
    assert len(proc(comm="a" * 50).comm.value) == MAX_COMM


def test_event_requires_matching_payload():
    with pytest.raises(ValueError):
        Event(EventType.NET_CONNECT, Source.EBPF, process=proc())
    with pytest.raises(ValueError):
        Event(EventType.PROCESS_EXEC, Source.EBPF, process=proc(),
              payload=SensorInfo.build(detail="x"))
    with pytest.raises(ValueError):
        Event(EventType.PROCESS_EXEC, Source.EBPF)  # manca il processo


def test_net_external_detection():
    ext = NetInfo.build(protocol="tcp", remote_addr="10.0.0.5", remote_port=4444)
    lo = NetInfo.build(protocol="tcp", remote_addr="127.0.0.1", remote_port=4444)
    assert ext.remote_is_external and not lo.remote_is_external
    with pytest.raises(ValueError):
        NetInfo.build(protocol="tcp", remote_port=70000)


def test_priv_became_root():
    assert PrivInfo(1000, 0, 1000, 0, Text("setuid")).became_root
    assert not PrivInfo(0, 0, 0, 0, Text("setuid")).became_root


def test_file_operation_validated():
    with pytest.raises(ValueError):
        FileInfo.build(path="/etc/shadow", operation="rm -rf")


def test_critical_lane():
    e = Event(EventType.PROCESS_EXEC, Source.EBPF, process=proc())
    assert e.is_critical
    f = Event(EventType.FILE_ACCESS, Source.EBPF, process=proc(),
              payload=FileInfo.build(path="/etc/hosts", operation="read"))
    assert not f.is_critical
