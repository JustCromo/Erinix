import pytest

from erinix.sensors.selector import Capabilities, SensorMode, auditd_running, choose, parse_kernel


@pytest.mark.parametrize("release,expected", [
    ("6.12.5-arch1-1", (6, 12)), ("5.8", (5, 8)), ("5.10-rc1", (5, 10)),
    ("4.19.0", (4, 19)), ("4", None), ("", None), ("abc", None), ("6.x", None),
])
def test_parse_kernel(release, expected):
    assert parse_kernel(release) == expected


def caps(euid=0, kernel="6.12.5", btf=True, installed=False, running=False):
    return Capabilities(euid, kernel, btf, installed, running)


def test_root_modern_kernel_uses_ebpf():
    plan = choose(caps())
    assert plan.mode is SensorMode.EBPF and not plan.rootless


def test_old_kernel_falls_back_to_auditd():
    plan = choose(caps(kernel="4.19.0", btf=False, installed=True))
    assert plan.mode is SensorMode.AUDITD and "too old" in plan.reason


def test_modern_kernel_without_btf_falls_back_and_says_why():
    plan = choose(caps(btf=False, running=True))
    assert plan.mode is SensorMode.AUDITD and "BTF" in plan.reason


def test_nothing_available_is_minimal():
    assert choose(caps(kernel="3.10.0", btf=False)).mode is SensorMode.MINIMAL


def test_rootless_is_observer_but_reports_potential():
    plan = choose(caps(euid=1000))
    assert plan.mode is SensorMode.MINIMAL and plan.rootless and plan.potential is SensorMode.EBPF


def test_unparseable_kernel_does_not_claim_ebpf():
    assert choose(caps(kernel="weird", installed=True)).mode is SensorMode.AUDITD


def test_auditd_running_scan(tmp_path):
    for pid, name in (("101", "bash"), ("202", "auditd"), ("abc", "auditd")):
        d = tmp_path / pid
        d.mkdir()
        (d / "comm").write_text(name + "\n")
    assert auditd_running(str(tmp_path))
    (tmp_path / "202" / "comm").write_text("other\n")
    assert not auditd_running(str(tmp_path))
    assert not auditd_running(str(tmp_path / "missing"))
