import os
import time

import pytest

from erinix import assessment as a


def put(root, path, text="", mode=0o644, mtime=None):
    full = root / path.lstrip("/")
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(text)
    os.chmod(full, mode)
    if mtime is not None:
        os.utime(full, (mtime, mtime))
    return full


def env(root, **kw):
    kw.setdefault("euid", 0)
    kw.setdefault("proc", str(root / "proc"))
    return a.Env(str(root), **kw)


def state(root, check_id, **kw):
    res = a.run_assessment(env(root, **kw))
    return next(c for c in res["checks"] if c["id"] == check_id)


@pytest.fixture()
def fake(tmp_path):
    put(tmp_path, "/etc/passwd", "root:x:0:0::/root:/bin/sh\nivan:x:1000:1000::/home/ivan:/bin/sh\n")
    put(tmp_path, "/etc/shadow", "root:!:1::::::\nivan:$6$x:1::::::\n", 0o640)
    (tmp_path / "proc" / "net").mkdir(parents=True)
    put(tmp_path, "/proc/net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
    return tmp_path


def test_clean_machine_scores_high_and_nothing_fails(fake):
    res = a.run_assessment(env(fake))
    assert res["counts"]["fail"] == 0 and res["score"] >= 90 and res["checks"]


def test_ssh_root_and_password(fake):
    put(fake, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n")
    assert state(fake, "ssh.root_login")["state"] == "fail"
    assert state(fake, "ssh.password_auth")["state"] == "warn"
    assert state(fake, "ssh.empty_passwords")["state"] == "fail"


def test_ssh_good_config_and_first_value_wins(fake):
    put(fake, "/etc/ssh/sshd_config", "PermitRootLogin no\nPasswordAuthentication no\nPermitRootLogin yes\nMatch User bob\n  PasswordAuthentication yes\n")
    assert state(fake, "ssh.root_login")["state"] == "ok"
    assert state(fake, "ssh.password_auth")["state"] == "ok"


def test_ssh_include_is_followed(fake):
    put(fake, "/etc/ssh/sshd_config", "Include sshd_config.d/*.conf\n")
    put(fake, "/etc/ssh/sshd_config.d/10.conf", "PermitRootLogin yes\n")
    assert state(fake, "ssh.root_login")["state"] == "fail"


def test_no_sshd_is_not_applicable(fake):
    assert state(fake, "ssh.root_login")["state"] == "na"


def test_second_uid0_account(fake):
    put(fake, "/etc/passwd", "root:x:0:0::/root:/bin/sh\ntoor:x:0:0::/:/bin/sh\n")
    got = state(fake, "accounts.uid0")
    assert got["state"] == "fail" and "toor" in got["detail"]


def test_empty_password_needs_root_to_know(fake):
    put(fake, "/etc/shadow", "bob::1::::::\n", 0o640)
    assert state(fake, "accounts.empty_password")["state"] == "fail"
    os.remove(fake / "etc/shadow")
    assert state(fake, "accounts.empty_password")["state"] == "unknown"


def test_account_file_permissions(fake):
    os.chmod(fake / "etc/shadow", 0o644)
    os.chmod(fake / "etc/passwd", 0o666)
    got = state(fake, "accounts.files")
    assert got["state"] == "fail" and "shadow" in got["detail"] and "passwd" in got["detail"]


def test_sudoers_writable(fake):
    put(fake, "/etc/sudoers", "root ALL=(ALL) ALL\n", 0o440)
    put(fake, "/etc/sudoers.d/x", "ivan ALL=(ALL) NOPASSWD: ALL\n", 0o666)
    assert state(fake, "accounts.sudoers")["state"] == "fail"
    os.chmod(fake / "etc/sudoers.d/x", 0o440)
    assert state(fake, "accounts.sudoers")["state"] == "ok"


def test_ssh_keys_permissions(fake):
    put(fake, "/home/ivan/.ssh/id_ed25519", "k", 0o644)
    os.chmod(fake / "home/ivan/.ssh", 0o755)
    got = state(fake, "ssh.keys")
    assert got["state"] == "fail" and "id_ed25519" in got["detail"]
    os.chmod(fake / "home/ivan/.ssh", 0o700)
    os.chmod(fake / "home/ivan/.ssh/id_ed25519", 0o600)
    assert state(fake, "ssh.keys")["state"] == "ok"


def _tcp(port, ip="00000000", st="0A"):
    return f"   0: {ip}:{port:04X} 00000000:0000 {st} 00000000:00000000 00:00000000 00000000     0        0 12345 1 0 100 0 0 10 0\n"


def test_risky_open_port_and_loopback_is_fine(fake):
    header = (fake / "proc/net/tcp").read_text()
    put(fake, "/proc/net/tcp", header + _tcp(6379) + _tcp(5432, "0100007F") + _tcp(8080))
    assert state(fake, "net.risky_ports")["state"] == "fail" and "6379" in state(fake, "net.risky_ports")["detail"]
    assert "5432" not in state(fake, "net.risky_ports")["detail"]
    assert state(fake, "net.exposed")["state"] == "info" and "8080" in state(fake, "net.exposed")["detail"]


def test_firewall_detection(fake):
    assert state(fake, "net.firewall")["state"] == "warn"
    put(fake, "/etc/ufw/ufw.conf", "ENABLED=yes\n")
    assert state(fake, "net.firewall")["state"] == "ok"


def test_kernel_settings(fake):
    put(fake, "/proc/sys/kernel/randomize_va_space", "0\n")
    assert state(fake, "system.kernel")["state"] == "fail"
    put(fake, "/proc/sys/kernel/randomize_va_space", "2\n")
    put(fake, "/proc/sys/net/ipv4/tcp_syncookies", "0\n")
    assert state(fake, "system.kernel")["state"] == "warn"


def test_world_writable_file_in_etc(fake):
    put(fake, "/etc/cron.d/evil", "x", 0o666)
    assert state(fake, "files.etc_writable")["state"] == "fail"


def test_setuid_file_in_tmp(fake):
    put(fake, "/tmp/rootkit", "x", 0o4755)
    got = state(fake, "files.suid_temp")
    assert got["state"] == "fail" and "/tmp/rootkit" in got["detail"]


def test_recent_startup_change(fake):
    now = time.time()
    put(fake, "/etc/systemd/system/old.service", "x", mtime=now - 90 * 86400)
    assert state(fake, "system.startup", now=now)["state"] == "ok"
    put(fake, "/etc/systemd/system/new.service", "x", mtime=now - 3600)
    got = state(fake, "system.startup", now=now)
    assert got["state"] == "warn" and "new.service" in got["detail"]


def test_docker_group_and_socket(fake):
    put(fake, "/etc/group", "docker:x:999:ivan\n")
    assert state(fake, "system.docker")["state"] == "warn"
    assert state(fake, "system.docker", euid=1000, home="/home/ivan")["state"] in ("ok", "warn")


def test_reboot_and_visibility(fake):
    put(fake, "/var/run/reboot-required", "")
    assert state(fake, "system.reboot")["state"] == "warn"
    assert state(fake, "erinix.visibility", full_view=False)["state"] == "info"


def test_hostile_names_are_escaped_and_capped(fake):
    put(fake, "/etc/cron.d/\x1b[31mevil\x1b[0m" + "x" * 150, "x", 0o666)
    got = state(fake, "files.etc_writable")
    assert "\x1b" not in got["detail"] and len(got["detail"]) <= 400


def test_one_broken_check_does_not_stop_the_others(fake):
    def boom(env):
        raise RuntimeError("x")
    checks = (a.Check("a", "A", "A", "high", "fix", boom), a.CHECKS[0])
    res = a.run_assessment(env(fake), checks)
    assert res["checks"][0]["state"] in ("unknown", "na") and len(res["checks"]) == 2
    assert any(c["id"] == "a" and c["state"] == "unknown" for c in res["checks"])


def test_scoring_and_order(fake):
    put(fake, "/etc/ssh/sshd_config", "PermitRootLogin yes\n")
    res = a.run_assessment(env(fake))
    assert res["score"] <= 80 and res["checks"][0]["state"] == "fail" and res["checks"][0]["fix"]
    assert all(not c["fix"] for c in res["checks"] if c["state"] in ("ok", "na", "unknown"))


def test_walk_is_bounded_and_does_not_follow_links(tmp_path):
    for i in range(50):
        put(tmp_path, f"/d/f{i}", "x")
    os.symlink("/", tmp_path / "d" / "loop")
    e = a.Env(str(tmp_path), euid=0, proc=str(tmp_path / "proc"))
    assert len(list(e.walk("/d", 3, limit=10))) == 10
    assert all("loop/" not in p for p, _ in e.walk("/d", 5))


def test_runs_on_the_real_machine_without_crashing():
    res = a.run_assessment()
    assert 0 <= res["score"] <= 100 and len(res["checks"]) == len(a.CHECKS)


def test_assess_command_prints_and_saves(tmp_path, monkeypatch, capsys):
    from erinix.cli import main
    from erinix.store import Store

    monkeypatch.setattr("erinix.store.default_db_path", lambda: tmp_path / "e.db")
    assert main(["assess", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "Score" in out and "/100" in out
    assert main(["assess", "--json"]) == 0
    import json
    data = json.loads(capsys.readouterr().out)
    assert data["checks"] and {"id", "state", "fix"} <= set(data["checks"][0])
    assert main(["assess", "extra"]) != 0
