"""Posture assessment: is this machine set up so that an attack is hard? (The "before" of an attack.)

Read-only. Every check only LOOKS at files, permissions and /proc; nothing is changed, no command is run. Each check says what
it found and how to fix it in plain words. What cannot be read without root is reported as "unknown", never guessed.
All text that comes from the machine is untrusted: it is capped and escaped before it is shown.
"""

from __future__ import annotations

import glob
import os
import stat
import time
from dataclasses import dataclass
from typing import Callable

from erinix.sensors import netproc
from erinix.ui.render import safe

MAX_READ = 256 * 1024
MAX_WALK = 6000
RECENT_DAYS = 7
PENALTY = {("fail", "high"): 20, ("fail", "medium"): 10, ("fail", "low"): 4, ("warn", "high"): 8, ("warn", "medium"): 4, ("warn", "low"): 1}
RISKY_PORTS = {21: "FTP", 23: "Telnet", 135: "Windows RPC", 139: "Windows file sharing", 445: "Windows file sharing", 1433: "SQL Server", 2375: "Docker without login",
               3306: "MySQL", 3389: "Remote desktop", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"}


class Env:
    """The machine as the checks see it. `root` lets tests point at a fake filesystem."""

    def __init__(self, root: str = "/", proc: str = "/proc", euid: int | None = None, home: str | None = None, now: float | None = None,
                 full_view: bool | None = None) -> None:
        self.root, self.proc = root, proc
        self.euid = os.geteuid() if euid is None else euid
        self.now = time.time() if now is None else now
        self.full_view = self.euid == 0 if full_view is None else full_view
        if self.euid == 0:
            self.homes = [h for h in self.glob("/home/*") + ["/root"] if os.path.isdir(self.path(h)) and not os.path.islink(self.path(h))]
        else:
            self.homes = [home or os.path.expanduser("~")]

    def path(self, p: str) -> str:
        return os.path.join(self.root, p.lstrip("/")) if self.root != "/" else p

    def virtual(self, real: str) -> str:
        return real if self.root == "/" else "/" + os.path.relpath(real, self.root)

    def glob(self, pattern: str, limit: int = 200) -> list[str]:
        return [self.virtual(r) for r in sorted(glob.glob(self.path(pattern)))[:limit]]

    def listdir(self, p: str, limit: int = 200) -> list[str]:
        try:
            return sorted(os.listdir(self.path(p)))[:limit]
        except OSError:
            return []

    def read(self, p: str) -> str | None:
        try:
            with open(self.path(p), "rb") as f:
                return f.read(MAX_READ).decode("utf-8", "replace")
        except OSError:
            return None

    def mode(self, p: str) -> int | None:
        try:
            return stat.S_IMODE(os.lstat(self.path(p)).st_mode)
        except OSError:
            return None

    def exists(self, p: str) -> bool:
        return os.path.lexists(self.path(p))

    def walk(self, top: str, depth: int, limit: int = MAX_WALK):
        """(path, lstat) for files below `top`, never following links, bounded in depth and count."""
        seen = 0
        base = self.path(top)
        stack = [(base, 0)]
        while stack:
            here, d = stack.pop()
            try:
                entries = os.scandir(here)
            except OSError:
                continue
            with entries:
                for e in entries:
                    seen += 1
                    if seen > limit:
                        return
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    yield self.virtual(e.path), st
                    if stat.S_ISDIR(st.st_mode) and d < depth:
                        stack.append((e.path, d + 1))


@dataclass(frozen=True)
class Check:
    id: str
    area: str
    title: str
    severity: str                       # high | medium | low
    fix: str
    run: Callable[[Env], tuple[str, str]]       # -> (state, detail); state: ok | warn | fail | unknown | info | na


def _short(items: list[str], n: int = 4) -> str:
    items = [safe(i)[:120] for i in items]
    return ", ".join(items[:n]) + (f" and {len(items) - n} more" if len(items) > n else "")


def _sshd(env: Env) -> dict[str, str] | None:
    """The first value of each global sshd setting (sshd keeps the first), or None if sshd is not set up here."""
    text = env.read("/etc/ssh/sshd_config")
    if text is None:
        return None
    values: dict[str, str] = {}

    def parse(body: str, depth: int) -> bool:
        for raw in body.splitlines():
            parts = raw.split("#", 1)[0].split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts[0].lower(), parts[1].strip()
            if key == "match":
                return False                       # everything after Match is conditional: not global
            if key == "include" and depth < 3:
                for pattern in val.split():
                    full = pattern if pattern.startswith("/") else "/etc/ssh/" + pattern
                    for f in env.glob(full, 50):
                        sub = env.read(f)
                        if sub is not None and not parse(sub, depth + 1):
                            return False
            elif key not in values:
                values[key] = val.lower()
        return True

    parse(text, 0)
    return values


def check_ssh_root(env: Env):
    v = _sshd(env)
    if v is None:
        return "na", "SSH server is not set up on this machine."
    val = v.get("permitrootlogin", "prohibit-password")
    if val == "yes":
        return "fail", "SSH lets root log in directly."
    return "ok", f"Root login over SSH is '{safe(val)}'."


def check_ssh_password(env: Env):
    v = _sshd(env)
    if v is None:
        return "na", "SSH server is not set up on this machine."
    if v.get("passwordauthentication", "yes") == "no":
        return "ok", "SSH accepts keys only."
    return "warn", "SSH accepts passwords, so they can be guessed (Erinix will see the guessing, but keys are safer)."


def check_ssh_empty(env: Env):
    v = _sshd(env)
    if v is None:
        return "na", "SSH server is not set up on this machine."
    if v.get("permitemptypasswords", "no") == "yes":
        return "fail", "SSH accepts accounts with an empty password."
    return "ok", "Empty passwords are refused."


def _passwd(env: Env) -> list[list[str]] | None:
    text = env.read("/etc/passwd")
    return None if text is None else [ln.split(":") for ln in text.splitlines() if ln and not ln.startswith("#") and ln.count(":") >= 6]


def check_uid0(env: Env):
    rows = _passwd(env)
    if rows is None:
        return "unknown", "Cannot read the account list."
    extra = [r[0] for r in rows if r[2] == "0" and r[0] != "root"]
    return ("fail", f"Besides root, these accounts have full power: {_short(extra)}.") if extra else ("ok", "Only root has full power.")


def check_empty_password(env: Env):
    text = env.read("/etc/shadow")
    if text is None:
        return "unknown", "Needs root to read the password file (press R in the cockpit, or run as root)."
    empty = [ln.split(":")[0] for ln in text.splitlines() if ln.count(":") >= 2 and ln.split(":")[1] == ""]
    return ("fail", f"Accounts without a password: {_short(empty)}.") if empty else ("ok", "No account has an empty password.")


def check_account_files(env: Env):
    bad = []
    m = env.mode("/etc/passwd")
    if m is not None and m & 0o022:
        bad.append("/etc/passwd can be changed by others")
    m = env.mode("/etc/shadow")
    if m is not None and m & 0o007:
        bad.append("/etc/shadow can be read by everyone")
    if m is not None and m & 0o022:
        bad.append("/etc/shadow can be changed by others")
    if env.mode("/etc/passwd") is None:
        return "unknown", "Cannot look at the account files."
    return ("fail", "; ".join(bad) + ".") if bad else ("ok", "The account files have safe permissions.")


def check_sudoers(env: Env):
    bad, seen = [], False
    for p in ["/etc/sudoers"] + env.glob("/etc/sudoers.d/*", 100):
        m = env.mode(p)
        if m is None:
            continue
        seen = True
        if m & 0o022:
            bad.append(os.path.basename(p))
    if not seen:
        return "na", "sudo is not set up here."
    return ("fail", f"These sudo rules can be changed by others: {_short(bad)}.") if bad else ("ok", "The sudo rules are only changeable by root.")


def check_ssh_keys(env: Env):
    bad = []
    for home in env.homes:
        ssh = home.rstrip("/") + "/.ssh"
        m = env.mode(ssh)
        if m is None:
            continue
        if m & 0o077:
            bad.append(f"{ssh} is open to others")
        for n in env.listdir(ssh):
            p = f"{ssh}/{n}"
            try:
                st = os.lstat(env.path(p))
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            mode = stat.S_IMODE(st.st_mode)
            if n == "authorized_keys" and mode & 0o022:
                bad.append(f"{p} can be changed by others")
            elif n.startswith(("id_", "ssh_host_")) and not n.endswith(".pub") and mode & 0o077:
                bad.append(f"private key {p} can be read by others")
    return ("fail", _short(bad) + ".") if bad else ("ok", "SSH folders and keys are private.")


def _listening(env: Env) -> list[tuple[int, str]] | None:
    try:
        socks = netproc.read_sockets(env.proc)
    except Exception:
        return None
    if not socks and not os.path.exists(os.path.join(env.proc, "net", "tcp")):
        return None
    return sorted({(s.lport, s.local) for s in socks if s.state == "0A" and s.local not in ("127.0.0.1", "::1") and not s.local.startswith("127.")})


def check_risky_ports(env: Env):
    got = _listening(env)
    if got is None:
        return "unknown", "Cannot read the list of open ports."
    risky = [f"{p} ({RISKY_PORTS[p]})" for p, _ in got if p in RISKY_PORTS]
    return ("fail", f"Open to the network: {_short(risky)}. These are common targets.") if risky else ("ok", "No commonly attacked service is open to the network.")


def check_exposed(env: Env):
    got = _listening(env)
    if got is None:
        return "unknown", "Cannot read the list of open ports."
    ports = sorted({p for p, _ in got if p not in RISKY_PORTS})
    return ("info", f"{len(ports)} port{'s' if len(ports) != 1 else ''} open to the network: {_short([str(p) for p in ports], 8)}.") if ports else ("ok", "Nothing is open to the network.")


def check_firewall(env: Env):
    ufw = env.read("/etc/ufw/ufw.conf") or ""
    if any(ln.strip().lower() == "enabled=yes" for ln in ufw.splitlines()):
        return "ok", "ufw is enabled."
    for unit in ("firewalld", "nftables", "netfilter-persistent", "iptables"):
        if env.exists(f"/etc/systemd/system/multi-user.target.wants/{unit}.service"):
            return "ok", f"{unit} starts at boot."
    return "warn", "No firewall found. Rules added by hand cannot be seen without root, so this may be wrong."


def _sysctl(env: Env, name: str) -> int | None:
    try:
        with open(os.path.join(env.proc, "sys", *name.split(".")), "rb") as f:
            return int(f.read(64).decode().strip())
    except (OSError, ValueError):
        return None


def check_kernel(env: Env):
    wanted = [("kernel.randomize_va_space", lambda v: v == 2, "fail", "memory randomization (ASLR) is not full"),
              ("net.ipv4.tcp_syncookies", lambda v: v == 1, "warn", "SYN cookies are off"),
              ("kernel.kptr_restrict", lambda v: v >= 1, "warn", "kernel addresses are visible to users"),
              ("kernel.yama.ptrace_scope", lambda v: v >= 1, "warn", "any program can inspect another of the same user"),
              ("fs.protected_symlinks", lambda v: v == 1, "warn", "symlink tricks in shared folders are not blocked"),
              ("fs.protected_hardlinks", lambda v: v == 1, "warn", "hardlink tricks in shared folders are not blocked")]
    state, problems, known = "ok", [], 0
    for name, good, level, text in wanted:
        v = _sysctl(env, name)
        if v is None:
            continue
        known += 1
        if not good(v):
            problems.append(text)
            state = "fail" if level == "fail" else (state if state == "fail" else "warn")
    if not known:
        return "unknown", "Cannot read the kernel settings."
    return (state, "; ".join(problems).capitalize() + ".") if problems else ("ok", "Kernel protections are on.")


def check_world_writable_etc(env: Env):
    bad = [p for p, st in env.walk("/etc", 3) if stat.S_ISREG(st.st_mode) and st.st_mode & 0o002]
    return ("fail", f"Anyone can change: {_short(bad)}.") if bad else ("ok", "No file in /etc can be changed by everyone.")


def check_suid_in_temp(env: Env):
    bad = []
    for top in ["/tmp", "/var/tmp", "/dev/shm"] + env.homes:
        for p, st in env.walk(top, 3, 2000):
            if stat.S_ISREG(st.st_mode) and st.st_mode & 0o6000:
                bad.append(p)
    return ("fail", f"Programs that run with extra power sit in places anyone can write: {_short(bad)}.") if bad else ("ok", "No hidden power-up programs in temporary or home folders.")


def check_docker(env: Env):
    m = env.mode("/var/run/docker.sock")
    if m is not None and m & 0o002:
        return "fail", "The Docker socket can be used by everyone, which is full control of the machine."
    members: list[str] = []
    for ln in (env.read("/etc/group") or "").splitlines():
        p = ln.split(":")
        if len(p) >= 4 and p[0] == "docker":
            members = [u for u in p[3].split(",") if u]
    if not members:
        return "ok", "Docker does not give extra power here."
    if env.euid == 0:
        return "warn", f"Users in the docker group (same as root): {_short(members)}."
    mine = {r[0] for r in (_passwd(env) or []) if r[2] == str(env.euid)}
    if mine & set(members):
        return "warn", "Your user is in the docker group, which is the same as root: a hijacked program of yours could take the machine."
    return "ok", "Your user is not in the docker group."


def check_recent_startup(env: Env):
    cutoff = env.now - RECENT_DAYS * 86400
    spots = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/systemd/system"] + \
            [h.rstrip("/") + "/.config/systemd/user" for h in env.homes] + [h.rstrip("/") + "/.config/autostart" for h in env.homes]
    recent = []
    for spot in spots:
        for p, st in env.walk(spot, 1, 800):
            if stat.S_ISREG(st.st_mode) and st.st_mtime >= cutoff:
                recent.append(p)
    if recent:
        return "warn", f"Changed in the last {RECENT_DAYS} days in places that start programs: {_short(recent)}. Fine if you did it; an attacker leaves things here to come back."
    return "ok", "Nothing new in the places that start programs automatically."


def check_reboot(env: Env):
    return ("warn", "The system asks for a restart to finish an update.") if env.exists("/var/run/reboot-required") else ("ok", "No restart pending.")


def check_mac(env: Env):
    lsm = env.read("/sys/kernel/security/lsm")
    if lsm is None:
        return "unknown", "Cannot tell if AppArmor or SELinux is active."
    on = [x for x in lsm.strip().split(",") if x in ("apparmor", "selinux")]
    return ("ok", f"{', '.join(on)} is active.") if on else ("info", "No AppArmor or SELinux: programs are not confined beyond normal permissions.")


def check_visibility(env: Env):
    return ("ok", "Erinix sees every program.") if env.full_view else ("info", "Erinix sees only your own programs. Press R in the cockpit to see all.")


CHECKS: tuple[Check, ...] = (
    Check("ssh.root_login", "Remote access", "Root cannot log in over SSH", "high", "In /etc/ssh/sshd_config set PermitRootLogin to no, then restart the SSH service.", check_ssh_root),
    Check("ssh.password_auth", "Remote access", "SSH needs a key, not a password", "medium", "Create an SSH key, copy it to the machine, then set PasswordAuthentication to no in /etc/ssh/sshd_config and restart SSH.", check_ssh_password),
    Check("ssh.empty_passwords", "Remote access", "SSH refuses empty passwords", "high", "In /etc/ssh/sshd_config set PermitEmptyPasswords to no, then restart SSH.", check_ssh_empty),
    Check("ssh.keys", "Remote access", "SSH folders and keys are private", "high", "Run chmod 700 on ~/.ssh and chmod 600 on private keys and authorized_keys.", check_ssh_keys),
    Check("net.risky_ports", "Network", "No commonly attacked service is open", "high", "Stop the service, or make it listen only on 127.0.0.1, or block its port with the firewall.", check_risky_ports),
    Check("net.exposed", "Network", "Open ports are expected", "low", "For each port open to the network, make sure you know which program it is (Erinix, Open ports panel) and that you need it.", check_exposed),
    Check("net.firewall", "Network", "A firewall is active", "medium", "Enable ufw or firewalld (or write nftables rules) and allow only what you need.", check_firewall),
    Check("accounts.uid0", "Accounts", "Only root has full power", "high", "Remove or lock any extra account with user id 0 (check /etc/passwd), then look for how it got there.", check_uid0),
    Check("accounts.empty_password", "Accounts", "Every account has a password", "high", "Set a password or lock the account (passwd -l name).", check_empty_password),
    Check("accounts.files", "Accounts", "Account files have safe permissions", "high", "Restore: chmod 644 /etc/passwd and chmod 640 (or 600) /etc/shadow, owned by root.", check_account_files),
    Check("accounts.sudoers", "Accounts", "Only root can change sudo rules", "high", "chmod 440 the files in /etc/sudoers and /etc/sudoers.d, owned by root. Use visudo to edit.", check_sudoers),
    Check("files.etc_writable", "Files", "Nothing in /etc is changeable by everyone", "high", "Remove the write permission for others (chmod o-w file) and find out who changed it.", check_world_writable_etc),
    Check("files.suid_temp", "Files", "No power-up programs in writable folders", "high", "Inspect the file, remove it if you do not know it (it may be a backdoor), and check how it arrived.", check_suid_in_temp),
    Check("system.kernel", "System", "Kernel protections are on", "medium", "Set the listed values with sysctl in a file under /etc/sysctl.d, then apply them.", check_kernel),
    Check("system.docker", "System", "Docker does not give away root", "medium", "Remove your user from the docker group, or use rootless Docker.", check_docker),
    Check("system.startup", "System", "No recent changes where programs start", "medium", "Open each file listed. If you do not recognize it, treat it as a possible persistence mechanism.", check_recent_startup),
    Check("system.reboot", "System", "No pending restart", "low", "Restart the machine when you can.", check_reboot),
    Check("system.mac", "System", "Programs are confined (AppArmor / SELinux)", "low", "Enable AppArmor or SELinux with your distribution's default profiles.", check_mac),
    Check("erinix.visibility", "Erinix", "Erinix sees every program", "low", "In the cockpit press R, or run erinix --elevate.", check_visibility),
)


def run_assessment(env: Env | None = None, checks: tuple[Check, ...] = CHECKS) -> dict:
    env = env or Env()
    results, penalty = [], 0
    for c in checks:
        try:
            state, detail = c.run(env)
        except Exception as exc:                      # one broken check must never hide the others
            state, detail = "unknown", f"This check failed to run ({type(exc).__name__})."
        results.append({"id": c.id, "area": c.area, "title": c.title, "severity": c.severity, "state": state, "detail": safe(detail)[:400],
                        "fix": c.fix if state in ("fail", "warn", "info") else ""})
        penalty += PENALTY.get((state, c.severity), 0)
    score = max(0, 100 - penalty)
    counts = {s: sum(1 for r in results if r["state"] == s) for s in ("ok", "warn", "fail", "unknown", "info", "na")}
    verdict = "Well set up" if score >= 90 else "Mostly fine, a few things to fix" if score >= 70 else "Needs attention"
    order = {"fail": 0, "warn": 1, "unknown": 2, "info": 3, "ok": 4, "na": 5}
    results.sort(key=lambda r: (order[r["state"]], {"high": 0, "medium": 1, "low": 2}[r["severity"]]))
    return {"at": env.now, "score": score, "verdict": verdict, "counts": counts, "checks": results, "full_view": env.full_view}


def empty_assessment() -> dict:
    return {"at": None, "score": None, "verdict": "Not checked yet", "counts": {s: 0 for s in ("ok", "warn", "fail", "unknown", "info", "na")}, "checks": [], "full_view": False}
