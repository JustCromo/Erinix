"""Settings and source detection.

Erinix works with no file at all: it looks at the machine and picks what it can read. A TOML file
(`~/.config/erinix/config.toml`, or `/etc/erinix/config.toml` for the service, or `--config PATH`) says exactly what to
watch. Nothing is hard-wired: every source, path, container and format comes from here.

    [agent]
    interval = 0.5            # seconds between looks (0.2 to 10)
    processes = true
    network = true

    [[source]]
    name = "Website (Caddy)"
    kind = "docker"           # file | journal | docker
    container = "caddy"
    format = "caddy"          # caddy | combined (nginx, Apache) | ssh

    [[source]]
    name = "SSH logins"
    kind = "journal"
    tag = ["sshd", "sshd-session"]       # or: unit = "ssh.service"
    format = "ssh"

    [[source]]
    kind = "file"
    path = "/var/log/nginx/access.log"
    format = "combined"

The file is trusted input only if it cannot be changed by anyone else (see check_private_file): a settings file
that a stranger can edit would let him choose what a (possibly root) agent runs and reads.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from erinix.sensors.logsrc import FORMATS, CommandTail, FileTail, LogSource, can_read_journal

MAX_SOURCES = 32
MAX_CONFIG_BYTES = 64 * 1024
_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,80}$")
_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@:-]{0,99}$")            # no leading "-": it could be taken for an option
_CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
KINDS = ("file", "journal", "docker")
_AGENT_KEYS = {"interval", "processes", "network"}
_SOURCE_KEYS = {"name", "kind", "path", "container", "unit", "tag", "format"}
WEB_FILES = (("/var/log/caddy/access.log", "caddy"), ("/var/log/nginx/access.log", "combined"),
             ("/var/log/apache2/access.log", "combined"), ("/var/log/httpd/access_log", "combined"),
             ("/var/log/httpd-access.log", "combined"))
SSH_FILES = ("/var/log/auth.log", "/var/log/secure")
WEB_IMAGES = (("caddy", "caddy"), ("nginx", "combined"), ("httpd", "combined"), ("apache", "combined"))


class ConfigError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SourceSpec:
    name: str
    kind: str
    format: str
    path: str = ""
    container: str = ""
    unit: str = ""
    tag: tuple[str, ...] = ()

    def build(self) -> LogSource:
        if self.kind == "file":
            return FileTail(self.name, self.path, self.format)
        if self.kind == "docker":
            return CommandTail(self.name, ["docker", "logs", "-f", "--since", "0s", self.container], self.format, merge_stderr=True)
        argv = ["journalctl", "-f", "-n", "0", "-o", "short-iso" if self.format == "ssh" else "cat"]
        for tag in self.tag:
            argv += ["-t", tag]
        if self.unit:
            argv += ["-u", self.unit]
        return CommandTail(self.name, argv, self.format)


@dataclass(frozen=True, slots=True)
class Config:
    interval: float = 0.5
    processes: bool = True
    network: bool = True
    sources: tuple[SourceSpec, ...] = ()
    detected: bool = False                     # True when no file was used and the sources were found by looking
    notes: tuple[str, ...] = field(default=())  # why something could not be detected


def check_private_file(path: Path) -> None:
    """Refuse a settings file that someone else could have written."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from None
    if not os.path.isfile(path):
        raise ConfigError(f"{path} is not a regular file")
    me = os.geteuid()
    if st.st_uid not in (me, 0) or (me == 0 and st.st_uid != 0):
        raise ConfigError(f"{path} must belong to you (or to root, when running as root)")
    if st.st_mode & 0o022:
        raise ConfigError(f"{path} can be written by others: run  chmod 600 {path}")
    if st.st_size > MAX_CONFIG_BYTES:
        raise ConfigError(f"{path} is too big")


def _spec(item: object, index: int) -> SourceSpec:
    where = f"source #{index + 1}"
    if not isinstance(item, dict):
        raise ConfigError(f"{where}: must be a table")
    unknown = set(item) - _SOURCE_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown setting {sorted(unknown)[0]!r}")
    kind, fmt = item.get("kind"), item.get("format")
    if kind not in KINDS:
        raise ConfigError(f"{where}: kind must be one of {', '.join(KINDS)}")
    if fmt not in FORMATS:
        raise ConfigError(f"{where}: format must be one of {', '.join(FORMATS)}")
    name = item.get("name", "")
    if name and (not isinstance(name, str) or not _NAME.match(name)):
        raise ConfigError(f"{where}: invalid name")
    if kind == "file":
        path = item.get("path")
        if not isinstance(path, str) or not os.path.isabs(path) or "\0" in path or len(path) > 1024:
            raise ConfigError(f"{where}: a file source needs an absolute path")
        return SourceSpec(name or os.path.basename(path), kind, fmt, path=os.path.normpath(path))
    if kind == "docker":
        container = item.get("container")
        if not isinstance(container, str) or not _CONTAINER.match(container):
            raise ConfigError(f"{where}: a docker source needs a valid container name")
        return SourceSpec(name or f"Container {container}", kind, fmt, container=container)
    unit, tags = item.get("unit", ""), item.get("tag", [])
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(unit, str) or (unit and not _WORD.match(unit)):
        raise ConfigError(f"{where}: invalid unit name")
    if not isinstance(tags, list) or len(tags) > 8 or not all(isinstance(t, str) and _WORD.match(t) for t in tags):
        raise ConfigError(f"{where}: invalid tag list")
    if not unit and not tags:
        raise ConfigError(f"{where}: a journal source needs a unit or a tag")
    return SourceSpec(name or f"Journal {unit or tags[0]}", kind, fmt, unit=unit, tag=tuple(tags))


def parse_config(text: str) -> Config:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"the settings file is not valid TOML: {exc}") from None
    unknown = set(data) - {"agent", "source"}
    if unknown:
        raise ConfigError(f"unknown section {sorted(unknown)[0]!r}")
    agent = data.get("agent", {})
    if not isinstance(agent, dict) or set(agent) - _AGENT_KEYS:
        raise ConfigError("[agent] accepts only: " + ", ".join(sorted(_AGENT_KEYS)))
    interval = agent.get("interval", 0.5)
    if isinstance(interval, bool) or not isinstance(interval, (int, float)) or not 0.2 <= interval <= 10:
        raise ConfigError("interval must be a number between 0.2 and 10")
    for key in ("processes", "network"):
        if not isinstance(agent.get(key, True), bool):
            raise ConfigError(f"{key} must be true or false")
    items = data.get("source", [])
    if not isinstance(items, list) or len(items) > MAX_SOURCES:
        raise ConfigError(f"at most {MAX_SOURCES} sources")
    sources = tuple(_spec(item, i) for i, item in enumerate(items))
    names = [s.name for s in sources]
    if len(set(names)) != len(names):
        raise ConfigError("two sources have the same name")
    return Config(float(interval), agent.get("processes", True), agent.get("network", True), sources)


def config_paths() -> list[Path]:
    paths = []
    if os.geteuid() != 0:                                  # root never reads a file from a home directory
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
        paths.append(Path(base) / "erinix" / "config.toml")
    paths.append(Path("/etc/erinix/config.toml"))
    return paths


def _docker_containers() -> tuple[list[tuple[str, str]], str]:
    exe = shutil.which("docker")
    if exe is None:
        return [], ""
    try:
        out = subprocess.run([exe, "ps", "--format", "{{.Names}}\t{{.Image}}"], capture_output=True, timeout=4, text=True, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return [], "Docker did not answer"
    if out.returncode != 0:
        return [], "Docker is installed but this user may not use it (join the 'docker' group, or set the container in the settings file)"
    rows = []
    for line in out.stdout.splitlines()[:200]:
        name, _, image = line.partition("\t")
        if _CONTAINER.match(name):
            rows.append((name, image))
    return rows, ""


def detect(*, files_exist=os.path.exists, docker=_docker_containers) -> Config:
    """Look at this machine and pick sources it can really read. Anything it cannot read is said, not hidden."""
    sources: list[SourceSpec] = []
    notes: list[str] = []
    ok, why = can_read_journal()
    if ok:
        sources.append(SourceSpec("SSH logins", "journal", "ssh", tag=("sshd", "sshd-session")))
    else:
        found = next((p for p in SSH_FILES if files_exist(p)), None)
        if found:
            sources.append(SourceSpec("SSH logins", "file", "ssh", path=found))
        elif shutil.which("sshd") or files_exist("/etc/ssh/sshd_config"):
            notes.append(f"SSH logins: {why}")
    for path, fmt in WEB_FILES:
        if files_exist(path):
            sources.append(SourceSpec(f"Web server log ({os.path.basename(os.path.dirname(path))})", "file", fmt, path=path))
    rows, note = docker()
    if note:
        notes.append(note)
    for name, image in rows:
        fmt = next((f for key, f in WEB_IMAGES if key in image.lower() or key in name.lower()), None)
        if fmt:
            sources.append(SourceSpec(f"Container {name}", "docker", fmt, container=name))
    return Config(sources=tuple(sources), detected=True, notes=tuple(notes))


def load(path: str | None = None, *, detector=detect) -> tuple[Config, str]:
    """(settings, where they came from). An explicit path that is wrong is an error; no file at all means detect."""
    if path:
        target = Path(path)
        check_private_file(target)
        return parse_config(target.read_text(encoding="utf-8")), str(target)
    env = os.environ.get("ERINIX_CONFIG")
    candidates = [Path(env)] if env else config_paths()
    for target in candidates:
        if target.exists():
            check_private_file(target)
            return parse_config(target.read_text(encoding="utf-8")), str(target)
    return detector(), "detected automatically"
