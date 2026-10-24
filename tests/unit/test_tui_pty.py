"""Integration test: the real console inside a pseudo-terminal."""

import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time

import pytest

from erinix.tui import terminal as t

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="serve un pty Linux")


class Session:
    def __init__(self, tmp_path, rows=40, cols=130):
        env = {**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor", "LANG": "C.UTF-8",
               "PYTHONIOENCODING": "utf-8", "XDG_STATE_HOME": str(tmp_path)}
        env.pop("NO_COLOR", None)
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execve(sys.executable, [sys.executable, "-m", "erinix.cli"], env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.buf = ""
        self.raw = b""

    def pump(self, seconds=0.5):
        end = time.time() + seconds
        try:
            while time.time() < end:
                ready, _, _ = select.select([self.fd], [], [], 0.05)
                if ready:
                    try:
                        data = os.read(self.fd, 65536)
                    except OSError:          # the child exited: the pty is closed
                        return
                    if not data:
                        return
                    self.raw += data
        finally:
            self.buf = self.raw.decode("utf-8", "replace")

    def wait_for(self, text, timeout=8.0):
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.2)
            if text in t.strip_ansi(self.buf):
                return True
        return False

    def send(self, data: str):
        os.write(self.fd, data.encode())

    def finish(self, timeout=5.0):
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.1)
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self.pump(0.1)
                return os.waitstatus_to_exitcode(status)
        os.kill(self.pid, 9)
        os.waitpid(self.pid, 0)
        return None


def test_console_runs_executes_commands_and_restores_terminal(tmp_path):
    s = Session(tmp_path)
    assert s.wait_for("QUICK START"), s.buf[-500:]
    assert t.ALT_ON in s.buf and t.MOUSE_ON in s.buf and t.PASTE_ON in s.buf
    s.send("version\r")
    assert s.wait_for("erinix 0.1.0")
    s.send("à")                                      # accented letter: UTF-8 is not split
    assert s.wait_for("à")
    s.send("\x15")
    s.send("\x04")
    assert s.finish() == 0
    tail = s.buf[s.buf.rindex(t.RESET + t.PASTE_OFF):]
    assert tail == t.RESET + t.PASTE_OFF + t.MOUSE_OFF + t.CURSOR_SHOW + t.ALT_OFF
    history = (tmp_path / "erinix" / "history").read_text()
    assert "version" in history and oct(os.stat(tmp_path / "erinix" / "history").st_mode & 0o777) == "0o600"


def test_paste_with_newline_does_not_run_the_command(tmp_path):
    s = Session(tmp_path)
    assert s.wait_for("QUICK START")
    s.send("\x1b[200~version\n\x1b[201~")
    s.pump(1.0)
    assert "erinix 0.1.0" not in t.strip_ansi(s.buf)
    s.send("\r")
    assert s.wait_for("erinix 0.1.0")
    s.send("\x04")
    s.send("\x15\x04")
    assert s.finish() in (0, None)


def test_terminate_signal_restores_terminal(tmp_path):
    s = Session(tmp_path)
    assert s.wait_for("QUICK START")
    os.kill(s.pid, 15)
    code = s.finish()
    assert code == 128 + 15                       # orderly exit, not an abrupt termination
    assert s.buf.endswith(t.RESET + t.PASTE_OFF + t.MOUSE_OFF + t.CURSOR_SHOW + t.ALT_OFF)
