"""Checks on the dashboard files themselves, plus the real page script run in jsdom (if available)."""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[2] / "src" / "erinix" / "web" / "static"
CHECK = Path(__file__).resolve().parents[1] / "js" / "dashboard_check.mjs"
JS = (STATIC / "app.js").read_text()
HTML = (STATIC / "index.html").read_text()
CSS = (STATIC / "style.css").read_text()


@pytest.mark.parametrize("banned", ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute(\"style\"",
                                    "localStorage", "sessionStorage", "document.cookie", "postMessage", "XMLHttpRequest", "importScripts"])
def test_script_never_builds_html_or_runs_strings(banned):
    assert banned not in JS


def test_script_has_no_external_addresses():
    urls = re.findall(r"https?://[^\s\"'`)]+", JS + HTML + CSS)
    assert [u for u in urls if "w3.org/2000/svg" not in u] == []
    assert JS.lstrip().startswith('"use strict"')


def test_page_has_no_inline_code_or_handlers():
    assert "<script>" not in HTML and not re.search(r"<script(?![^>]*\bsrc=)", HTML)
    assert not re.search(r"\son[a-z]+\s*=", HTML) and "style=" not in HTML and "<style" not in HTML
    assert "javascript:" not in HTML + JS + CSS
    assert "@import" not in CSS and "url(" not in CSS and "expression(" not in CSS


def test_page_points_only_at_local_files():
    refs = re.findall(r'(?:src|href)="([^"]+)"', HTML)
    assert refs and all(r.startswith(("/static/", "/favicon", "#")) for r in refs)


def test_dashboard_files_ship_with_the_package():
    import erinix.web

    pkg = Path(erinix.web.__file__).parent / "static"
    assert {p.name for p in pkg.iterdir()} >= {"index.html", "app.js", "style.css"}


def _jsdom_available():
    node = shutil.which("node")
    if not node:
        return None
    probe = subprocess.run([node, "-e", "require('jsdom')"], capture_output=True, env=os.environ, timeout=30)
    return node if probe.returncode == 0 else None


def test_real_page_script_in_jsdom():
    node = _jsdom_available()
    if node is None:
        pytest.skip("needs node and the 'jsdom' npm package (npm install jsdom)")
    out = subprocess.run([node, str(CHECK), str(STATIC)], capture_output=True, text=True, timeout=120, env=os.environ)
    assert out.returncode == 0, out.stderr
    checks = json.loads(out.stdout)["checks"]
    failed = [name for name, ok in checks.items() if not ok]
    assert len(checks) >= 25 and failed == []
