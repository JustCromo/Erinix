"""Tests must give the same answer on every machine, whatever the user's umask.

Ubuntu uses umask 002, so a folder made by a test is group-writable and Erinix (rightly) refuses to load rules from it.
Every test runs with the usual 022 instead.
"""

import os

import pytest


@pytest.fixture(autouse=True)
def _usual_umask():
    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)
