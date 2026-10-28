"""Shared pytest fixtures. HTTP-target helpers live in tests/targets.py."""

import socket

import pytest

from scanner import forms, http


@pytest.fixture(autouse=True)
def fresh_scan_state():
    """Give every test the clean slate `run_all_checks` gives every scan.

    The form cache and the cookie jar are module-level and outlive one test.
    Tests bind ephemeral ports, so the OS can hand the same port to a later
    test's server -- without this, that test would be served a cached form list
    parsed from a completely different target.
    """
    forms.clear_cache()
    http.reset_session()
    yield
    forms.clear_cache()
    http.reset_session()


@pytest.fixture
def dead_url():
    """A URL on a port where nothing is listening -> connections refused.

    Bind an ephemeral port to learn a free number, then close it so the port is
    unlistened -- a deterministic 'connection refused' target for the
    down-target tests.
    """
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"
