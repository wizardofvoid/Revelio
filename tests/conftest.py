"""Shared pytest fixtures. HTTP-target helpers live in tests/targets.py."""

import socket

import pytest


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
