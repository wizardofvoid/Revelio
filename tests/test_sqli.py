"""SQL-injection check: fires on a DB error, stays quiet on a clean app.

Detection is error-based: a payload that provokes a database error string is a
hit. The regression this guards is the signature list -- it once matched only
MySQL/Oracle and missed the SQLite errors the practice target actually emits,
so a real injection produced no finding.
"""

import html
from urllib.parse import parse_qs, urlparse

from scanner import sqli_check
from tests.targets import make_handler, serve

FORM_PAGE = (
    "<!doctype html><title>Login</title>"
    '<form method="get" action="/login"><input type="text" name="username"></form>'
)


def _u(handler):
    return parse_qs(urlparse(handler.path).query).get("username", [""])[0]


def _sqlite_erroring_login(handler):
    """A quote breaks the query and the app leaks the SQLite error."""
    user = _u(handler)
    if "'" in user:
        # The signature list must recognise this SQLite wording.
        return 200, '<p>Database error: unrecognized token: "x\'"</p>'
    return 200, "<p>Login</p>"


def _safe_login(handler):
    """Parameterised query: input is escaped and no error ever leaks."""
    return 200, f"<p>Welcome, {html.escape(_u(handler))}</p>"


def test_sqlite_error_is_flagged():
    routes = {"/": (200, FORM_PAGE), "/login": _sqlite_erroring_login}
    with serve(make_handler(routes)) as base:
        result = sqli_check.run(base)
    assert result["status"] == "fail"
    assert "username" in result["detail"]


def test_clean_app_is_not_flagged():
    """No DB error ever returned -> pass, no false positive."""
    routes = {"/": (200, FORM_PAGE), "/login": _safe_login}
    with serve(make_handler(routes)) as base:
        result = sqli_check.run(base)
    assert result["status"] == "pass"
