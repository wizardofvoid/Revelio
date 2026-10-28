"""Reflected-XSS check, centred on the false-positive guard.

The whole point of this check is that it does NOT fire on every app that echoes
input. An app that reflects ``&lt;script&gt;`` is escaping correctly and must
pass; only a raw, unescaped reflection is a finding. If this guard breaks, the
scanner flags XSS on well-written apps and becomes useless.
"""

import html
from urllib.parse import parse_qs, urlparse

from scanner import xss_check
from tests.targets import make_handler, serve

FORM_PAGE = (
    "<!doctype html><title>Search</title>"
    '<form method="get" action="/search"><input type="text" name="q"></form>'
)


def _q(handler):
    """Pull the 'q' query param off the request."""
    return parse_qs(urlparse(handler.path).query).get("q", [""])[0]


def _escaping_search(handler):
    """Reflect q HTML-escaped -- a correctly-written app."""
    return 200, f"<p>No results for: {html.escape(_q(handler))}</p>"


def _raw_search(handler):
    """Reflect q verbatim -- a vulnerable app."""
    return 200, f"<p>No results for: {_q(handler)}</p>"


def test_escaping_app_is_not_flagged():
    """The false-positive guard: escaped reflection -> PASS."""
    routes = {"/": (200, FORM_PAGE), "/search": _escaping_search}
    with serve(make_handler(routes)) as base:
        result = xss_check.run(base)
    assert result["status"] == "pass", result["detail"]


def test_unescaped_reflection_is_flagged():
    """Raw reflection of the payload -> FAIL naming the field."""
    routes = {"/": (200, FORM_PAGE), "/search": _raw_search}
    with serve(make_handler(routes)) as base:
        result = xss_check.run(base)
    assert result["status"] == "fail"
    assert "'q'" in result["detail"]


def _sticky_raw_search(handler):
    """Reflect q raw AND echo an escaped copy into the sticky input value.

    This is what most frameworks do -- re-populate the box the user typed in --
    and it used to hide the vulnerability completely: the check demanded that no
    escaped copy of the payload appear anywhere on the page, so the sticky field
    cancelled out the real, raw reflection above it and the app came back PASS.
    """
    value = _q(handler)
    escaped = (
        value.replace("&", "&amp;").replace("<", "&lt;")
        .replace(">", "&gt;").replace('"', "&quot;")
    )
    return 200, (
        f"<p>No results for: {value}</p>"
        f'<form method="get" action="/search">'
        f'<input type="text" name="q" value="{escaped}"></form>'
    )


def test_raw_reflection_still_flagged_when_page_also_escapes_elsewhere():
    """Regression: an escaped copy elsewhere must not cancel a raw reflection."""
    routes = {"/": (200, FORM_PAGE), "/search": _sticky_raw_search}
    with serve(make_handler(routes)) as base:
        result = xss_check.run(base)
    assert result["status"] == "fail", result["detail"]
    assert "'q'" in result["detail"]


def test_no_forms_is_a_pass():
    """A page with no forms has nothing to test -> pass, not error."""
    routes = {"/": (200, "<p>no forms here</p>")}
    with serve(make_handler(routes)) as base:
        result = xss_check.run(base)
    assert result["status"] == "pass"
