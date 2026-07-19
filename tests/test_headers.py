"""Security-headers check, including the 'present but useless' case.

The subtle bug: a header can be *set* to a value that does nothing
(``X-Content-Type-Options: sniff`` instead of ``nosniff``). Checking only for
presence would pass it; the check must treat a wrong value as a finding.
"""

from scanner import headers_check
from tests.targets import make_handler, serve

# A value set on all four required headers so nothing is merely "missing".
GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "SAMEORIGIN",
    "X-Content-Type-Options": "nosniff",
    # HSTS not needed: target is http, so the check skips it.
}


def test_all_headers_present_passes():
    with serve(make_handler({"/": (200, "ok")}, extra_headers=GOOD_HEADERS)) as base:
        result = headers_check.run(base)
    assert result["status"] == "pass", result["detail"]


def test_missing_headers_flagged_high():
    """No security headers at all -> fail, and CSP missing makes it high."""
    with serve(make_handler({"/": (200, "ok")})) as base:
        result = headers_check.run(base)
    assert result["status"] == "fail"
    assert result["severity"] == "high"
    assert "Content-Security-Policy" in result["detail"]


def test_present_but_useless_value_is_flagged():
    """X-Content-Type-Options: sniff is set but does nothing -> still flagged."""
    headers = dict(GOOD_HEADERS, **{"X-Content-Type-Options": "sniff"})
    with serve(make_handler({"/": (200, "ok")}, extra_headers=headers)) as base:
        result = headers_check.run(base)
    assert result["status"] == "fail"
    # It's reported as set-but-not-effective, not as missing.
    assert "not effective" in result["detail"].lower()
    assert "sniff" in result["detail"]
