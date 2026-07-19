"""Directory-listing check: the SPA trap and the real-listing case.

The bug this guards against: a target that returns 200 for *every* path (an SPA
serving its shell, or a catch-all router) was once reported as an exposed
directory listing. A 200 is not enough -- the body must actually look like a
listing.
"""

import pytest

from scanner import dir_listing_check
from scanner.http import TargetUnreachable
from tests.targets import make_handler, serve

SPA_SHELL = "<!doctype html><title>My App</title><div id=app>loading…</div>"
REAL_LISTING = (
    "<html><head><title>Index of /uploads</title></head><body>"
    "<h1>Index of /uploads</h1><pre>"
    '<a href="../">Parent Directory</a>\n'
    '<a href="db_backup.sql">db_backup.sql</a>   14K'
    "</pre></body></html>"
)


def test_spa_200_everywhere_is_not_a_listing():
    """Every path returns the SPA shell with 200 -> must PASS, not flag."""
    handler = make_handler(
        {p: (200, SPA_SHELL) for p in dir_listing_check.COMMON_PATHS},
        default_status=200,
    )
    with serve(handler) as base:
        result = dir_listing_check.run(base)
    assert result["status"] == "pass", result["detail"]


def test_real_listing_is_flagged():
    """A genuine 'Index of /uploads' body -> FAIL naming that path."""
    routes = {"/uploads/": (200, REAL_LISTING)}
    with serve(make_handler(routes)) as base:
        result = dir_listing_check.run(base)
    assert result["status"] == "fail"
    assert "/uploads/" in result["detail"]


def test_403_forbidden_is_not_a_listing():
    """A 403 on the path is access control working, not exposure."""
    routes = {p: (403, "Forbidden") for p in dir_listing_check.COMMON_PATHS}
    with serve(make_handler(routes)) as base:
        result = dir_listing_check.run(base)
    assert result["status"] == "pass"


def test_dead_target_raises_not_pass(dead_url):
    """Nothing reachable -> raise, never a clean 'no listings found'."""
    with pytest.raises(TargetUnreachable):
        dir_listing_check.run(dead_url)
