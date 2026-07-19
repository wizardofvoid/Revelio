"""Whole-scan behaviour via run_all_checks / summarise.

The rule being protected: a target that is completely down must produce *error*
findings, never a clean 'pass'. A scanner that reports a healthy target having
reached nothing is worse than useless.
"""

from scanner import run_all_checks, summarise
from tests.targets import make_handler, serve

# A minimal target with no forms, no security headers, no version banner.
BARE_PAGE = "<!doctype html><title>Bare</title><p>nothing here</p>"


def test_dead_target_errors_never_passes(dead_url):
    results = run_all_checks(dead_url)
    summary = summarise(results)
    # Every check should have errored; none should claim a clean pass.
    assert summary["errored"] == summary["total"]
    assert summary["passed"] == 0
    assert all(r["status"] == "error" for r in results)


def test_summarise_counts_add_up():
    with serve(make_handler({"/": (200, BARE_PAGE)}, default_status=200)) as base:
        results = run_all_checks(base)
    summary = summarise(results)
    assert summary["total"] == len(results)
    assert summary["passed"] + summary["failed"] + summary["errored"] == summary["total"]


def test_every_finding_has_the_required_shape():
    """Contract check: each finding carries name/status/severity/detail/risk/fix."""
    with serve(make_handler({"/": (200, BARE_PAGE)}, default_status=200)) as base:
        results = run_all_checks(base)
    required = {"name", "status", "severity", "detail", "risk", "fix"}
    for r in results:
        assert required <= set(r), f"missing keys in {r.get('name')}"
        assert r["status"] in {"pass", "fail", "error"}
        assert r["severity"] in {"low", "medium", "high"}
