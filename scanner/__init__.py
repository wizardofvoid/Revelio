"""Scanner package.

`run_all_checks` is the single place that knows which checks exist and is the
only place that handles check failures -- individual check modules can raise
freely and the scan still completes with a "check failed to run" result.
"""

from scanner import (
    dir_listing_check,
    forms,
    headers_check,
    http,
    sqli_check,
    version_check,
    xss_check,
)

# Order here is the order findings appear in the report.
CHECKS = [
    headers_check,
    version_check,
    dir_listing_check,
    sqli_check,
    xss_check,
]


def run_all_checks(target_url):
    """Run every check against target_url and return a list of finding dicts.

    Each finding has: name, status (pass/fail/error), severity (low/medium/high),
    detail, risk, fix.
    """
    # Both are module-level and outlive a single scan, so clear them here rather
    # than leaking cookies and a stale form list into the next one.
    http.reset_session()
    forms.clear_cache()

    results = []
    for check in CHECKS:
        try:
            results.append(check.run(target_url))
        except Exception as exc:  # noqa: BLE001 - a broken check must not kill the scan
            results.append(
                {
                    "name": getattr(check, "CHECK_NAME", check.__name__),
                    "status": "error",
                    "severity": "low",
                    "detail": f"Check failed to run: {type(exc).__name__}: {exc}",
                    "risk": "This check could not complete, so the target may still "
                    "be vulnerable in this area.",
                    "fix": "Confirm the target URL is reachable, then re-run the scan.",
                }
            )
    return results


def summarise(results):
    """Counts for the report header."""
    # .get() rather than [] -- /export re-summarises findings posted back from
    # the browser, and a hand-edited payload must not turn into a 500.
    return {
        "total": len(results),
        "failed": sum(1 for r in results if r.get("status") == "fail"),
        "passed": sum(1 for r in results if r.get("status") == "pass"),
        "errored": sum(1 for r in results if r.get("status") == "error"),
    }
