"""Check 4: directory listing exposed at common paths."""

from scanner import http
from scanner.severity import worst

CHECK_NAME = "Directory listing exposure"

# Path -> severity if it turns out to be browsable.
COMMON_PATHS = {
    "/admin/": "medium",
    "/backup/": "high",
    "/uploads/": "medium",
    "/files/": "medium",
    "/images/": "low",
    "/.git/": "high",
}

# A 200 alone is not enough: plenty of apps return 200 for every path, and a
# SPA returns its shell for anything. The body has to actually look like a
# listing before we call it exposed.
LISTING_SIGNATURES = [
    "index of /",
    "<title>directory listing",
    "parent directory",
    "[to parent directory]",  # IIS
]

MAX_BODY = 4096  # signatures all appear near the top; don't scan whole files


def run(target_url):
    exposed = []
    unreachable = 0

    for path, severity in COMMON_PATHS.items():
        url = http.join(target_url, path)
        try:
            # No redirect following: a 302 to a login page is access control
            # working, not an exposed listing.
            response = http.get(url, allow_redirects=False)
        except http.TargetUnreachable:
            unreachable += 1
            continue

        if response.status_code != 200:
            continue

        body = response.text[:MAX_BODY].lower()
        if any(sig in body for sig in LISTING_SIGNATURES):
            exposed.append((path, severity))

    # If nothing at all was reachable the target is down, and "no listings
    # found" would be a lie -- we'd be reporting a clean pass having tested
    # nothing. Escalate to run_all_checks, which records it as an error.
    if unreachable == len(COMMON_PATHS):
        raise http.TargetUnreachable(
            f"None of the {unreachable} common paths on {target_url} could be "
            "reached. Is the target actually running?"
        )

    if exposed:
        severity = worst([s for _, s in exposed])
        paths = ", ".join(p for p, _ in exposed)
        return {
            "name": CHECK_NAME,
            "status": "fail",
            "severity": severity,
            "detail": f"These paths return a browsable file listing: {paths}.",
            "risk": "Anyone can browse and download files here, including ones "
            "that were never meant to be public.",
            "fix": "Turn off automatic directory indexes (Apache: Options -Indexes; "
            "nginx: autoindex off) and restrict access to these paths.",
        }

    checked = len(COMMON_PATHS) - unreachable
    # Name the base actually probed: for a page-level target like /login these
    # paths are resolved against the directory it sits in, not below the page.
    detail = (
        f"Checked {checked} common paths under {http.join(target_url, '/')} "
        f"({', '.join(COMMON_PATHS)}); none returned a file listing."
    )
    if unreachable:
        detail += f" {unreachable} path(s) could not be reached."

    return {
        "name": CHECK_NAME,
        "status": "pass",
        "severity": "low",
        "detail": detail,
        "risk": "No issue found — these directories aren't browsable.",
        "fix": "No action needed.",
    }
