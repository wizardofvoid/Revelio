"""Check 5: software version strings leaked in response headers."""

import re

from scanner import http

CHECK_NAME = "Software version leakage"

VERSION_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

# Matches "Apache/2.2.3", "PHP/8.1", "nginx/1.18.0" -- a product name followed
# by at least one dotted number. Bare "nginx" deliberately does not match.
VERSION_PATTERN = re.compile(r"([A-Za-z][\w+.-]*)/(\d+(?:\.\d+)+)")

# Some headers are a version on their own, with no product prefix.
BARE_VERSION_HEADERS = {"X-AspNet-Version"}
BARE_VERSION_PATTERN = re.compile(r"^\d+(?:\.\d+)+$")


def run(target_url):
    headers = http.get(target_url).headers

    versioned = []  # exact versions -- the actionable finding
    named = []      # product name only -- minor leak

    for header in VERSION_HEADERS:
        value = headers.get(header)
        if not value:
            continue

        found = VERSION_PATTERN.findall(value)
        if header in BARE_VERSION_HEADERS and BARE_VERSION_PATTERN.match(value.strip()):
            found = [(header, value.strip())]

        if found:
            versioned += [(header, f"{p} {v}".strip()) for p, v in found]
        else:
            named.append((header, value.strip()))

    if versioned:
        listed = "; ".join(f"{h} reveals {what}" for h, what in versioned)
        return {
            "name": CHECK_NAME,
            "status": "fail",
            "severity": "medium",
            "detail": f"Exact software versions are being advertised: {listed}.",
            "risk": "Publishing an exact version tells an attacker which known "
            "exploits to try first, with no guesswork.",
            "fix": "Turn off version banners (Apache: ServerTokens Prod; "
            "nginx: server_tokens off; PHP: expose_php Off).",
        }

    if named:
        listed = "; ".join(f"{h}: {v}" for h, v in named)
        return {
            "name": CHECK_NAME,
            "status": "pass",
            "severity": "low",
            "detail": f"Software is named but no version number is given ({listed}). "
            "This is a minor leak, not a finding.",
            "risk": "Naming the software narrows an attacker's search slightly, "
            "but without a version it isn't directly actionable.",
            "fix": "Optional: remove the header entirely to give away nothing.",
        }

    return {
        "name": CHECK_NAME,
        "status": "pass",
        "severity": "low",
        "detail": f"No version information found in {', '.join(VERSION_HEADERS)}.",
        "risk": "No issue found — the server isn't advertising what it runs.",
        "fix": "No action needed.",
    }
