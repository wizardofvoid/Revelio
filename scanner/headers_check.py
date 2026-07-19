"""Check 1: presence and sanity of common security response headers."""

from urllib.parse import urlparse

from scanner import http

CHECK_NAME = "Security headers"

# Header -> (severity if missing, what it protects against, how to set it)
REQUIRED_HEADERS = {
    "Content-Security-Policy": (
        "high",
        "controls which scripts the browser will run",
        "Content-Security-Policy: default-src 'self'",
    ),
    "Strict-Transport-Security": (
        "medium",
        "forces browsers to use https",
        "Strict-Transport-Security: max-age=31536000",
    ),
    "X-Frame-Options": (
        "medium",
        "stops the page being framed by an attacker (clickjacking)",
        "X-Frame-Options: SAMEORIGIN",
    ),
    "X-Content-Type-Options": (
        "low",
        "stops the browser guessing file types",
        "X-Content-Type-Options: nosniff",
    ),
}

# Headers that are only meaningful with a specific value.
EXPECTED_VALUES = {
    "X-Content-Type-Options": ["nosniff"],
    "X-Frame-Options": ["deny", "sameorigin"],
}

SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


def _worst(severities):
    return sorted(severities, key=lambda s: SEVERITY_RANK[s])[0]


def run(target_url):
    response = http.get(target_url)
    headers = response.headers
    over_https = urlparse(response.url).scheme == "https"

    missing, weak, present = [], [], []

    for header, (severity, _purpose, _fix) in REQUIRED_HEADERS.items():
        # HSTS is ignored by browsers when served over plain http, so flagging
        # it on an http target would be noise the reader can't act on.
        if header == "Strict-Transport-Security" and not over_https:
            continue

        value = headers.get(header)
        if value is None:
            missing.append((header, severity))
            continue

        allowed = EXPECTED_VALUES.get(header)
        if allowed and value.strip().lower() not in allowed:
            weak.append((header, value.strip(), severity))
        else:
            present.append(header)

    if not missing and not weak:
        detail = f"All expected headers present: {', '.join(present)}."
        if not over_https:
            detail += (
                " Strict-Transport-Security was not checked because the target "
                "is served over http, where browsers ignore it."
            )
        return {
            "name": CHECK_NAME,
            "status": "pass",
            "severity": "low",
            "detail": detail,
            "risk": "No issue found — the browser's built-in protections are switched on.",
            "fix": "No action needed.",
        }

    parts = []
    if missing:
        parts.append(
            "Missing: "
            + ", ".join(
                f"{h} ({REQUIRED_HEADERS[h][1]})" for h, _ in missing
            )
            + "."
        )
    if weak:
        parts.append(
            "Set but not effective: "
            + ", ".join(f"{h} is '{v}'" for h, v, _ in weak)
            + "."
        )
    if present:
        parts.append(f"Correctly set: {', '.join(present)}.")

    severity = _worst([s for _, s in missing] + [s for _, _, s in weak])
    fixes = [REQUIRED_HEADERS[h][2] for h, _ in missing]
    fixes += [REQUIRED_HEADERS[h][2] for h, _, _ in weak]

    return {
        "name": CHECK_NAME,
        "status": "fail",
        "severity": severity,
        "detail": " ".join(parts),
        "risk": "Without these headers the browser drops protections that would "
        "otherwise blunt script injection and clickjacking attacks.",
        "fix": "Add in your web server or framework config: " + "; ".join(fixes) + ".",
    }
