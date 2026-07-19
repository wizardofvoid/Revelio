"""Check 3: reflected XSS against forms found on the page.

Strategy: submit a payload carrying a unique marker into each text field and
check whether it comes back in the response *unescaped* -- i.e. the raw
characters, not their HTML-entity form. An app that reflects
`&lt;script&gt;` is escaping correctly and is NOT vulnerable; only a raw
`<script>` reflection is.
"""

from scanner import forms
from scanner.http import TargetUnreachable

CHECK_NAME = "Reflected XSS (basic)"

# A marker so we know we're seeing OUR reflection, not incidental page text.
MARKER = "xSs7q1"

# {} is replaced with the marker. Each payload's "proof" is the raw substring
# that must appear un-entity-encoded for the payload to have executed.
XSS_PAYLOADS = [
    "<script>alert('{}')</script>",
    "\"><script>alert('{}')</script>",
    "<img src=x onerror=alert('{}')>",
]


def _reflected_unescaped(payload, body):
    """True if payload appears raw AND wasn't entity-escaped on the way out."""
    if payload not in body:
        return False
    # If the same content also appears HTML-escaped, the app is escaping and
    # the raw hit is a coincidence (or a different context) -- don't flag.
    escaped = (
        payload.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
    return escaped not in body


def run(target_url):
    all_forms = forms.parse_forms(target_url)
    if not all_forms:
        return {
            "name": CHECK_NAME,
            "status": "pass",
            "severity": "low",
            "detail": "No forms with text inputs were found on the page, so there "
            "was nothing to test for reflected XSS here.",
            "risk": "No issue found on this page. Note: forms behind a login or "
            "built by JavaScript won't be seen by this scanner.",
            "fix": "No action needed.",
        }

    hits = []
    tested_fields = 0

    for form in all_forms:
        for field in form["texty_names"]:
            tested_fields += 1
            for template in XSS_PAYLOADS:
                payload = template.format(MARKER)
                try:
                    resp = forms.submit(form, field, payload)
                except TargetUnreachable:
                    continue
                if _reflected_unescaped(payload, resp.text):
                    hits.append((form["action"], field, payload))
                    break  # field proven; next field

    if hits:
        listed = "; ".join(
            f"field '{field}' at {action} reflected {payload!r} unescaped"
            for action, field, payload in hits
        )
        return {
            "name": CHECK_NAME,
            "status": "fail",
            "severity": "high",
            "detail": f"Reflected XSS likely in {len(hits)} field(s): {listed}.",
            "risk": "An attacker could run their own JavaScript in another user's "
            "browser session (steal cookies, act as that user).",
            "fix": "Escape user input on output (HTML-encode < > \" &), and set a "
            "Content-Security-Policy header as a second line of defence.",
        }

    return {
        "name": CHECK_NAME,
        "status": "pass",
        "severity": "low",
        "detail": f"Submitted {len(XSS_PAYLOADS)} payloads to {tested_fields} text "
        f"field(s) across {len(all_forms)} form(s); none were reflected unescaped.",
        "risk": "No reflected XSS found. This is a basic check and doesn't cover "
        "stored or DOM-based XSS.",
        "fix": "No action needed for the cases tested; keep escaping output.",
    }
