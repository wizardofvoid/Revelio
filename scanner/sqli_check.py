"""Check 2: basic SQL injection against forms found on the page.

Strategy: for each text field on each form, submit a payload that would break
malformed SQL and look for a database error surfacing in the response. This is
the highest-signal, lowest-false-positive tell -- an app echoing a raw SQL
error is almost always building queries by string concatenation.
"""

import re

from scanner import forms
from scanner.http import TargetUnreachable

CHECK_NAME = "SQL injection (basic)"

SQLI_PAYLOADS = [
    "'",             # simplest: an unbalanced quote breaks concatenated SQL
    "' OR '1'='1",
    "'--",
    "1' ORDER BY 99--",
]

# Database error signatures, as compiled regexes so we can be specific.
# Covers MySQL, Oracle, SQL Server, PostgreSQL AND SQLite -- the practice
# target is SQLite, and its errors matched NONE of the original list.
SQL_ERROR_SIGNATURES = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"SQL syntax",
        r"mysql_fetch",
        r"you have an error in your sql",
        r"ORA-\d{5}",
        r"unterminated quoted string",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"pg_query\(\)",
        r"SQLite3?::",
        r"unrecognized token",          # SQLite
        r"near \".*\": syntax error",   # SQLite
        r"sqlite3\.\w+error",           # Python sqlite3 driver
    ]
]


def _error_in(text):
    for sig in SQL_ERROR_SIGNATURES:
        m = sig.search(text)
        if m:
            return m.group(0)
    return None


def run(target_url):
    all_forms = forms.parse_forms(target_url)
    if not all_forms:
        return {
            "name": CHECK_NAME,
            "status": "pass",
            "severity": "low",
            "detail": "No forms with text inputs were found on the page, so there "
            "was nothing to test for SQL injection here.",
            "risk": "No issue found on this page. Note: forms behind a login or "
            "built by JavaScript won't be seen by this scanner.",
            "fix": "No action needed.",
        }

    hits = []          # (action, field, payload, matched error text)
    tested_fields = 0

    for form in all_forms:
        for field in form["texty_names"]:
            tested_fields += 1
            for payload in SQLI_PAYLOADS:
                try:
                    resp = forms.submit(form, field, payload)
                except TargetUnreachable:
                    continue  # a single failed submit shouldn't sink the check
                found = _error_in(resp.text)
                if found:
                    hits.append((form["action"], field, payload, found))
                    break  # this field is proven; move to the next

    if hits:
        listed = "; ".join(
            f"field '{field}' at {action} (payload {payload!r} triggered "
            f"database error {err!r})"
            for action, field, payload, err in hits
        )
        return {
            "name": CHECK_NAME,
            "status": "fail",
            "severity": "high",
            "detail": f"SQL injection likely in {len(hits)} field(s): {listed}.",
            "risk": "An attacker could read or change database contents by typing "
            "special characters into a form.",
            "fix": "Use parameterised queries (prepared statements) instead of "
            "building SQL by joining strings, and don't show database errors to users.",
        }

    return {
        "name": CHECK_NAME,
        "status": "pass",
        "severity": "low",
        "detail": f"Submitted {len(SQLI_PAYLOADS)} payloads to {tested_fields} text "
        f"field(s) across {len(all_forms)} form(s); no database errors surfaced.",
        "risk": "No error-based SQL injection found. This is a basic check and "
        "doesn't rule out blind or filtered injection.",
        "fix": "No action needed for the cases tested; keep using parameterised queries.",
    }
