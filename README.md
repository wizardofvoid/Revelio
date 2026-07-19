# Lightweight Web Vulnerability Scanner

Paste a URL, click **Scan**, get a severity-rated report of five common
security misconfigurations. The report can also be downloaded as a
standalone HTML file.

> **Only scan targets you own or that exist for testing** (DVWA, OWASP Juice
> Shop) running locally. This tool sends real attack payloads. Never point it
> at a site you don't have permission to test.

## Setup

```
pip install -r requirements.txt
python app.py
```

Then open <http://localhost:5000>.

A practice target needs to be running separately. This repo ships a small
deliberately-vulnerable app for exactly that — no Docker or npm needed:

```
python practice_target/app.py    # http://127.0.0.1:8000
```

Then scan `http://127.0.0.1:8000` (and `http://127.0.0.1:8000/login` for the
form-based checks). See `practice_target/README.md` for what's vulnerable and
why the usual suspects (Juice Shop, DVWA) aren't used here.

## The five checks

| # | Check | Module |
|---|-------|--------|
| 1 | Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) | `scanner/headers_check.py` |
| 2 | SQL injection on forms | `scanner/sqli_check.py` |
| 3 | Reflected XSS on forms | `scanner/xss_check.py` |
| 4 | Directory listing exposure | `scanner/dir_listing_check.py` |
| 5 | Software version leakage in headers | `scanner/version_check.py` |

## Adding or changing a check

Each module exposes one function, `run(target_url) -> dict`, returning:

```python
{
    "name":     "Security headers",
    "status":   "pass" | "fail" | "error",
    "severity": "low" | "medium" | "high",
    "detail":   "what was actually found",
    "risk":     "one line on why it matters, no jargon",
    "fix":      "one line on how to fix it",
}
```

Register it in `CHECKS` in `scanner/__init__.py`. Keep payload and signature
lists as module-level constants at the top of the file so they're easy to
extend.

A check may raise freely — `run_all_checks` catches exceptions per check and
records a `"error"` finding, so one broken check never fails the whole scan.

## Tests

```
pip install -r requirements-dev.txt
python -m pytest
```

The suite (in `tests/`) spins up throwaway `http.server` targets and checks the
cases that actually caught bugs during development: an SPA returning 200 for
every path (must **not** be reported as a directory listing), a completely-down
target (must error, never a clean pass), a security header set to a useless
value, the XSS false-positive guard against an escaping app, and the
exact-version-vs-bare-name distinction.

## Manual verification

`docs/manual-verification.md` reproduces all five findings by hand against the
practice target (including carrying the SQL injection through to a working auth
bypass) — the "penetration testing" step that confirms the scanner's findings
are real, not artefacts of the matching logic.

## Status

**Complete.** All five checks send real requests; the form → scan → report →
download flow works; the scanner finds real vulnerabilities in
`practice_target/` and correctly reports an escaped/safe app clean. Covered by
an automated test suite (`tests/`) and a by-hand verification writeup
(`docs/manual-verification.md`).
