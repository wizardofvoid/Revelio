# Lightweight Web Vulnerability Scanner

Paste a URL, click **Scan**, get a severity-rated report of five common
security misconfigurations. The report can also be downloaded as a
standalone HTML file.

> **Only scan targets you own or that exist for testing** (DVWA, OWASP Juice
> Shop) running locally. This tool sends real attack payloads. Never point it
> at a site you don't have permission to test.

## Setup

Install into a virtual environment, not globally:

```
python -m venv .venv
.venv\Scripts\activate          # Windows;  source .venv/bin/activate on macOS/Linux
pip install -r requirements.txt
python app.py
```

Then open <http://localhost:5000>. The dev server binds to `127.0.0.1` only;
set `SCANNER_DEBUG=0` to run it without the Werkzeug debugger.

A practice target needs to be running separately. This repo ships a small
deliberately-vulnerable app for exactly that — no Docker or npm needed:

```
python practice_target/app.py    # http://127.0.0.1:8000
```

Then scan `http://127.0.0.1:8000/login`, which trips all five checks. See
`practice_target/README.md` for what's vulnerable and why the usual suspects
(Juice Shop, DVWA) aren't used here.

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

45 tests, ~47s (two of them make real refused connections to prove a dead target
errors rather than passing; on Windows each takes ~2s to give up — not a hang).

The suite (in `tests/`) spins up throwaway `http.server` targets and checks the
cases that actually caught bugs: an SPA returning 200 for every path (must
**not** be reported as a directory listing), a completely-down target (must
error, never a clean pass), a security header set to a useless value, the XSS
guard in *both* directions (an escaping app must pass, and a vulnerable app must
still be flagged even when the page also echoes an escaped copy), probe paths
resolving against the site root rather than below a page, `/export` surviving
malformed input, and the exact-version-vs-bare-name distinction.

## Manual verification

`docs/manual-verification.md` reproduces all five findings by hand against the
practice target (including carrying the SQL injection through to a working auth
bypass) — the "penetration testing" step that confirms the scanner's findings
are real, not artefacts of the matching logic.

## Known limits

The report says this too, but so it's clear up front — the scanner tests **one
URL**, the one you give it. It does not crawl, cannot log in, and cannot see
forms built by JavaScript. SQL injection is detected only when the app leaks a
database error (not blind or filtered injection), and only *reflected* XSS is
tested, not stored or DOM-based. A PASS means "not found on this URL", never
"this site is secure".

## Status

**Complete.** All five checks send real requests; the form → scan → report →
download flow works; scanning `practice_target/login` reports 5 failures out of
5, and an escaped/safe app is correctly reported clean. Covered by an automated
test suite (`tests/`, 45 tests) and a by-hand verification writeup
(`docs/manual-verification.md`).
