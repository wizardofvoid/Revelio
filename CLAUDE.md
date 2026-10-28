# Project: Lightweight Web Vulnerability Scanner

## Overview
A web-based tool that scans a target URL for common, well-documented security
misconfigurations and displays a severity-rated report. User pastes a URL into
a simple web page, clicks "Scan", and sees results on the page. Report can
also be saved as a standalone HTML file. This is a scoped-down, rule-based
version of the SQLShield-LLM idea (D5.1) — no ML model, direct payload +
response pattern matching instead.

**Only scan targets you own or that are explicitly built for testing**
(e.g. DVWA, OWASP Juice Shop) running locally. Never point this at a real
website you don't have permission to test.

## Tech stack
- Backend: Python 3.11+, Flask
- HTTP requests to target: `requests` library
- HTML parsing (finding forms/inputs): `beautifulsoup4`
- Frontend: plain HTML + CSS + minimal JS (no framework needed — keep it simple)
- Report rendering: Flask's `render_template` (Jinja2), same template reused
  for on-page display and the saved HTML report

## Environment / commands
- **Use the venv.** `.venv/` now exists and is gitignored; everything below
  assumes it. Never `pip install` into the global environment — doing so once
  downgraded `requests` and broke unrelated packages (`langchain-community`,
  `prawcore`). Recreate with `python -m venv .venv` if it's missing.
- Install deps: `.venv/Scripts/python -m pip install -r requirements-dev.txt`
  (that pulls in `requirements.txt` too; drop the `-dev` for runtime only)
- Run dev server: `.venv/Scripts/python app.py` (serves on `http://localhost:5000`).
  Set `SCANNER_DEBUG=0` to run without the Werkzeug debugger.
- Run a practice target separately before scanning: `python practice_target/app.py`
  (serves on `http://127.0.0.1:8000`). See `practice_target/README.md`.
- **`npx juice-shop` does not work** — the npm package was unpublished in 2019.
  Juice Shop is now Docker/GitHub-release only, and being an Angular SPA its
  forms are built client-side, so a `requests` + BeautifulSoup scanner can't
  see them at all. DVWA needs Docker (not installed here) and puts its
  vulnerable pages behind a session login this scanner can't authenticate to.
- Requirements are pinned with `>=`, not `==`, so the scanner doesn't fight
  whatever else is installed

## Project structure
```
/
├── app.py                 # Flask routes: GET / (form), POST /scan, POST /export
├── scanner/
│   ├── __init__.py        # CHECKS registry + run_all_checks() + summarise()
│   ├── http.py            # shared Session: get/post, timeout, TargetUnreachable, join()
│   ├── severity.py        # ORDER + worst(); the one place severities are ranked
│   ├── forms.py           # BeautifulSoup form parsing + submit(), shared by sqli/xss
│   ├── headers_check.py   # missing/misconfigured security headers
│   ├── sqli_check.py      # basic SQL injection payload testing on forms
│   ├── xss_check.py       # basic reflected XSS payload testing on forms
│   ├── dir_listing_check.py  # checks common paths for exposed directory listing
│   └── version_check.py   # flags outdated software versions in headers
├── templates/
│   ├── index.html         # URL input form
│   └── report.html        # scan results, reused for on-page view and saved export
├── static/
│   └── style.css
├── tests/                 # pytest suite (45 tests); conftest.py resets shared state
├── docs/manual-verification.md   # findings reproduced by hand
├── requirements.txt       # runtime deps only
├── requirements-dev.txt   # adds pytest
└── README.md
```

## The five checks (what "scanning" means here)
1. **Security headers** — request the target, check for presence of
   `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
   `Strict-Transport-Security`. Missing = flagged, with severity based on
   which header is missing.
2. **SQL injection (basic)** — find all `<form>` elements, submit each text
   input with a small list of known payloads (e.g. `' OR '1'='1`, `'--`),
   check response for database error signatures (e.g. "SQL syntax", "mysql_fetch").
3. **Reflected XSS (basic)** — submit a payload like `<script>alert(1)</script>`
   into each input, check if it comes back unescaped in the response HTML.
4. **Directory listing exposure** — request a list of common paths
   (`/admin/`, `/backup/`, `/uploads/`) and check if the response looks like
   an index/listing page rather than a 403/404.
5. **Outdated software version leakage** — check `Server` and `X-Powered-By`
   response headers for version strings (e.g. `Apache/2.2.3`) that indicate
   a specific, checkable software version.

Each check returns:
`{name, status: pass/fail/error, severity: low/medium/high, detail, risk, fix}`.

`risk` and `fix` are the one-liners the report shows (see below) — they live on
the check because only the check knows *which* header or payload tripped.
`error` is set by `run_all_checks`, never by a check itself.

A check reports one dict even when it finds several problems (e.g. three
vulnerable forms): `detail` lists them and `severity` is the worst of them.
This keeps the report one row per check.

## Report contents
For each finding: what was checked, pass/fail, severity, one-line explanation
of the risk, one-line suggested fix. No jargon dump — a non-security reader
should understand each line.

## Manual verification step (for the "penetration testing" requirement)
After the scanner runs, manually reproduce 3-5 of its findings by hand
(e.g. actually typing the SQLi payload into the login form yourself and
confirming the error appears). Document this in the final report/writeup —
this is what makes it more than "just running a script."

## Out of scope (don't build these — keep it simple)
- No AI/ML/LLM component
- No authentication/login system for the tool itself
- No scanning of live/real-world websites — local practice targets only
- No attempt to exploit findings beyond confirming they exist (no data
  exfiltration, no actual account takeover, etc.)

## Suggested team split
- Person A: `app.py` Flask routes + `scanner/` request-sending logic
  (headers, dir listing, version checks — these are simpler, request/response only)
- Person B: SQLi + XSS checks (need form-parsing logic) + `report.html` template

## Milestone plan (3-4 weeks)
- **Week 1 — DONE (skeleton).** Flask skeleton with form → report → download
  working end to end on stub checks. Report styling and export were pulled
  forward from Week 4 since the template had to exist anyway. Still to do:
  set up DVWA/Juice Shop locally.
- **Week 2 — DONE.** Headers, version and dir-listing checks. Real requests, tested.
- **Week 3 — DONE.** SQLi and XSS checks over `scanner/forms.py`. Tested against
  the vulnerable practice target *and* an escaped/safe app (no false positives).
- **Week 4 — DONE.** Manual verification writeup (`docs/manual-verification.md`),
  automated pytest suite (`tests/`), final polish (README setup section fixed).
  Project is complete.

## Current status
**Project complete — all four weeks done, plus a bug-fix pass.** All five checks
send real requests and work. Scanning `http://127.0.0.1:8000/login` on the
practice target now produces **five failures out of five** (headers, version,
directory listing, SQLi, XSS). Scanning the root gives 3 failed / 2 passed — the
two passes are honest, that page has no form to test.

The bug-fix pass (see the two bullets about XSS and `join()` below) fixed three
defects, two of which made the scanner report vulnerable things as safe:
- the XSS check passed a genuinely vulnerable app whenever the page also echoed
  an escaped copy of the payload — which most apps do
- `http.join()` built probe paths by concatenation, so a page-level target made
  the directory-listing check look under `/login/admin/` and report nothing found
- `/export` returned HTTP 500 on any malformed payload

Test count went 18 → 45 covering these. Suite runs in a `.venv`.

Week 4 deliverables:
- `docs/manual-verification.md` — all five findings reproduced by hand with real
  captured output (SQLi carried through to an actual auth bypass). This is the
  "penetration testing" requirement.
- `tests/` — pytest suite covering the bug-catching cases (SPA-200-everywhere,
  dead target, useless header value, XSS/SQLi false-positive guards, exact-vs-
  bare version). Started at 18 tests; **now 45** after the bug-fix pass added
  regression cover for `join()`, `/export` and the XSS false negative. Test deps
  are in `requirements-dev.txt` (kept out of the runtime `requirements.txt`).
  ~47s wall time because two dead-target tests make real refused connections
  (Windows drops the SYN, ~2s each) — not a hang.
- README setup section fixed: it told users to run `npx juice-shop` / DVWA-in-
  Docker (neither works here); now points at `practice_target/`.

Everything routes through three shared modules — don't reimplement per check:
- `scanner/http.py` — `get()`/`post()`, 8s timeout, TLS verification off for
  self-signed practice targets, `TargetUnreachable` for readable errors,
  `join()` for probe URLs, and a 2 MB body cap so a huge response can't
  exhaust memory.
- `scanner/severity.py` — `worst()`. Use it rather than re-declaring a rank map.
- `scanner/forms.py` — `parse_forms()` returns each form's absolute action,
  method and text fields; `submit()` fills one field with a payload and the
  rest with placeholders, so a hit points at a specific field. Results are
  cached per URL so SQLi and XSS don't fetch the same page twice;
  `run_all_checks` clears the cache (and the cookie jar) at the start of each
  scan, so nothing carries over between scans.

Nothing is stubbed anymore.

## How the two form checks decide
- **SQLi** submits payloads (starting with a bare `'`) and looks for a database
  error in the response via `SQL_ERROR_SIGNATURES`. That list is now regexes
  and **includes SQLite** (`unrecognized token`, `near "...": syntax error`) —
  the earlier MySQL/Oracle-only list matched nothing the practice target emits.
  Error-based only; blind/filtered injection is out of scope and the pass text
  says so.
- **XSS** requires the payload to come back *unescaped* — i.e. the raw substring
  is present in the response. An app that reflects `&lt;script&gt;` doesn't
  contain the raw `<script>`, so it is NOT flagged; that single substring test
  is the entire false-positive guard. Verified against a Flask app using
  `markupsafe.escape` — correctly passes.
  **Do not re-add an "and the escaped form is absent" condition.** It was there,
  it protected nothing the substring test didn't already cover, and it caused
  false negatives: most apps re-populate the submitted value into the input box
  escaped, so a page reflecting the payload raw *and* echoing an escaped copy
  into its sticky field cancelled itself out and came back PASS. Pinned by
  `tests/test_xss.py::test_raw_reflection_still_flagged_when_page_also_escapes_elsewhere`.

## Testing
`tests/` holds a pytest suite — **45 tests, all green**, ~47s wall time.
Run: `.venv/Scripts/python -m pytest` (deps in `requirements-dev.txt`).

Every test spins up a throwaway `http.server` target on an ephemeral port. The
cases that actually caught bugs:
- a target serving 200 for *every* path (SPA shell), which must **not** be
  reported as a directory listing
- a target that is completely down, which must produce `error` findings and
  never a clean "pass"
- a header present but set to a useless value (`X-Content-Type-Options: sniff`)
- a vulnerable app that reflects a payload raw **and** echoes an escaped copy
  into its own sticky input — must still be flagged (see XSS below)
- a page-level target (`/login`), whose absolute probe paths must resolve to the
  site root, not to `/login/admin/`
- `/export` fed malformed JSON, which must render a report rather than 500

Two notes for anyone adding tests:
- A Flask-based fake target can't spoof the `Server` header — Werkzeug
  overwrites it after `after_request`. Use `http.server` and override
  `version_string()`.
- `conftest.py` has an autouse fixture clearing the form cache and cookie jar
  between tests. Both are module-level state; ephemeral ports get reused, so
  without it a test can be served another test's cached forms.

## Behaviour decided while implementing Phase 1
- **A check that can't reach the target must raise, not return pass.**
  `dir_listing_check` originally counted unreachable paths and still returned
  "no listings found" — a scanner reporting a clean bill of health having
  tested nothing. If everything is unreachable, raise `TargetUnreachable`.
  Apply the same rule to any new check.
- **HSTS is not flagged on http targets.** Browsers ignore it over plain
  http, so flagging it there is noise the reader can't act on.
- **Directory listing needs a body signature, not just a 200.** See above.
- **Version check distinguishes `Apache/2.2.3` from bare `nginx`.** An exact
  version is a medium finding; a product name with no version is a pass with
  a note, not a finding.
- **XSS (Week 3):** check the payload comes back *unescaped* — the raw substring
  present in the body. (This originally also required the escaped form to be
  absent; see "How the two form checks decide" for why that was removed.)
- **Probe paths resolve against the site root, not below the target page.**
  `http.join()` parses the URL: `/login` + `/admin/` is `/admin/`, not
  `/login/admin/`, while a `/dvwa/` mount point is still preserved. It was
  string concatenation, which made the directory-listing check probe paths that
  existed nowhere and report a clean pass — the same "reported healthy having
  tested nothing" failure as the bullet above, in a different check.

## Conventions
- Each check lives in its own file under `scanner/`, exposes one function
  `run(target_url) -> dict` (see shape above), and is registered in `CHECKS`
  in `scanner/__init__.py` — that list is the only place the check set is known
- Keep payload lists as simple Python lists at the top of each check file,
  not hardcoded inline — makes it easy to add more later
- No exception should crash the whole scan. This is handled centrally in
  `run_all_checks`, not per-check: a check may raise freely and it becomes an
  `error` finding. Don't add try/except inside check modules for this.

## Gotchas found the hard way
- `report.html` posts its results back to `/export` as JSON in a hidden field
  so downloading doesn't re-scan (and re-attack) the target. That field needs
  `|tojson|forceescape` — `|tojson` alone returns `Markup`, which autoescaping
  skips, so its quotes break out of the `value="..."` attribute.
- Inlined CSS in the standalone report needs `|safe`, or autoescaping mangles
  selectors like `a > b`.
- `/scan` blocks targets that don't resolve to a loopback/private address
  unless a permission checkbox is ticked. Soft guard, not a hard block, so
  scanning a VM on the LAN still works.
- `/export` is the only route taking arbitrary input, so it trusts none of it.
  `_clean_findings()` in `app.py` drops anything that isn't a well-formed
  finding and defaults unknown status/severity values — otherwise an unknown
  status reaches the template as a CSS class (`finding-banana`), and a
  truncated payload used to be a 500. `summarise()` uses `.get("status")` for
  the same reason.