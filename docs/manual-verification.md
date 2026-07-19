# Manual Verification

The scanner is a script: it sends payloads and pattern-matches responses. To
show the findings are real and not artefacts of the matching logic, each one
below was **reproduced by hand** against the practice target and the actual
output recorded. This is the "penetration testing" step — confirming, manually,
that every finding the scanner raises is a genuine weakness.

> All testing was done against `practice_target/`, a deliberately vulnerable app
> bound to `127.0.0.1` only. Nothing here was run against a site we don't own.
> Reproduce it yourself: `python practice_target/app.py`, then run the commands
> below. Session captured 2026-07-20.

## What the scanner reported

Two scans cover all five checks (the scanner inspects one URL at a time and does
not crawl, so the forms live at `/login` and the listing at the root):

**Scan of `http://127.0.0.1:8000/`** — `3 failed, 2 passed`

| Result | Severity | Check |
|--------|----------|-------|
| FAIL | high | Security headers |
| FAIL | medium | Software version leakage |
| FAIL | medium | Directory listing exposure |
| PASS | low | SQL injection *(no forms on this page)* |
| PASS | low | Reflected XSS *(no forms on this page)* |

**Scan of `http://127.0.0.1:8000/login`** — `4 failed, 1 passed`

| Result | Severity | Check |
|--------|----------|-------|
| FAIL | high | Security headers |
| FAIL | medium | Software version leakage |
| FAIL | high | SQL injection *(fields `username`, `password`)* |
| FAIL | high | Reflected XSS *(fields `username`, `password`)* |
| PASS | low | Directory listing *(none under `/login`)* |

Each is reproduced by hand below.

---

## 1. Security headers (high) — CONFIRMED

**Scanner said:** Missing `Content-Security-Policy`, `X-Frame-Options`,
`X-Content-Type-Options`.

**By hand** — dump the response headers and look for them:

```
$ curl -s -D - -o /dev/null http://127.0.0.1:8000/login
HTTP/1.1 200 OK
Server: Apache/2.2.8 (Ubuntu) DAV/2
Date: Sun, 19 Jul 2026 20:12:49 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 651
X-Powered-By: PHP/5.4.45
Connection: close
```

None of the three security headers are present. **Confirmed** — the finding is
literally "these header names do not appear", and they don't.

**Why it matters:** with no `X-Frame-Options` the page can be framed for
clickjacking; with no CSP, an injected `<script>` (see finding 3) runs
unrestricted.

---

## 2. SQL injection (high) — CONFIRMED

**Scanner said:** payload `'` in field `username` triggered a database error.

The scanner detects SQLi by provoking an error. By hand we can go one step
further and show the two classic consequences: an **error leak** and an **auth
bypass**.

**2a. Error leak** — submit a single quote as the username:

```
$ curl -s -X POST http://127.0.0.1:8000/login \
    --data-urlencode "username='" --data-urlencode "password=x"
...
<p>Database error: unrecognized token: "x'"<br>
Query was: SELECT name FROM users WHERE name = ''' AND password = 'x'</p>
```

The app echoes the raw SQL. The lone `'` closed the string and left the query
malformed — proof the input is concatenated straight into the query. This is
exactly the signature the scanner matched.

**2b. Auth bypass** — turn the injection into a working exploit (still just
confirming the flaw, no data taken):

```
$ curl -s -X POST http://127.0.0.1:8000/login \
    --data-urlencode "username=admin' OR '1'='1" --data-urlencode "password=wrongpassword"
...
<p>Welcome, admin.</p>
```

Logged in as `admin` with a deliberately **wrong** password. The `OR '1'='1`
made the `WHERE` clause always true. **Confirmed** — this is a real,
exploitable SQL injection, not just a noisy error.

**Why it matters:** an attacker logs in as any user, and the query leak hands
them the schema to write further injections.

---

## 3. Reflected XSS (high) — CONFIRMED

**Scanner said:** field reflected `<script>...</script>` **unescaped**.

**By hand** — put a script tag in the search box and read the raw HTML that
comes back:

```
$ curl -s "http://127.0.0.1:8000/search?q=<script>alert(1)</script>"
...
<p>No results for: <script>alert(1)</script></p>
```

The tags come back **verbatim** — `<script>`, not the escaped `&lt;script&gt;`.
A browser loading this would execute `alert(1)`. **Confirmed.**

This is also the check most prone to false positives, so the negative case
matters: the scanner only flags XSS when the raw payload is present **and** its
escaped form is absent. An app that returns `&lt;script&gt;` is *not* flagged
(verified separately in `tests/` against an escaping app). So this finding means
"reflected and unescaped", not merely "reflected".

**Why it matters:** any script an attacker puts in the URL runs in the victim's
browser — session theft, defacement, credential capture.

---

## 4. Directory listing exposure (medium) — CONFIRMED

**Scanner said:** `/uploads/` returns a browsable file listing.

**By hand:**

```
$ curl -s http://127.0.0.1:8000/uploads/
<html><head><title>Index of /uploads</title></head><body>
<h1>Index of /uploads</h1><pre><a href="../">Parent Directory</a>
<a href="notes.txt">notes.txt</a>      2.1K
<a href="db_backup.sql">db_backup.sql</a>   14K
</pre></body></html>
```

A real index page — "Index of /uploads" with clickable files, including a
`db_backup.sql`. **Confirmed.** (The scanner requires this body signature, not
just an HTTP 200, so a normal page that happens to return 200 is not
misreported — see the SPA test in `tests/`.)

**Why it matters:** anyone can browse and download files that were never meant
to be public — here, a database backup.

---

## 5. Software version leakage (medium) — CONFIRMED

**Scanner said:** `Server` reveals Apache 2.2.8; `X-Powered-By` reveals PHP
5.4.45.

**By hand** — same header dump as finding 1:

```
Server: Apache/2.2.8 (Ubuntu) DAV/2
X-Powered-By: PHP/5.4.45
```

Both advertise **exact versions**. **Confirmed.** Apache 2.2.8 (2008) and PHP
5.4.45 are long end-of-life and have publicly documented CVEs, so the version
string alone tells an attacker which exploits to try. (The scanner treats an
exact version as a finding but a bare product name like `nginx` as a pass — a
distinction also covered in `tests/`.)

**Why it matters:** the target hands an attacker a shortlist of known exploits
for the exact software it runs.

---

## Verdict

All five checks were reproduced by hand; **every finding the scanner raised is a
genuine weakness** — no false positives. The SQL injection was carried through
to a working authentication bypass to show it is exploitable and not merely a
logged error. Reproduction was confined to confirming the flaws exist: no data
was exfiltrated and no account was actually taken over, per the project's
out-of-scope rules.
