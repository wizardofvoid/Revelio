# Practice target

A small **deliberately vulnerable** web app, so the scanner has something safe
and legal to point at. It is not part of the scanner.

```
python practice_target/app.py     # http://127.0.0.1:8000
```

Then scan `http://127.0.0.1:8000` from the scanner UI.

> It binds to `127.0.0.1` only and must never be exposed to a network. The
> database is in memory and rebuilt on every start, so it holds no real data.

## What's wrong with it, on purpose

| Page | Vulnerability | Exercises |
|------|---------------|-----------|
| `/login` | SQL built by string concatenation; database errors printed to the page | Check 2 (SQLi) |
| `/search` | `?q=` reflected unescaped (GET form) | Check 3 (XSS) |
| `/feedback` | `comment` reflected unescaped (POST form) | Check 3 (XSS) |
| `/uploads/` | browsable file listing | Check 4 |
| all | no CSP / X-Frame-Options / X-Content-Type-Options | Check 1 |
| all | `Server: Apache/2.2.8`, `X-Powered-By: PHP/5.4.45` | Check 5 |

## Confirmed by hand

Useful for the manual verification writeup — these are real, reproduced with
curl:

- **Auth bypass.** Username `admin' OR '1'='1`, any password → logs in as
  admin.
- **Error leak.** Username `'` → page prints
  `Database error: unrecognized token: "x'"` along with the full query.
- **Reflected XSS.** `/search?q=<script>alert(1)</script>` → the tags come
  back raw in the HTML, not escaped.

## Why not DVWA or Juice Shop

The CLAUDE.md suggests both; neither currently works here.

- **Juice Shop** — `npx juice-shop` no longer exists; the npm package was
  unpublished in 2019. It's now distributed via Docker or GitHub releases.
  It's also an Angular SPA, so its forms are built client-side and are
  invisible to a `requests` + BeautifulSoup scanner that doesn't run JS.
- **DVWA** — needs Docker (not installed) or a PHP/MySQL stack. More
  importantly its vulnerable pages sit behind `login.php` and a session
  cookie, and this scanner has no auth support, so an unauthenticated scan
  only ever reaches the login page.

Both are still worth setting up for the writeup if Docker becomes available —
they're recognised names and DVWA's adjustable security levels demonstrate
findings appearing and disappearing. This target exists so Phase 2 isn't
blocked on that.
