"""A DELIBERATELY VULNERABLE practice target for the scanner.

This is NOT part of the scanner. It exists so the scanner has something safe
and legal to point at, and it is insecure ON PURPOSE:

  - the login form concatenates SQL, so it is genuinely injectable
  - /search and /feedback reflect input without escaping (reflected XSS)
  - no security headers are sent
  - the Server banner advertises an exact version
  - /uploads/ serves a browsable file listing

It binds to 127.0.0.1 only and must never be exposed to a network. It holds
no real data -- the database is rebuilt in memory on every start.

Run:  python practice_target/app.py     ->  http://127.0.0.1:8000
"""

import sqlite3

from flask import Flask, g, request
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)
PORT = 8000

PAGE = """<!DOCTYPE html>
<html><head><title>{title} — Practice Target</title></head>
<body style="font-family:system-ui;max-width:640px;margin:2rem auto">
<p style="background:#fff3cd;padding:.6rem">Deliberately vulnerable practice
target. Do not deploy.</p>
<h1>{title}</h1>
{body}
<hr><p><a href="/">Home</a> · <a href="/login">Login</a> ·
<a href="/search">Search</a> · <a href="/feedback">Feedback</a> ·
<a href="/uploads/">Uploads</a></p>
</body></html>"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(":memory:")
        g.db.execute("CREATE TABLE users (id INTEGER, name TEXT, password TEXT)")
        g.db.execute("INSERT INTO users VALUES (1, 'admin', 'letmein')")
        g.db.execute("INSERT INTO users VALUES (2, 'gordonb', 'abc123')")
        g.db.commit()
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@app.route("/")
def home():
    return PAGE.format(
        title="Practice Target",
        body="<p>A small intentionally-insecure app for testing the scanner.</p>"
        "<ul><li>Login — SQL injection</li><li>Search — reflected XSS (GET)</li>"
        "<li>Feedback — reflected XSS (POST)</li>"
        "<li>/uploads/ — directory listing</li></ul>",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    result = ""
    if request.method == "POST":
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        # VULNERABLE ON PURPOSE: string-built SQL. Never do this for real.
        query = f"SELECT name FROM users WHERE name = '{user}' AND password = '{pw}'"
        try:
            rows = db().execute(query).fetchall()
            result = (
                f"<p>Welcome, {rows[0][0]}.</p>" if rows else "<p>Login failed.</p>"
            )
        except sqlite3.Error as exc:
            # Leaking the database error is half the vulnerability.
            result = f"<p>Database error: {exc}<br>Query was: {query}</p>"

    return PAGE.format(
        title="Login",
        body=result + """<form method="post">
<p><label>Username <input type="text" name="username"></label></p>
<p><label>Password <input type="text" name="password"></label></p>
<p><button type="submit">Log in</button></p></form>""",
    )


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE ON PURPOSE: reflected without escaping.
    found = f"<p>No results for: {q}</p>" if q else ""
    return PAGE.format(
        title="Search",
        body=found + """<form method="get">
<p><label>Search <input type="text" name="q"></label></p>
<p><button type="submit">Search</button></p></form>""",
    )


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    said = ""
    if request.method == "POST":
        # VULNERABLE ON PURPOSE: reflected without escaping.
        said = f"<p>Thanks. You said: {request.form.get('comment', '')}</p>"
    return PAGE.format(
        title="Feedback",
        body=said + """<form method="post">
<p><label>Name <input type="text" name="name"></label></p>
<p><label>Comment <input type="text" name="comment"></label></p>
<p><button type="submit">Send</button></p></form>""",
    )


@app.route("/uploads/")
def uploads():
    return """<html><head><title>Index of /uploads</title></head><body>
<h1>Index of /uploads</h1><pre><a href="../">Parent Directory</a>
<a href="notes.txt">notes.txt</a>      2.1K
<a href="db_backup.sql">db_backup.sql</a>   14K
</pre></body></html>"""


@app.after_request
def insecure_headers(response):
    # No CSP, no X-Frame-Options, no X-Content-Type-Options -- on purpose.
    response.headers["X-Powered-By"] = "PHP/5.4.45"
    return response


# The Server banner has to be set on the request handler, not in
# after_request: Werkzeug writes its own Server header at the HTTP layer
# afterwards, which would leave the response with two of them.
WSGIRequestHandler.server_version = "Apache/2.2.8 (Ubuntu) DAV/2"
WSGIRequestHandler.sys_version = ""

if __name__ == "__main__":
    print(f"Practice target on http://127.0.0.1:{PORT} — deliberately insecure.")
    # host is pinned to loopback: this must not be reachable from the network.
    app.run(host="127.0.0.1", port=PORT, debug=False)
