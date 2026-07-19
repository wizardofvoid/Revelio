"""Flask entry point for the Lightweight Web Vulnerability Scanner.

Run with:  python app.py   ->  http://localhost:5000
"""

import ipaddress
import json
import socket
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, render_template, request

from scanner import run_all_checks, summarise

app = Flask(__name__)

STYLE_PATH = Path(__file__).parent / "static" / "style.css"


def normalise_url(raw):
    """Add a scheme if the user omitted it, and validate the shape."""
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a URL to scan.")
    if "://" not in raw:
        raw = "http://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// targets are supported.")
    if not parsed.hostname:
        raise ValueError(f"Could not read a hostname from {raw!r}.")
    return raw, parsed.hostname


def is_local_target(hostname):
    """True if the hostname resolves to loopback or a private network.

    Scanning sends real attack payloads, so anything outside a network you
    control needs the user to explicitly confirm they have permission.
    """
    try:
        addr = ipaddress.ip_address(socket.gethostbyname(hostname))
    except (socket.gaierror, ValueError):
        return False
    return addr.is_loopback or addr.is_private


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    try:
        target_url, hostname = normalise_url(request.form.get("target_url"))
    except ValueError as exc:
        return render_template("index.html", error=str(exc)), 400

    confirmed = request.form.get("permission_confirmed") == "on"
    if not is_local_target(hostname) and not confirmed:
        return (
            render_template(
                "index.html",
                error=f"{hostname} is not a local or private address. Tick the "
                "permission box to scan it anyway.",
                target_url=target_url,
                needs_confirmation=True,
            ),
            400,
        )

    results = run_all_checks(target_url)
    return render_template(
        "report.html",
        target_url=target_url,
        results=results,
        summary=summarise(results),
        scanned_at=datetime.now().strftime("%d %b %Y, %H:%M"),
        standalone=False,
    )


@app.route("/export", methods=["POST"])
def export():
    """Re-render an already-computed report as a standalone downloadable file.

    The report page posts its own results back as JSON so we don't re-scan the
    target (and re-send attack payloads) just to produce a download.
    """
    payload = json.loads(request.form.get("results_json", "{}"))
    results = payload.get("results", [])
    html = render_template(
        "report.html",
        target_url=payload.get("target_url", ""),
        results=results,
        summary=summarise(results),
        scanned_at=payload.get("scanned_at", ""),
        standalone=True,
        inline_css=STYLE_PATH.read_text(encoding="utf-8"),
    )
    filename = f"scan-report-{datetime.now().strftime('%Y%m%d-%H%M')}.html"
    return html, 200, {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Disposition": f'attachment; filename="{filename}"',
    }


if __name__ == "__main__":
    app.run(debug=True, port=5000)
