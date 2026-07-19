"""Throwaway HTTP targets the checks can scan during tests.

We use stdlib ``http.server`` rather than Flask on purpose. Werkzeug rewrites
the ``Server`` header after the app runs, so a Flask fixture cannot spoof
``Apache/2.2.8`` for the version-leak test -- ``http.server`` lets us override
``version_string()`` and control every header and body exactly.
"""

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@contextlib.contextmanager
def serve(handler_cls):
    """Run ``handler_cls`` on 127.0.0.1:<ephemeral> for the duration of a with-block."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def make_handler(routes, server_banner=None, extra_headers=None, default_status=404):
    """Build a request handler from a routing table.

    ``routes`` maps an exact path (query string stripped) to either:
      - a ``(status, body)`` tuple, or
      - a callable ``(handler) -> (status, body)`` that can read the query.
    ``server_banner`` overrides the ``Server`` header (None -> omitted).
    ``extra_headers`` is a dict added to every response.
    Any path not in ``routes`` returns ``default_status`` with a plain body.
    """

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence per-request stderr noise
            pass

        def version_string(self):
            # Controls the Server header. Return "" so no meaningful Server
            # banner is sent unless one was explicitly asked for.
            return server_banner or ""

        def _dispatch(self):
            path = self.path.split("?", 1)[0]
            entry = routes.get(path, (default_status, "Not found"))
            status, body = entry(self) if callable(entry) else entry

            body_bytes = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body_bytes)))
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body_bytes)

        do_GET = _dispatch
        do_POST = _dispatch

    return _Handler
