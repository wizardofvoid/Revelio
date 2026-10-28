"""The shared HTTP layer: URL joining and the response size cap.

``join`` is what decides which paths the directory-listing check probes. It was
plain string concatenation, which produced ``/login/admin/`` when the target was
a page and put the path inside the query string when the target had one -- so
the check silently probed nonsense and reported "no listings found".
"""

from scanner import http
from tests.targets import make_handler, serve


class TestJoin:
    """Each case is a URL shape that used to come out wrong."""

    def test_bare_origin(self):
        assert http.join("http://h:8000", "/admin/") == "http://h:8000/admin/"

    def test_origin_with_trailing_slash(self):
        assert http.join("http://h:8000/", "/admin/") == "http://h:8000/admin/"

    def test_page_target_probes_its_directory_not_below_it(self):
        """The original bug: '/login' + '/admin/' gave '/login/admin/'."""
        assert http.join("http://h:8000/login", "/admin/") == "http://h:8000/admin/"

    def test_query_string_is_dropped(self):
        """Concatenation put the path inside the query: '/s?q=1/admin/'."""
        assert http.join("http://h:8000/s?q=1", "/admin/") == "http://h:8000/admin/"

    def test_fragment_is_dropped(self):
        assert http.join("http://h:8000/app#frag", "/admin/") == "http://h:8000/admin/"

    def test_subdirectory_mount_is_preserved(self):
        """The reason urljoin() isn't used: don't lose a /dvwa mount point."""
        assert http.join("http://h:8000/dvwa/", "/admin/") == "http://h:8000/dvwa/admin/"

    def test_page_inside_a_mount_keeps_the_mount(self):
        assert (
            http.join("http://h:8000/dvwa/login.php", "/admin/")
            == "http://h:8000/dvwa/admin/"
        )


def test_body_is_capped():
    """A target serving more than MAX_BODY_BYTES must not be read whole."""
    oversized = "A" * (http.MAX_BODY_BYTES + 500_000)
    with serve(make_handler({"/": (200, oversized)})) as base:
        response = http.get(base)
    assert len(response.text) == http.MAX_BODY_BYTES


def test_reset_session_clears_cookies():
    """Cookies must not survive into the next scan of a different target."""
    routes = {"/": (200, "ok")}
    with serve(make_handler(routes, extra_headers={"Set-Cookie": "sid=abc123"})) as base:
        http.get(base)
        assert len(http._session.cookies) == 1
        http.reset_session()
        assert len(http._session.cookies) == 0
