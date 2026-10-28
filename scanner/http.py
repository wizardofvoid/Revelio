"""Shared HTTP layer for all checks.

Every check goes through here so timeout, User-Agent and error handling are
defined once instead of copy-pasted into five modules.
"""

from urllib.parse import urlsplit, urlunsplit

import requests
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

TIMEOUT = 8  # seconds; practice targets are local, so this is generous
USER_AGENT = "LightweightVulnScanner/0.1 (local testing only)"

# Every check reads the whole body into memory to pattern-match it. Without a
# cap, a target serving a huge file (or an endless stream) would take the
# scanner down with it, so stop reading past this point -- the signatures we
# look for are all near the top of a page anyway.
MAX_BODY_BYTES = 2_000_000

# Practice targets (DVWA in Docker, self-hosted labs) routinely use self-signed
# certificates. Verifying would turn every https lab into a connection error,
# so we skip it -- this tool is for targets you control, never the public web.
VERIFY_TLS = False
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT})


class TargetUnreachable(Exception):
    """Raised when the target can't be contacted at all.

    requests' own exception text is long and stack-shaped; this keeps the
    message short enough to show a non-technical reader in the report.
    """


def reset_session():
    """Drop any cookies picked up so far.

    The session is module-level and lives as long as the Flask process, so
    without this a cookie set during one scan is still being sent on the next
    one. Called once per scan by ``run_all_checks``.
    """
    _session.cookies.clear()


def _read_capped(response):
    """Consume at most MAX_BODY_BYTES of the body, then close the connection.

    Fills in ``response._content`` by hand so ``.text`` works exactly as it does
    on a normal non-streamed response -- callers never need to know the body
    was truncated.
    """
    body = b""
    try:
        for chunk in response.iter_content(8192):
            body += chunk
            if len(body) >= MAX_BODY_BYTES:
                body = body[:MAX_BODY_BYTES]
                break
    finally:
        response.close()
    response._content = body
    response._content_consumed = True
    return response


def _request(method, url, **kwargs):
    """One request path so get/post share identical timeout + error handling."""
    try:
        return _read_capped(
            _session.request(
                method,
                url,
                timeout=TIMEOUT,
                verify=VERIFY_TLS,
                stream=True,  # so _read_capped can stop early on a huge body
                **kwargs,
            )
        )
    except requests.exceptions.Timeout:
        raise TargetUnreachable(f"{url} did not respond within {TIMEOUT}s.")
    except requests.exceptions.SSLError as exc:
        raise TargetUnreachable(f"TLS handshake with {url} failed: {exc}.")
    except requests.exceptions.ConnectionError:
        raise TargetUnreachable(
            f"Could not connect to {url}. Is the target actually running?"
        )
    except RequestException as exc:
        raise TargetUnreachable(f"Request to {url} failed: {type(exc).__name__}.")


def get(url, allow_redirects=True, params=None):
    return _request("GET", url, allow_redirects=allow_redirects, params=params)


def post(url, data, allow_redirects=True):
    return _request("POST", url, data=data, allow_redirects=allow_redirects)


def join(base_url, path):
    """Resolve an absolute path against the *directory* the target URL is in.

    urljoin() is wrong here: urljoin('http://h/dvwa/', '/admin/') gives
    'http://h/admin/', throwing away a subdirectory mount point.

    Plain concatenation (what this used to do) is wrong the other way:
      - 'http://h/login'      + '/admin/' -> 'http://h/login/admin/', probing
        under a *page*, which is why scanning a form URL always reported "no
        directory listings" no matter what the site was actually exposing
      - 'http://h/s?q=1'      + '/admin/' -> 'http://h/s?q=1/admin/', which puts
        the path inside the query string
      - a '#fragment' landed in the middle of the result the same way

    So: split the URL properly, drop query and fragment, and treat a path with
    no trailing slash as a page and probe alongside it rather than beneath it.
        http://h            -> http://h/admin/
        http://h/login      -> http://h/admin/
        http://h/dvwa/      -> http://h/dvwa/admin/
        http://h/dvwa/x.php -> http://h/dvwa/admin/
    """
    parts = urlsplit(base_url)
    directory = parts.path
    if not directory.endswith("/"):
        directory = directory.rsplit("/", 1)[0]  # '/dvwa/login.php' -> '/dvwa'
    return urlunsplit(
        (parts.scheme, parts.netloc, directory.rstrip("/") + path, "", "")
    )
