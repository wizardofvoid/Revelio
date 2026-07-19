"""Shared HTTP layer for all checks.

Every check goes through here so timeout, User-Agent and error handling are
defined once instead of copy-pasted into five modules.
"""

import requests
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

TIMEOUT = 8  # seconds; practice targets are local, so this is generous
USER_AGENT = "LightweightVulnScanner/0.1 (local testing only)"

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


def _request(method, url, **kwargs):
    """One request path so get/post share identical timeout + error handling."""
    try:
        return _session.request(
            method,
            url,
            timeout=TIMEOUT,
            verify=VERIFY_TLS,
            **kwargs,
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
    """Append path to base_url, preserving any base path.

    urljoin() would throw away a base path -- urljoin('http://h/dvwa', '/admin/')
    gives 'http://h/admin/', which is the wrong target when the app is mounted
    in a subdirectory.
    """
    return base_url.rstrip("/") + path
