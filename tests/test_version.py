"""Version-leak check: an exact version is a finding, a bare name is not.

``Apache/2.2.8`` tells an attacker exactly which exploits to try; bare
``nginx`` does not. The check must distinguish the two, or it either misses real
leaks or cries wolf on every server that names itself.
"""

from scanner import version_check
from tests.targets import make_handler, serve


def test_exact_version_is_flagged():
    handler = make_handler({"/": (200, "ok")}, server_banner="Apache/2.2.8 (Ubuntu)")
    with serve(handler) as base:
        result = version_check.run(base)
    assert result["status"] == "fail"
    assert result["severity"] == "medium"
    assert "Apache 2.2.8" in result["detail"]


def test_x_powered_by_version_is_flagged():
    handler = make_handler(
        {"/": (200, "ok")}, extra_headers={"X-Powered-By": "PHP/5.4.45"}
    )
    with serve(handler) as base:
        result = version_check.run(base)
    assert result["status"] == "fail"
    assert "PHP 5.4.45" in result["detail"]


def test_bare_product_name_is_a_pass():
    """'nginx' with no version number -> pass with a note, not a finding."""
    handler = make_handler({"/": (200, "ok")}, server_banner="nginx")
    with serve(handler) as base:
        result = version_check.run(base)
    assert result["status"] == "pass"
    assert "nginx" in result["detail"]
