"""The /export route, which is the only one accepting arbitrary input.

The report page posts its own findings back so downloading doesn't re-scan the
target. That payload used to be trusted completely: malformed JSON, a non-list
``results``, or a finding missing ``status`` each produced an HTTP 500. A
download button must not be able to 500 on a hand-edited field.
"""

import json

import pytest

from app import app


@pytest.fixture
def client():
    return app.test_client()


@pytest.mark.parametrize(
    "label, posted",
    [
        ("malformed json", "not json at all"),
        ("empty string", ""),
        ("json but not an object", "[1, 2, 3]"),
        ("results is not a list", '{"results": "oops"}'),
        ("finding missing status", '{"results": [{"name": "x"}]}'),
        ("finding is not a dict", '{"results": ["just a string"]}'),
        ("unknown status value", '{"results": [{"status": "banana"}]}'),
        ("field missing entirely", "{}"),
    ],
)
def test_broken_payloads_still_render(client, label, posted):
    response = client.post("/export", data={"results_json": posted})
    assert response.status_code == 200, label
    assert b"Scan report" in response.data


def test_no_field_at_all(client):
    """Nothing posted -> still a report, not a crash."""
    assert client.post("/export", data={}).status_code == 200


def test_unknown_status_is_shown_as_error_not_invented(client):
    """An unrecognised status must not reach the template as a bogus CSS class."""
    posted = json.dumps({"results": [{"name": "X", "status": "banana",
                                      "severity": "nuclear"}]})
    response = client.post("/export", data={"results_json": posted})
    body = response.data.decode()
    assert "finding-banana" not in body
    assert "sev-nuclear" not in body
    assert "finding-error" in body


def test_valid_payload_round_trips(client):
    """The normal path still works: a real finding renders with its text."""
    finding = {
        "name": "Security headers",
        "status": "fail",
        "severity": "high",
        "detail": "Missing: Content-Security-Policy.",
        "risk": "Browser protections are off.",
        "fix": "Add the header.",
    }
    posted = json.dumps({"target_url": "http://127.0.0.1:8000",
                         "scanned_at": "01 Jan 2026, 10:00",
                         "results": [finding]})
    response = client.post("/export", data={"results_json": posted})
    body = response.data.decode()
    assert response.status_code == 200
    assert "Missing: Content-Security-Policy." in body
    assert "attachment" in response.headers["Content-Disposition"]
