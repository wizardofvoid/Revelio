"""Form parsing shared by the SQLi and XSS checks.

Two things worth pinning: a <select> is a fixed list of options, not a free-text
field, so payloads must not be aimed at it; and the page must be fetched once
per scan even though two checks ask for its forms.
"""

from scanner import forms
from tests.targets import make_handler, serve

MIXED_FORM = (
    "<!doctype html><title>Order</title>"
    '<form method="post" action="/order">'
    '  <input type="text" name="note">'
    '  <input type="hidden" name="csrf" value="tok123">'
    '  <textarea name="comment"></textarea>'
    '  <select name="size"><option value="M">Medium</option>'
    '                      <option value="L">Large</option></select>'
    '  <input type="submit" name="go" value="Order">'
    "</form>"
)


def _parse(html):
    forms.clear_cache()
    with serve(make_handler({"/": (200, html)})) as base:
        return forms.parse_forms(base)


def test_select_is_not_treated_as_injectable():
    """A dropdown can't carry a payload -- it must not inflate the field count."""
    form = _parse(MIXED_FORM)[0]
    assert "size" not in form["texty_names"]
    assert set(form["texty_names"]) == {"note", "comment"}


def test_select_still_submits_its_first_option():
    """It's excluded from injection but still sent, so validation passes."""
    form = _parse(MIXED_FORM)[0]
    size = next(f for f in form["inputs"] if f["name"] == "size")
    assert size["type"] == "select"
    assert size["value"] == "M"


def test_hidden_field_value_is_preserved():
    """A CSRF token must go back unchanged or the app rejects the submission."""
    form = _parse(MIXED_FORM)[0]
    csrf = next(f for f in form["inputs"] if f["name"] == "csrf")
    assert csrf["value"] == "tok123"


def test_page_is_fetched_once_per_scan():
    """SQLi and XSS both want the same forms; that's one request, not two."""
    hits = {"n": 0}

    def counting(_handler):
        hits["n"] += 1
        return 200, MIXED_FORM

    forms.clear_cache()
    with serve(make_handler({"/": counting})) as base:
        first = forms.parse_forms(base)
        second = forms.parse_forms(base)
    assert hits["n"] == 1
    assert first == second


def test_clear_cache_forces_a_refetch():
    """A new scan must see the page as it is now, not as it was."""
    hits = {"n": 0}

    def counting(_handler):
        hits["n"] += 1
        return 200, MIXED_FORM

    forms.clear_cache()
    with serve(make_handler({"/": counting})) as base:
        forms.parse_forms(base)
        forms.clear_cache()
        forms.parse_forms(base)
    assert hits["n"] == 2
