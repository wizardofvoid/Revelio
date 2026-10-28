"""Shared form parsing for the SQLi and XSS checks.

Both checks need the same thing: find every <form> on a page, know where it
submits and which fields to fill. That logic lives here once so the two checks
can't drift apart.
"""

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from scanner import http

# Input types we submit payloads into. Buttons, checkboxes, files etc. are
# skipped -- they don't take free text and aren't where injection lives.
TEXTY_TYPES = {"text", "search", "email", "url", "tel", "password", "textarea"}

# Types we send back with a harmless placeholder so the form validates, but
# never inject into. hidden/submit carry values the app expects unchanged, and
# a <select> is a fixed list of options rather than a free-text field -- feeding
# it a payload only inflated the "tested N fields" count with fields that can't
# take one.
PASSTHROUGH_TYPES = {"hidden", "submit", "button", "radio", "checkbox", "select"}

# The SQLi and XSS checks are handed the same target URL and both need its
# forms. Without this they fetched and re-parsed the page once each. Keyed by
# URL and cleared per scan by run_all_checks, so results are never stale.
_form_cache = {}


def clear_cache():
    """Forget parsed forms. Called once per scan so a re-scan sees the page as
    it is now, not as it was."""
    _form_cache.clear()


def _field_descriptor(field):
    """Read one <input>/<textarea>/<select> into {name, type, value}."""
    if field.name == "textarea":
        return "textarea", field.get_text() or ""
    if field.name == "select":
        # Submit the first option so required-field validation passes.
        option = field.find("option")
        if option is None:
            return "select", ""
        value = option.get("value")
        return "select", value if value is not None else option.get_text(strip=True)
    return (field.get("type") or "text").strip().lower(), field.get("value") or ""


def parse_forms(page_url):
    """Fetch page_url and return a list of form descriptors.

    Each form is: {action (absolute url), method (get/post),
                   inputs: [{name, type, value}], texty_names: [str]}
    Forms with no named field we can inject into are dropped.
    """
    if page_url in _form_cache:
        return _form_cache[page_url]

    response = http.get(page_url)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = []

    for form in soup.find_all("form"):
        # A form with no action submits back to the page it's on.
        action = form.get("action") or ""
        method = (form.get("method") or "get").strip().lower()
        if method not in ("get", "post"):
            method = "get"

        inputs, texty_names = [], []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if not name:
                continue  # unnamed fields aren't submitted by the browser

            ftype, value = _field_descriptor(field)
            inputs.append({"name": name, "type": ftype, "value": value})
            if ftype in TEXTY_TYPES:
                texty_names.append(name)

        if texty_names:  # nothing to inject into -> not worth testing
            forms.append(
                {
                    "action": urljoin(response.url, action),
                    "method": method,
                    "inputs": inputs,
                    "texty_names": texty_names,
                }
            )

    _form_cache[page_url] = forms
    return forms


def submit(form, inject_name, payload):
    """Submit form with `payload` in `inject_name` and placeholders elsewhere.

    Returns the response. Only one field is injected at a time so a positive
    result points at a specific field, not "somewhere in this form".
    """
    data = {}
    for field in form["inputs"]:
        if field["type"] in PASSTHROUGH_TYPES:
            data[field["name"]] = field["value"]  # keep what the app expects
        elif field["name"] == inject_name:
            data[field["name"]] = payload
        else:
            # Other text fields get a benign value so required-field checks pass.
            data[field["name"]] = "test"

    if form["method"] == "post":
        return http.post(form["action"], data)
    return http.get(form["action"], params=data)
