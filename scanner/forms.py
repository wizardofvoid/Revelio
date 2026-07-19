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
TEXTY_TYPES = {"text", "search", "email", "url", "tel", "password", "textarea", ""}

# Types we send back with a harmless placeholder so the form validates, but
# never inject into. hidden/submit carry values the app expects unchanged.
PASSTHROUGH_TYPES = {"hidden", "submit", "button", "radio", "checkbox"}


def parse_forms(page_url):
    """Fetch page_url and return a list of form descriptors.

    Each form is: {action (absolute url), method (get/post),
                   inputs: [{name, type, value}], texty_names: [str]}
    Forms with no named field we can inject into are dropped.
    """
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

            ftype = (
                "textarea"
                if field.name == "textarea"
                else (field.get("type") or "text").strip().lower()
            )
            value = field.get("value") or ""
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
