"""Severity ranking, defined once.

Several checks find more than one problem and have to report the worst of them
as the row's severity. That ranking lived in three places (an unused constant in
``scanner/__init__.py`` plus a private copy in two check modules); it lives here
now so a new severity level can't be added to some of them and not the others.

This is a leaf module -- it imports nothing from the package, so checks can
import it without the circular import that pulling it from ``scanner/__init__``
would cause.
"""

# Lower number = more serious. Used for sorting, so the values matter.
ORDER = {"high": 0, "medium": 1, "low": 2}

LEVELS = frozenset(ORDER)


def worst(severities):
    """Return the most serious severity in `severities`.

    Raises KeyError on an unknown level rather than guessing, so a typo in a
    check shows up immediately instead of being silently ranked last.
    """
    return min(severities, key=lambda s: ORDER[s])
