# SPDX-FileCopyrightText: 2026 Open Web Calendar Contributors
# SPDX-License-Identifier: GPL-2.0-only

"""Security boundaries for user-controlled calendar specifications."""

import os
from urllib.parse import urlsplit

from markupsafe import Markup


def safe_url(value):
    """Allow HTTP(S) and relative links, never executable URL schemes."""
    if not isinstance(value, str):
        return "#"
    value = value.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in value) or "\\" in value:
        return "#"
    try:
        parts = urlsplit(value)
    except ValueError:
        return "#"
    if parts.scheme.lower() not in ("", "http", "https"):
        return "#"
    return value


def safe_css(value):
    """Keep CSS literal while preventing an HTML raw-text element breakout."""
    return Markup(str(value).replace("<", r"\3c "))  # noqa: S704


def harden_specification(specification):
    """Never allow public specifications to enable arbitrary JavaScript.

    An operator can opt into the upstream customization feature only through
    the process environment. Doing so intentionally permits arbitrary scripts.
    """
    if os.environ.get("OWC_ALLOW_CUSTOM_JAVASCRIPT", "").lower() != "true":
        specification["javascript"] = ""
        specification["javascript_url"] = []
    return specification
