# SPDX-FileCopyrightText: 2026 Open Web Calendar Contributors
# SPDX-License-Identifier: GPL-2.0-only

"""Regressions for configuration, query-string and raw-text XSS."""

from urllib.parse import parse_qs, urlsplit

import pytest
from bs4 import BeautifulSoup

from open_web_calendar.clean_html import clean_html

PAYLOAD = '"><img src=data:,x onerror="document.title=\'OWC-XSS-CONFIRMED\'">'
PAGES = ["/", "/index.html", "/about.html", "/calendar.html"]


def parse_response(client, path, query):
    response = client.get(path, query_string=query)
    assert response.status_code == 200
    return BeautifulSoup(response.text, "html.parser")


@pytest.mark.parametrize("path", PAGES)
@pytest.mark.parametrize(
    "parameter",
    ["privacy_policy", "contributing", "source_code", "title", "version", "unknown"],
)
@pytest.mark.parametrize(
    "payload", [PAYLOAD, '</title><img src=data:,x onerror="alert(3)">']
)
def test_specification_cannot_inject_elements(client, path, parameter, payload):
    document = parse_response(client, path, {parameter: payload})
    assert not document.select('img[src="data:,x"]')
    assert not document.select("[onerror]")


@pytest.mark.parametrize("path", PAGES)
def test_raw_query_cannot_break_link_attribute(client, path):
    response = client.get(path + '?unknown="onmouseover="alert(3)')
    assert response.status_code == 200
    document = BeautifulSoup(response.text, "html.parser")
    assert not document.select("[onmouseover]")


@pytest.mark.parametrize("path", ["/index.html", "/about.html"])
@pytest.mark.parametrize(
    "parameter", ["privacy_policy", "contributing", "source_code", "translate"]
)
@pytest.mark.parametrize(
    "value",
    [
        "javascript:alert(3)",
        "JaVaScRiPt:alert(3)",
        "java\nscript:alert(3)",
        "data:text/html,<script>alert(3)</script>",
    ],
)
def test_navigation_urls_are_not_executable(client, path, parameter, value):
    document = parse_response(client, path, {parameter: value})
    assert not any(link.get("href") == value for link in document.select("a[href]"))


@pytest.mark.parametrize("path", PAGES)
def test_query_links_preserve_encoded_values(client, path):
    query = [
        ("url", "https://example.org/a.ics?a=1&b=2"),
        ("url", "https://example.org/b.ics"),
        ("title", 'A + B " & C'),
    ]
    document = parse_response(client, path, query)
    link = document.select_one('link[rel="alternate"][type="text/calendar"]')
    assert parse_qs(urlsplit(link["href"]).query) == {
        "url": [query[0][1], query[1][1]],
        "title": [query[2][1]],
    }


@pytest.mark.parametrize("payload", ["</style>" + PAYLOAD, "</StYlE>" + PAYLOAD])
def test_css_cannot_close_style_element(client, payload):
    document = parse_response(client, "/calendar.html", {"css": payload})
    assert not document.select("[onerror]")


def test_custom_scripts_disabled_by_default(client, monkeypatch):
    monkeypatch.delenv("OWC_ALLOW_CUSTOM_JAVASCRIPT", raising=False)
    document = parse_response(
        client,
        "/calendar.html",
        {
            "javascript": "document.title='OWC-XSS-CONFIRMED'",
            "javascript_url": "https://example.org/attack.js",
            "OWC_ALLOW_CUSTOM_JAVASCRIPT": "true",
        },
    )
    assert not document.select('script[src="https://example.org/attack.js"]')
    assert not any(
        "document.title='OWC-XSS-CONFIRMED'" in script.text
        for script in document.select("script")
    )


def test_remote_spec_cannot_enable_scripts(client, cache_url, monkeypatch):
    monkeypatch.delenv("OWC_ALLOW_CUSTOM_JAVASCRIPT", raising=False)
    url = "https://example.org/config.json"
    cache_url(
        url,
        '{"javascript": "alert(3)", "javascript_url": ["https://example.org/attack.js"]}',
    )
    document = parse_response(client, "/calendar.html", {"specification_url": url})
    assert not document.select('script[src="https://example.org/attack.js"]')
    assert not any("alert(3)" in script.text for script in document.select("script"))


def test_cleaner_security_cannot_be_disabled():
    spec = {
        "clean_html_scripts": False,
        "clean_html_javascript": False,
        "clean_html_safe_attrs_only": False,
    }
    document = BeautifulSoup(
        clean_html("<script>alert(3)</script>" + PAYLOAD, spec), "html.parser"
    )
    assert not document.select("script, [onerror]")


def test_https_privacy_link_is_preserved(client):
    url = "https://example.org/privacy?a=1&b=2"
    document = parse_response(client, "/index.html", {"privacy_policy": url})
    assert any(link.get("href") == url for link in document.select("a[href]"))
