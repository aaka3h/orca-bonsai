"""Small, unauthenticated web search helper for the local Orca agent.

Search pages are untrusted data. This module only extracts result titles, URLs,
and brief snippets; it does not follow result links or execute page content.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup


_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
_HEADERS = {"User-Agent": _USER_AGENT, "Accept": "text/html"}
_MAX_RESPONSE_BYTES = 1_000_000
_MAX_OUTPUT_CHARS = 5_000


class _SearchUnavailable(Exception):
    pass


def _text(value: str, maximum: int) -> str:
    clean = " ".join(value.split())
    return clean if len(clean) <= maximum else clean[: maximum - 1].rstrip() + "…"


def _get_html(url: str, query: str) -> BeautifulSoup:
    params = {"p": query} if "yahoo.com" in url else {"q": query}
    if "brave.com" in url:
        params["source"] = "web"
    try:
        with requests.get(
            url,
            params=params,
            headers=_HEADERS,
            timeout=12,
            stream=True,
        ) as response:
            if response.status_code != 200:
                raise _SearchUnavailable(f"HTTP {response.status_code}")
            content_length = response.headers.get("Content-Length")
            if content_length and content_length.isdecimal() and int(content_length) > _MAX_RESPONSE_BYTES:
                raise _SearchUnavailable("response too large")
            if "html" not in response.headers.get("Content-Type", "").lower():
                raise _SearchUnavailable("unexpected response type")
            chunks = []
            size = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                size += len(chunk)
                if size > _MAX_RESPONSE_BYTES:
                    raise _SearchUnavailable("response too large")
                chunks.append(chunk)
            if not chunks:
                raise _SearchUnavailable("empty response")
            soup = BeautifulSoup(b"".join(chunks), "html.parser")
            title = soup.title.get_text(" ", strip=True).lower() if soup.title else ""
            final_url = response.url.lower()
            if any(marker in title or marker in final_url for marker in ("captcha", "challenge", "unusual traffic")):
                raise _SearchUnavailable("search verification page")
            return soup
    except requests.RequestException as exc:
        raise _SearchUnavailable(type(exc).__name__) from exc


def _valid_url(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _brave_results(soup: BeautifulSoup) -> list[dict[str, str]]:
    results = []
    for card in soup.select('div.snippet[data-type="web"]'):
        title = card.select_one(".search-snippet-title")
        link = title.find_parent("a", href=True) if title else None
        if not link or not _valid_url(link["href"]):
            continue
        snippet = card.select_one(".generic-snippet .content")
        results.append(
            {
                "title": _text(title.get_text(" ", strip=True), 160),
                "url": link["href"],
                "snippet": _text(snippet.get_text(" ", strip=True), 220) if snippet else "",
            }
        )
    return results


def _duckduckgo_destination(href: str) -> str:
    url = urljoin("https://lite.duckduckgo.com", href)
    parsed = urlparse(url)
    if parsed.hostname in ("duckduckgo.com", "www.duckduckgo.com") and parsed.path == "/l/":
        return parse_qs(parsed.query).get("uddg", [""])[0]
    return url


def _duckduckgo_results(soup: BeautifulSoup) -> list[dict[str, str]]:
    results = []
    for link in soup.select("a.result-link[href]"):
        url = _duckduckgo_destination(link["href"])
        if not _valid_url(url):
            continue
        row = link.find_parent("tr")
        snippet = None
        if row:
            next_row = row.find_next_sibling("tr")
            if next_row:
                snippet = next_row.select_one(".result-snippet")
        results.append(
            {
                "title": _text(link.get_text(" ", strip=True), 160),
                "url": url,
                "snippet": _text(snippet.get_text(" ", strip=True), 220) if snippet else "",
            }
        )
    return results


def _yahoo_results(soup: BeautifulSoup) -> list[dict[str, str]]:
    results = []
    for card in soup.select("div.algo"):
        title = card.select_one("h3")
        link = title.find_parent("a", href=True) if title else None
        if not link:
            continue
        href = link["href"]
        redirect = re.search(r"/RU=([^/]+)", href)
        url = unquote(redirect.group(1)) if redirect else urljoin("https://search.yahoo.com", href)
        if not _valid_url(url):
            continue
        snippet = card.select_one(".compText")
        results.append(
            {
                "title": _text(title.get_text(" ", strip=True), 160),
                "url": url,
                "snippet": _text(snippet.get_text(" ", strip=True), 220) if snippet else "",
            }
        )
    return results


def _bounded_results(results: list[dict[str, str]], limit: int, source: str) -> dict:
    output: dict = {"success": True, "source": source, "results": []}
    seen = set()
    for result in results:
        url = result["url"]
        if url in seen or not result["title"]:
            continue
        seen.add(url)
        candidate = result.copy()
        for snippet_max in (220, 100, 0):
            candidate["snippet"] = _text(result["snippet"], snippet_max) if snippet_max else ""
            trial = {**output, "results": output["results"] + [candidate]}
            if len(json.dumps(trial, ensure_ascii=False)) <= _MAX_OUTPUT_CHARS:
                output["results"].append(candidate.copy())
                break
        if len(output["results"]) >= limit:
            break
    return output


def search_web(query: str, limit: int = 6) -> dict:
    """Return up to ten web results, trying three providers in order.

    No account, API key, browser session, or CAPTCHA solving is used.
    """
    if not isinstance(query, str):
        return {"success": False, "error": "Search query must be text."}
    query = query.strip()
    if not query or len(query) > 250 or re.search(r"[\x00-\x1f\x7f]", query):
        return {"success": False, "error": "Search query must be 1–250 characters on one line."}
    if isinstance(limit, bool) or not isinstance(limit, int):
        return {"success": False, "error": "Result limit must be an integer."}
    limit = max(1, min(10, limit))

    attempts = []
    for name, url, parser in (
        ("Brave Search", "https://search.brave.com/search", _brave_results),
        ("DuckDuckGo Lite", "https://lite.duckduckgo.com/lite/", _duckduckgo_results),
        ("Yahoo Search", "https://search.yahoo.com/search", _yahoo_results),
    ):
        try:
            results = parser(_get_html(url, query))
            if not results:
                raise _SearchUnavailable("no results or search verification page")
            output = _bounded_results(results, limit, name)
            if output["results"]:
                return output
            raise _SearchUnavailable("results exceeded output limit")
        except _SearchUnavailable as exc:
            attempts.append(f"{name}: {exc}")
    return {
        "success": False,
        "error": "Search unavailable. " + "; ".join(attempts) + ". Try again later or open a known site directly.",
    }
