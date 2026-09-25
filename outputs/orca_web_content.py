"""Small, bounded JSON excerpts for text-only web tools.

The returned text is valid JSON with flattened JSON-pointer field names. Useful
API links survive verbose JSON-LD metadata, and URLs are never cut mid-address.
This module only formats supplied data; it performs no network or file access.
"""

from __future__ import annotations

import itertools
import json
import math


_MAX_NODES = 1536
_MAX_DEPTH = 10
_MAX_CHILDREN = 128
_MAX_ARRAY_ITEMS = 24
_MAX_PATH = 240
_MAX_TEXT = 420
_MAX_OUTPUT = 20000
_SKIP_KEYS = {"@context", "geometry", "coordinates", "bbox", "crs"}
_LINK_KEYS = {
    "url", "uri", "href", "next", "previous", "prev", "first", "last",
    "forecast", "forecasthourly", "forecastgriddata", "observationstations",
    "latestobservation", "observations", "stations", "nextpage", "nextlink",
}
_FACT_KEYS = {
    "name", "title", "description", "timestamp", "time", "date", "updated",
    "updatedat", "validtime", "starttime", "endtime", "textdescription",
    "stationidentifier", "city", "state", "country", "latitude", "longitude",
    "value", "unit", "units", "unitcode", "status", "message", "error",
}
_MEASUREMENT_KEYS = {"value", "unit", "units", "unitcode", "timestamp", "textdescription"}


def _key(value: str) -> str:
    return value.lower().replace("_", "").replace("-", "")


def _pointer(path: str, key: str) -> str:
    return path + "/" + key.replace("~", "~0").replace("/", "~1")


def _is_link(value: str, key: str) -> bool:
    return value.startswith(("http://", "https://")) or (
        key in _LINK_KEYS and value.startswith(("/", "?"))
    )


def _rank(key: str, value: object) -> int:
    normalized = _key(key)
    if normalized in _MEASUREMENT_KEYS:
        return 0
    if isinstance(value, str) and _is_link(value, normalized):
        return 1 if normalized in _LINK_KEYS else 3
    if normalized in _FACT_KEYS:
        return 2
    return 4


def compact_json_content(data: object, limit: int = 3000) -> str:
    """Return a bounded JSON excerpt, keeping actionable links before boilerplate.

    Field names are JSON pointers into the supplied value. ``truncated`` means
    some content was skipped or shortened, including context/geometry metadata.
    URL fields are included intact or omitted when they cannot fit. A limit
    smaller than two characters returns an empty string; very small budgets
    otherwise return ``{}``. Work is bounded independently of input dimensions.
    """
    limit = max(0, min(int(limit), _MAX_OUTPUT))
    if limit < 2:
        return ""

    candidates: list[tuple[int, int, str, object]] = []
    stack: list[tuple[str, str, object, int]] = [("", "", data, 0)]
    visited = 0
    truncated = False
    while stack and visited < _MAX_NODES:
        path, key, value, depth = stack.pop()
        visited += 1
        if len(path) > _MAX_PATH:
            truncated = True
            continue
        if isinstance(value, (dict, list)):
            if depth >= _MAX_DEPTH:
                truncated = True
                continue
            if isinstance(value, dict):
                items = list(itertools.islice(value.items(), _MAX_CHILDREN))
                truncated |= len(value) > _MAX_CHILDREN
                children = []
                for child_key, child in items:
                    if not isinstance(child_key, str) or child_key.lower() in _SKIP_KEYS:
                        truncated = True
                        continue
                    if len(child_key) > 120:
                        truncated = True
                        continue
                    children.append((_pointer(path, child_key), child_key, child, depth + 1))
                # Visit data-bearing objects ahead of metadata and array items.
                children.sort(key=lambda item: (
                    0 if item[1] in {"properties", "data", "current", "results"} else 1,
                    _rank(item[1], item[2]),
                ))
            else:
                truncated |= len(value) > _MAX_ARRAY_ITEMS
                children = [
                    (_pointer(path, str(index)), key, child, depth + 1)
                    for index, child in enumerate(value[:_MAX_ARRAY_ITEMS])
                ]
            stack.extend(reversed(children))
            continue
        if value is not None and not isinstance(value, (str, bool, int, float)):
            truncated = True
            continue
        if isinstance(value, float) and not math.isfinite(value):
            truncated = True
            continue
        rank = _rank(key, value)
        if isinstance(value, str):
            if _is_link(value, _key(key)):
                # Reject an oversized URL intact instead of fabricating a broken one.
                if len(value) > limit:
                    truncated = True
                    continue
            elif len(value) > _MAX_TEXT:
                value = value[:_MAX_TEXT - 1] + "…"
                truncated = True
        candidates.append((rank, visited, path or "/", value))
    truncated |= bool(stack)

    def encode(fields: dict, omitted: bool) -> str:
        return json.dumps(
            {"fields": fields, "truncated": omitted}, ensure_ascii=False,
            separators=(",", ":"), allow_nan=False,
        )

    fields: dict[str, object] = {}
    # Reserve the longer false value so the final omission flag always fits.
    base_size = len(encode(fields, False))
    if base_size > limit:
        return "{}"
    current_size = base_size
    for _, _, path, value in sorted(candidates):
        pair = json.dumps({path: value}, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        addition = len(pair) - 2 + bool(fields)
        if current_size + addition > limit:
            truncated = True
            continue
        fields[path] = value
        current_size += addition
    return encode(fields, truncated)


def compact_tool_result(result: dict, limit: int = 1000) -> str:
    """Keep a fetch result useful after history/evidence compression.

    JSON response bodies become a small ``data`` object whose keys are JSON
    pointers. HTML responses keep a text excerpt plus up to three complete
    links. Source URLs are kept whole or omitted, never shortened into new URLs.
    The returned outer object is valid JSON and always fits the character limit.
    """
    limit = max(0, min(int(limit), _MAX_OUTPUT))
    if limit < 2:
        return ""

    output: dict = {"truncated": True}

    def encode(value: dict) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)

    if len(encode(output)) > limit:
        return "{}"

    def add(key: str, value: object) -> bool:
        trial = {**output, key: value}
        if len(encode(trial)) > limit:
            return False
        output[key] = value
        return True

    def add_text(key: str, text: str, maximum: int) -> None:
        maximum = min(len(text), max(0, maximum))
        low, high = 0, maximum
        chosen = ""
        while low <= high:
            middle = (low + high) // 2
            excerpt = text[:middle] + ("…" if middle < len(text) else "")
            if len(encode({**output, key: excerpt})) <= limit:
                chosen = excerpt
                low = middle + 1
            else:
                high = middle - 1
        if chosen:
            output[key] = chosen

    status = result.get("status")
    if isinstance(status, (int, bool)) or isinstance(status, str) and len(status) <= 30:
        add("status", status)
    url = result.get("url")
    if isinstance(url, str) and len(url) <= max(100, min(240, limit // 3)):
        add("url", url)
    if isinstance(result.get("error"), str):
        add_text("error", result["error"], min(240, limit // 3))
    if isinstance(result.get("note"), str):
        add_text("note", result["note"], min(160, limit // 6))

    content_type = str(result.get("content_type", "")).lower().split(";", 1)[0].strip()
    text = result.get("text", "")
    parsed = None
    has_json = False
    fields = None
    if isinstance(result.get("data"), dict):
        # shorten_history may recompact a result already processed here.
        fields = result["data"]
        has_json = True
    elif isinstance(text, str) and len(text) <= 2_000_000 and (
        content_type == "application/json" or content_type.endswith("+json")
        or text.lstrip().startswith(("{", "["))
    ):
        try:
            parsed = json.loads(text)
            has_json = True
        except (ValueError, RecursionError):
            pass
    if has_json:
        if fields is not None:
            pass
        elif isinstance(parsed, dict) and set(parsed) == {"fields", "truncated"} and isinstance(parsed["fields"], dict):
            # Avoid adding another /fields prefix when a body was compacted at fetch time.
            fields = parsed["fields"]
        else:
            fields = json.loads(compact_json_content(parsed, _MAX_OUTPUT))["fields"]
        add("data", {})
        if "data" in output:
            ranked = sorted(
                itertools.islice(fields.items(), _MAX_NODES),
                key=lambda item: _rank(str(item[0]).rsplit("/", 1)[-1], item[1]),
            )
            for path, value in ranked:
                if not isinstance(path, str) or len(path) > _MAX_PATH:
                    continue
                # The precompacted shape is data too; validate its scalar values.
                if value is not None and not isinstance(value, (str, int, float, bool)):
                    continue
                if isinstance(value, float) and not math.isfinite(value):
                    continue
                if isinstance(value, str):
                    if _is_link(value, _key(path.rsplit("/", 1)[-1])):
                        if len(value) > limit:
                            continue
                    elif len(value) > min(180, limit // 5):
                        value = value[:max(0, min(180, limit // 5) - 1)] + "…"
                candidate = {**output["data"], path: value}
                add("data", candidate)
        return encode(output)

    if isinstance(result.get("title"), str):
        add_text("title", result["title"], min(80, limit // 10))
    links = result.get("links")
    if isinstance(links, list):
        selected = []
        links_budget = limit // 3
        for link in links[:12]:
            if not isinstance(link, dict) or not isinstance(link.get("url"), str):
                continue
            target = link["url"]
            if not target.startswith(("http://", "https://", "/")) or len(target) > links_budget:
                continue
            item = {"url": target}
            if isinstance(link.get("text"), str):
                item["text"] = link["text"][:40]
            candidate = [*selected, item]
            if len(json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))) > links_budget:
                item.pop("text", None)
                candidate = [*selected, item]
            if len(json.dumps(candidate, ensure_ascii=False, separators=(",", ":"))) <= links_budget and add("links", candidate):
                selected = candidate
            if len(selected) == 3:
                break
    if isinstance(text, str) and text:
        add_text("text", text, limit)
    return encode(output)
