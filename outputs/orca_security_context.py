"""Bounded security context excerpts without turning candidates into findings.

Formatting only: no network, filesystem, tool execution, or trust in source text.
Records and URLs are included whole or omitted. A zero-character budget cannot
hold JSON and returns an empty string; one character returns the JSON number 0.
"""

from __future__ import annotations

import json
import math
import re


_LINK = re.compile(r"https?://\S+", re.I)
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
_ADVISORY_NOTE = "Candidate advisories; target applicability unverified. Rejected records are not vulnerabilities."
_CHECK_NOTE = "Hardening/configuration observations and service banners do not prove exploitation. Check completion is not assessment completion."


def _encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _whole(value, cap=180):
    return value if isinstance(value, str) and len(value) <= cap else None


def _short(value, cap=160):
    if not isinstance(value, str):
        return None
    value = " ".join(value.split())
    if len(value) <= cap:
        return value
    end = max(0, cap - 1)
    for match in _LINK.finditer(value):
        if match.start() < end < match.end():
            end = match.start()
            break
    return value[:end].rstrip() + "…" if end else None


def _scalar(value):
    return value is None or isinstance(value, (bool, int)) or (isinstance(value, float) and math.isfinite(value))


def _minimal(limit, note):
    for result in ({"truncated": True, "note": note}, {"truncated": True}, {}):
        text = _encode(result)
        if len(text) <= limit:
            return text
    return "0" if limit == 1 else ""


def _advisory_record(item):
    if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not _CVE.fullmatch(item["id"]):
        return None
    rejected = item.get("classification") == "rejected_record" or str(item.get("status", "")).casefold() == "rejected"
    result = {"id": item["id"], "classification": "rejected_record" if rejected else "candidate_advisory",
              "status": _whole(item.get("status"), 45) or "Unknown"}
    prior_excerpt = item.get("description_excerpt")
    description = _short(prior_excerpt if isinstance(prior_excerpt, str) else item.get("description"), 110)
    if description:
        result["description_excerpt"] = description
    metric = item.get("cvss")
    if isinstance(metric, dict) and not rejected:
        rating = {}
        for key in ("version", "severity", "source"):
            value = _whole(metric.get(key), 100 if key == "source" else 20)
            if value:
                rating[key] = value
        score = metric.get("base_score")
        if isinstance(score, (float, int)) and not isinstance(score, bool) and math.isfinite(score) and 0 <= score <= 10:
            rating["base_score"] = score
        if rating:
            result["cvss"] = rating
    url = _whole(item.get("nvd_url"), 200)
    if url and url.startswith(("https://", "http://")):
        result["nvd_url"] = url
    return result


def _finding(item):
    if not isinstance(item, dict):
        return None
    identifier, classification = _whole(item.get("id"), 100), _whole(item.get("classification"), 45)
    evidence = _short(item.get("evidence"), 135)
    if not identifier or not classification or not evidence:
        return None
    result = {"id": identifier, "classification": classification, "evidence": evidence}
    severity = _whole(item.get("severity"), 20)
    if severity:
        result["severity"] = severity
    return result


def _with_vendor_link(record, item):
    references = item.get("vendor_advisories")
    if isinstance(references, list):
        for reference in references[:2]:
            url = _whole(reference, 350)
            if url and _LINK.fullmatch(url):
                return {**record, "vendor_advisories": [url]}
    return record


def _with_fix(record, item):
    fix = _short(item.get("fix"), 100)
    return {**record, "fix": fix} if fix else record


def _service(item):
    if not isinstance(item, dict) or isinstance(item.get("port"), bool) or not isinstance(item.get("port"), int):
        return None
    if not 1 <= item["port"] <= 65535:
        return None
    result = {"port": item["port"]}
    for key, cap in (("state", 20), ("name", 40), ("product", 65), ("version", 45), ("tunnel", 15)):
        value = _whole(item.get(key), cap)
        if value:
            result[key] = value
    return result


def compact_assessment(result: dict, limit: int = 6500) -> str:
    """Keep full assessment coverage and report paths ahead of finding excerpts."""
    note = "Selected evidence; scanner candidates are unverified. Full findings and limits are in the saved report."
    if not isinstance(result, dict) or limit < 180:
        return _minimal(limit, note)
    output = {"truncated": True, "note": note}

    def add(key, value):
        trial = {**output, key: value}
        if value is not None and len(_encode(trial)) <= limit:
            output[key] = value
            return True
        return False

    add("assessment_status", _whole(result.get("assessment_status"), 30))
    coverage = [{"stage": _whole(s.get("stage"), 40), "status": _whole(s.get("status"), 30)}
                for s in result.get("coverage", []) if isinstance(s, dict)]
    add("coverage", coverage)
    detailed_coverage = [{**s, **({"reason": reason} if (reason := _short(raw.get("reason"), 200)) else {})}
                         for s, raw in zip(coverage, (r for r in result.get("coverage", []) if isinstance(r, dict)))]
    add("coverage", detailed_coverage)
    add("report_path", _whole(result.get("report_path"), 1200))
    add("manifest_path", _whole(result.get("manifest_path"), 1200))
    add("error", _short(result.get("error"), 230))
    add("target", _whole(result.get("target"), 1500))
    counts = result.get("counts", {})
    counts = {k: v for k, v in counts.items() if isinstance(k, str) and isinstance(v, int)} if isinstance(counts, dict) else {}
    add("counts", counts)
    items = result.get("findings", [])
    items = items if isinstance(items, list) else []
    total = counts.get("total", len(items) + result.get("omitted_findings", 0))
    add("omitted_findings", total)
    limits = result.get("limits", [])
    add("limits", [str(x) for x in limits] if isinstance(limits, list) else [])
    findings = []
    for item in items:
        if not isinstance(item, dict):
            continue
        identifier = _whole(item.get("id"), 120)
        classification = _whole(item.get("classification"), 40)
        if not identifier or not classification:
            continue
        record = {"id": identifier, "classification": classification}
        for field, cap in (("title", 180), ("severity", 30)):
            value = _short(item.get(field), cap)
            if value:
                record[field] = value
        evidence = item.get("evidence", [])
        evidence = evidence if isinstance(evidence, list) else [evidence]
        record["evidence"] = [short for v in evidence[:3]
                              if (short := _short(v if isinstance(v, str) else _encode(v), 350))]
        for field in ("sources", "fixes"):
            values = item.get(field)
            if isinstance(values, list):
                record[field] = [short for v in values[:2] if (short := _short(v, 180))]
        trial = {**output, "findings": [*findings, record], "omitted_findings": max(0, total - len(findings) - 1)}
        if len(_encode(trial)) <= limit:
            output, findings = trial, trial["findings"]
    return _encode(output)


def compact_security_result(name: str, result: dict, limit: int = 1000) -> str:
    """Return valid bounded JSON, preserving IDs with their qualifications.

    ``truncated`` is always true because this is a selected context excerpt.
    Omission counts describe supplied records, not unknown undiscovered issues.
    """
    limit = max(0, min(int(limit), 20000))
    if name == "full_security_assessment":
        return compact_assessment(result, limit)
    advisory = name == "lookup_security_advisories"
    note = _ADVISORY_NOTE if advisory else _CHECK_NOTE
    if limit < 400:
        note = "Target applicability unverified." if advisory else "Observations only; no exploit validated."
    if limit < 2 or not isinstance(result, dict):
        return _minimal(limit, note)
    output = {"truncated": True, "note": note}
    if len(_encode(output)) > limit:
        return _minimal(limit, note)

    def add(key, value):
        if value is None:
            return False
        trial = {**output, key: value}
        if len(_encode(trial)) > limit:
            return False
        output[key] = value
        return True

    def omitted(key):
        count = result.get(key, 0)
        return count if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 1_000_000 else 0

    if advisory:
        items = result.get("results")
        items = items if isinstance(items, list) else []
        total_items = len(items) + omitted("omitted_results")
        # Reserve the omission count before any optional metadata or records.
        if not add("omitted_results", total_items):
            return _encode(output)
        add("error", _short(result.get("error"), 230))
        add("source", _whole(result.get("source"), 80))
        add("query", _whole(result.get("query"), 120))
        if isinstance(result.get("total_results"), int) and not isinstance(result.get("total_results"), bool):
            add("total_results", result["total_results"])
        records = []
        for item in items[:16]:
            record = _advisory_record(item)
            if record is None:
                continue
            # Keep a usable primary-source link when it fits. Its optional size
            # must never prevent a qualified CVE record from being retained.
            for candidate in (_with_vendor_link(record, item), record):
                trial = {**output, "results": [*records, candidate], "omitted_results": total_items - len(records) - 1}
                if len(_encode(trial)) <= limit:
                    output, records = trial, trial["results"]
                    break
        add("results", records)
        return _encode(output)

    findings = result.get("findings")
    findings = findings if isinstance(findings, list) else []
    evidence = result.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    services = evidence.get("open_services")
    services = services if isinstance(services, list) else []
    total_findings = len(findings) + omitted("omitted_findings")
    total_services = len(services) + omitted("omitted_services")
    add("check", _whole(result.get("check"), 30))
    # A target URL is never truncated into a different target.
    add("target", _whole(result.get("target"), min(300, limit // 3)))
    add("check_status", _whole(result.get("check_status"), 30))
    add("error", _short(result.get("error"), 230))
    add("omitted_findings", total_findings)
    if total_services:
        add("omitted_services", total_services)
    observations = {}

    def observe(key, value):
        nonlocal observations
        if value is None:
            return False
        updated = {**observations, key: value}
        if add("evidence", updated):
            observations = updated
            return True
        return False

    # Failure reasons and measured status survive before optional metadata.
    for key in ("http_status", "certificate_verified", "verify_code", "port", "exit_code"):
        if key in evidence and _scalar(evidence[key]):
            observe(key, evidence[key])
    observe("reason", _short(evidence.get("reason"), 180))
    for key, cap in (("negotiated_version", 30), ("valid_until", 45), ("host", 253)):
        observe(key, _whole(evidence.get(key), cap))

    # Store at least the first qualified finding before large headers consume
    # the budget. Its evidence stays in the same JSON record as its ID.
    kept_findings = []
    for item in findings[:1]:
        finding = _finding(item)
        if finding:
            for candidate in (_with_fix(finding, item), finding):
                trial = {**output, "findings": [candidate], "omitted_findings": total_findings - 1}
                if len(_encode(trial)) <= limit:
                    output, kept_findings = trial, [candidate]
                    break

    ports = evidence.get("tcp_ports_checked")
    if isinstance(ports, list):
        observe("tcp_ports_checked", [p for p in ports[:16] if isinstance(p, int) and not isinstance(p, bool) and 1 <= p <= 65535])
    kept_services = []
    for item in services[:16]:
        service = _service(item)
        if service:
            updated = {**observations, "open_services": [*kept_services, service]}
            trial = {**output, "evidence": updated, "omitted_services": total_services - len(kept_services) - 1}
            if len(_encode(trial)) <= limit:
                output, observations, kept_services = trial, updated, updated["open_services"]
    if not services and "open_services" in evidence:
        observe("open_services", [])
    for item in findings[1:16]:
        finding = _finding(item)
        if finding:
            for candidate in (_with_fix(finding, item), finding):
                trial = {**output, "findings": [*kept_findings, candidate], "omitted_findings": total_findings - len(kept_findings) - 1}
                if len(_encode(trial)) <= limit:
                    output, kept_findings = trial, trial["findings"]
                    break
    add("findings", kept_findings)
    headers = evidence.get("headers")
    if isinstance(headers, dict):
        kept_headers = {}
        for key in ("server", "content-type", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options"):
            value = _short(headers.get(key), 110)
            if value and observe("headers", {**kept_headers, key: value}):
                kept_headers[key] = value
    add("checked_at", _whole(result.get("checked_at"), 40))
    add("limits", _short(result.get("limits"), 180))
    return _encode(output)
