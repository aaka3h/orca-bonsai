"""Bounded same-origin crawl and isolated ZAP passive analysis.

ZAP references: https://www.zaproxy.org/docs/api/ and
https://www.zaproxy.org/docs/desktop/cmdline/. No active scan or spider is started.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

import requests

from orca_security_checks import _parse_target

_BODY_LIMIT = 262_144
_API_LIMIT = 2_000_000
_UNSAFE_PATH = re.compile(r"(?:^|[/_.;=-])(?:logout|logoff|signout|delete|remove|destroy|unsubscribe|reset|reboot|shutdown|purge|clear|approve|reject|activate|deactivate|enable|disable|buy|purchase|checkout|submit|send|upload|execute|exec)(?:$|[/_.;=-])", re.I)
_ASSET = re.compile(r"\.(?:png|jpe?g|gif|webp|avif|ico|svg|woff2?|ttf|eot|mp[34]|avi|mov|pdf|zip|gz|tar|exe|deb|rpm|iso)$", re.I)
_HEADERS = {"content-type", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "strict-transport-security", "server"}
# These rule IDs describe browser header policy rather than validated exploits.
# Official definitions: https://www.zaproxy.org/docs/desktop/addons/passive-scan-rules/
_HEADER_POLICY_RULES = {"10019", "10020", "10021", "10035", "10038"}
_BANNER_RULES = {"10036", "10061"}


def _short(value, limit=500):
    return " ".join(str(value).split())[:limit]


def _origin(url: str) -> tuple:
    parts = urlsplit(url)
    return parts.scheme.lower(), (parts.hostname or "").lower(), parts.port or (443 if parts.scheme.lower() == "https" else 80)


def _origin_pattern(url: str) -> str:
    scheme, host, port = _origin(url)
    authority = f"[{host}]" if ":" in host else host
    suffix = f"(?::{port})?" if port == (443 if scheme == "https" else 80) else f":{port}"
    return re.escape(f"{scheme}://{authority}") + suffix + r"/.*"


def _public_url(url: str) -> str:
    """Do not persist URL credentials, fragments, or query parameter values."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        authority = host + (f":{parts.port}" if parts.port else "")
        return urlunsplit((parts.scheme, authority, parts.path, "[omitted]" if parts.query else "", ""))[:1500]
    except ValueError:
        return "[invalid URL]"


def _crawl_url(base: str, href: str, origin: tuple) -> tuple[str | None, str | None]:
    if not isinstance(href, str) or len(href) > 1500 or any(ord(c) < 32 for c in href):
        return None, "invalid URL"
    try:
        candidate = urljoin(base, href)
        parts = urlsplit(candidate)
        if parts.scheme not in {"http", "https"} or parts.username is not None or parts.password is not None:
            return None, "unsupported or credential-bearing URL"
        if _origin(candidate) != origin:
            return None, "outside the exact authorized origin"
        if parts.query:
            return None, "query URL was not requested"
        decoded = parts.path
        for _ in range(3):
            decoded = unquote(decoded)
        if _UNSAFE_PATH.search(decoded):
            return None, "possibly state-changing path was not requested"
        if _ASSET.search(decoded):
            return None, "binary/static asset was not requested"
        host = (parts.hostname or "").lower()
        authority = f"[{host}]" if ":" in host else host
        if parts.port and parts.port != (443 if parts.scheme == "https" else 80):
            authority += f":{parts.port}"
        return urlunsplit((parts.scheme, authority, parts.path or "/", "", "")), None
    except (ValueError, UnicodeError):
        return None, "invalid URL"


class _Page(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links = []
        self.forms = []
        self.form = None
        self.in_title = False
        self.title = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.in_title = True
        # Do not honor <base>; all destinations must resolve under the received URL.
        if tag in {"a", "iframe", "frame", "script"}:
            href = attrs.get("href" if tag == "a" else "src")
            if href and len(self.links) < 400:
                self.links.append(href)
        if tag == "form" and len(self.forms) < 40:
            action = urljoin(self.base, attrs.get("action", ""))
            self.form = {"page": _public_url(self.base), "action": _public_url(action),
                         "method": _short(attrs.get("method", "GET").upper(), 20),
                         "fields": [], "submitted": False}
            self.forms.append(self.form)
        if tag in {"input", "textarea", "select", "button"} and self.form is not None and len(self.form["fields"]) < 80:
            self.form["fields"].append({"name": _short(attrs.get("name", ""), 100),
                                         "type": _short(attrs.get("type", tag), 40)})

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag == "form":
            self.form = None

    def handle_data(self, data):
        if self.in_title and len(self.title) < 5:
            self.title.append(data[:180])


class _Zap:
    def __init__(self, directory: Path, deadline: float):
        self.directory = directory
        self.deadline = deadline
        self.key = secrets.token_urlsafe(36)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.address = f"http://127.0.0.1:{self.port}"
        self.ca = directory / "ca.pem"
        self.log = None
        self.process = None
        self.version = None
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"X-ZAP-API-Key": self.key})

    def api(self, component, kind, name, params=None, limit=_API_LIMIT):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Web audit time limit reached.")
        with self.session.get(f"{self.address}/JSON/{component}/{kind}/{name}/", params=params,
                              timeout=min(8, max(.2, remaining)), stream=True) as response:
            response.raise_for_status()
            chunks, size = [], 0
            for chunk in response.iter_content(8192):
                size += len(chunk)
                if size > limit or time.monotonic() > self.deadline:
                    raise RuntimeError("ZAP API result exceeded its bounded response or time limit.")
                chunks.append(chunk)
            data = json.loads(b"".join(chunks))
        if isinstance(data, dict) and "code" in data and "message" in data:
            raise RuntimeError(f"ZAP API {component}/{name}: {_short(data['code'], 80)}")
        return data

    def start(self, executable, origin_url):
        config = self.directory / "api.properties"
        config.write_text(f"api.key={self.key}\napi.addrs.addr.name=127.0.0.1\napi.addrs.addr.regex=false\n", encoding="utf-8")
        config.chmod(0o600)
        self.log = (self.directory / "startup.log").open("wb")
        command = [executable, "-daemon", "-silent", "-host", "127.0.0.1", "-port", str(self.port),
                   "-dir", str(self.directory / "home"), "-configfile", str(config),
                   "-certpubdump", str(self.ca), "-loglevel", "WARN", "-Xmx512m"]
        # Inherit the agent's process group so the GUI Stop action terminates ZAP too.
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT)
        startup_deadline = min(self.deadline, time.monotonic() + 60)
        while time.monotonic() < startup_deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"ZAP exited during startup (exit {self.process.returncode}).")
            try:
                self.version = self.api("core", "view", "version").get("version")
                if self.version:
                    break
            except (requests.RequestException, ValueError, RuntimeError):
                pass
            time.sleep(.25)
        else:
            raise TimeoutError("ZAP did not become ready within the startup deadline.")
        self.api("core", "action", "setMode", {"mode": "safe"})
        self.api("context", "action", "newContext", {"contextName": "OrcaAuthorizedOrigin"})
        self.api("context", "action", "includeInContext", {"contextName": "OrcaAuthorizedOrigin",
                 "regex": _origin_pattern(origin_url)})
        self.api("context", "action", "setContextInScope", {"contextName": "OrcaAuthorizedOrigin", "booleanInScope": "true"})
        self.api("pscan", "action", "setScanOnlyInScope", {"onlyInScope": "true"})
        self.api("pscan", "action", "setMaxBodySizeInBytes", {"maxSize": str(_BODY_LIMIT)})
        self.api("pscan", "action", "setMaxAlertsPerRule", {"maxAlerts": "30"})
        self.api("pscan", "action", "setEnabled", {"enabled": "true"})
        scanners = self.api("pscan", "view", "scanners").get("scanners", [])
        enabled = [row for row in scanners if str(row.get("enabled", "")).lower() == "true"]
        if not enabled:
            raise RuntimeError("No enabled ZAP passive scan rules were available.")
        if not self.ca.exists():
            raise RuntimeError("ZAP did not export its isolated proxy CA.")
        return len(enabled)

    def finish(self):
        waiting_deadline = min(self.deadline, time.monotonic() + 60)
        queue_empty = False
        while time.monotonic() < waiting_deadline:
            count = int(self.api("pscan", "view", "recordsToScan").get("recordsToScan", -1))
            if count == 0:
                queue_empty = True
                break
            time.sleep(.25)
        alerts = self.api("core", "view", "alerts", {"start": "0", "count": "300"}).get("alerts", [])
        return alerts, queue_empty

    def close(self):
        if self.process and self.process.poll() is None:
            try:
                self.api("core", "action", "shutdown")
            except (requests.RequestException, ValueError, RuntimeError, TimeoutError):
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
        if self.log:
            self.log.close()
        self.session.close()


def _redacted_alerts(alerts, authorized_origin):
    result = []
    for alert in alerts[:300]:
        try:
            if _origin(alert.get("url", "")) != authorized_origin:
                continue
        except ValueError:
            continue
        # Response snippets, attack payloads, cookie/auth values and bodies are deliberately
        # omitted. Rule, location, confidence and description remain reviewable evidence.
        result.append({"rule_id": _short(alert.get("pluginId", ""), 30),
                       "title": _short(alert.get("name", alert.get("alert", "")), 200),
                       "risk": _short(alert.get("risk", "Informational"), 40),
                       "confidence": _short(alert.get("confidence", ""), 40),
                       "url": _public_url(alert.get("url", "")),
                       "parameter": _short(alert.get("param", ""), 100),
                       "description": _short(alert.get("description", ""), 1600),
                       "solution": _short(alert.get("solution", ""), 1000),
                       "reference": _short(alert.get("reference", ""), 1200),
                       "cwe_id": _short(alert.get("cweid", ""), 20),
                       "evidence_note": "Raw response evidence and values omitted to avoid persisting credentials or personal data."})
    return result


def _findings(alerts):
    grouped = {}
    for alert in alerts:
        key = alert["rule_id"] or alert["title"]
        if key not in grouped:
            risk = alert["risk"].lower()
            rule = alert["rule_id"].split("-", 1)[0]
            classification = ("observation" if risk in {"informational", "info"} or rule in _BANNER_RULES
                              else "hardening" if rule in _HEADER_POLICY_RULES else "candidate")
            grouped[key] = {"id": "zap-" + key, "title": alert["title"], "classification": classification,
                            "severity": risk if risk in {"high", "medium", "low"} else "informational",
                            "evidence": {"rule_id": alert["rule_id"], "confidence": alert["confidence"],
                                         "urls": [], "description": alert["description"]},
                            "fix": alert["solution"], "references": [alert["reference"]] if alert["reference"] else []}
        locations = grouped[key]["evidence"]["urls"]
        if alert["url"] not in locations and len(locations) < 12:
            locations.append(alert["url"])
    return list(grouped.values())


def run_web_audit(target: str, output_dir: Path, timeout: int = 300, page_limit: int = 30) -> dict:
    """Crawl explicit same-origin GET pages, record forms, and run passive rules."""
    result = {"status": "blocked", "tool": "web_audit", "summary": "Web audit did not start.",
              "observations": {"pages": [], "forms": [], "skipped": []}, "findings": [], "artifacts": [],
              "limits": ["Unauthenticated GET crawl only; forms were recorded but never submitted.",
                         "ZAP passive alerts are observations, hardening suggestions or candidates; no exploit is confirmed by this analysis.",
                         "JavaScript-generated routes, query URLs and possibly state-changing paths were not requested."]}
    try:
        parsed = _parse_target(target)
        timeout = max(10, min(int(timeout), 1800))
        page_limit = max(1, min(int(page_limit), 100))
        origin = _origin(parsed.url)
        start_url, reason = _crawl_url(parsed.url, parsed.url, origin)
        if reason:
            raise ValueError(f"Starting URL is unsuitable for the GET-only crawl: {reason}.")
    except (ValueError, TypeError) as exc:
        result["error"] = _short(exc)
        return result
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    audit_dir = Path(tempfile.mkdtemp(prefix="web-audit-", dir=output_dir))
    audit_dir.chmod(0o700)
    private = audit_dir / "work"
    private.mkdir(mode=0o700)
    deadline = time.monotonic() + timeout
    obs = result["observations"]
    obs["scope"] = {"origin": urlunsplit((parsed.scheme, urlsplit(parsed.url).netloc, "", "", "")),
                    "page_limit": page_limit, "timeout_seconds": timeout, "methods": ["GET"]}
    obs["passive_analysis"] = {"status": "blocked", "engine": "ZAP"}
    zap = None
    session = requests.Session()
    session.trust_env = False
    session.headers.update({"User-Agent": "OrcaBonsai-AuthorizedAudit/1.0", "Accept": "text/html,application/json,text/plain;q=0.8,*/*;q=0.1"})
    incomplete = []
    alerts = []
    try:
        executable = shutil.which("zaproxy") or shutil.which("owasp-zap")
        if executable:
            zap = _Zap(private, deadline)
            try:
                rules = zap.start(executable, obs["scope"]["origin"])
                obs["passive_analysis"].update(status="running", version=zap.version, enabled_rules=rules)
                session.proxies = {"http": zap.address, "https": zap.address}
                session.verify = str(zap.ca)
            except (OSError, requests.RequestException, ValueError, RuntimeError, TimeoutError) as exc:
                reason = f"ZAP passive analysis unavailable: {type(exc).__name__}: {_short(exc, 180)}"
                obs["passive_analysis"].update(status="blocked", reason=reason)
                incomplete.append(reason)
                zap.close()
                zap = None
        else:
            reason = "ZAP executable is not installed; only the bounded page/form inventory ran."
            obs["passive_analysis"]["reason"] = reason
            incomplete.append(reason)
        queue = deque([start_url])
        seen = set()
        queued = {start_url}
        while queue and len(seen) < page_limit and time.monotonic() < deadline:
            url = queue.popleft()
            seen.add(url)
            page = {"url": _public_url(url), "method": "GET"}
            obs["pages"].append(page)
            try:
                session.cookies.clear()
                remaining = max(.2, deadline - time.monotonic())
                with session.get(url, allow_redirects=False, stream=True, timeout=min(8, remaining)) as response:
                    page.update(status=response.status_code, headers={k.lower(): _short(v, 500) for k, v in response.headers.items() if k.lower() in _HEADERS})
                    page["cookie_names"] = [_short(k, 100) for k in response.cookies.keys()][:30]
                    body, truncated = bytearray(), False
                    for chunk in response.iter_content(8192):
                        room = _BODY_LIMIT - len(body)
                        body.extend(chunk[:room])
                        if len(chunk) > room or time.monotonic() >= deadline:
                            truncated = True
                            break
                    page["body_truncated"] = truncated
                    if truncated:
                        incomplete.append("At least one response exceeded the body or time limit.")
                    links = []
                    if 300 <= response.status_code < 400 and response.headers.get("location"):
                        links.append(response.headers["location"])
                        page["redirect"] = _public_url(urljoin(url, response.headers["location"]))
                    if response.status_code >= 400:
                        incomplete.append(f"HTTP {response.status_code} encountered at {_public_url(url)}.")
                    if "html" in response.headers.get("content-type", "").lower():
                        document = _Page(url)
                        try:
                            text = body.decode(response.encoding or "utf-8", errors="replace")
                        except LookupError:
                            text = body.decode("utf-8", errors="replace")
                        document.feed(text)
                        page["title"] = _short(" ".join(document.title), 180)
                        obs["forms"].extend(document.forms)
                        links.extend(document.links)
                    for href in links:
                        candidate, reason = _crawl_url(url, href, origin)
                        if reason:
                            if len(obs["skipped"]) < 200:
                                obs["skipped"].append({"url": _public_url(urljoin(url, href)), "reason": reason})
                        elif candidate not in queued:
                            if len(queued) < page_limit * 5:
                                queue.append(candidate)
                                queued.add(candidate)
            except (requests.RequestException, ValueError) as exc:
                page["error"] = f"Request failed ({type(exc).__name__})."
                incomplete.append(f"A page request failed ({type(exc).__name__}).")
        if queue:
            incomplete.append(f"Crawl stopped at its page/time limit with {len(queue)} discovered URLs still pending.")
        obs["crawl"] = {"requested_pages": len(seen), "discovered_urls": len(queued), "pending_urls": len(queue),
                        "complete_within_scope": not queue and not any("error" in p for p in obs["pages"])}
        if zap:
            try:
                raw_alerts, complete = zap.finish()
                alerts = _redacted_alerts(raw_alerts, origin)
                obs["passive_analysis"].update(status="complete" if complete else "partial", alert_count=len(alerts))
                if not complete:
                    incomplete.append("ZAP passive queue did not finish within its deadline.")
                if len(raw_alerts) >= 300:
                    incomplete.append("ZAP alert retrieval was capped at 300 alerts.")
            except (requests.RequestException, ValueError, RuntimeError, TimeoutError) as exc:
                reason = f"ZAP passive results incomplete ({type(exc).__name__})."
                obs["passive_analysis"].update(status="partial", reason=reason)
                incomplete.append(reason)
        result["findings"] = _findings(alerts)
        result["status"] = "partial" if incomplete else "complete"
        if not obs["pages"] or not any("status" in p for p in obs["pages"]):
            result["status"] = "blocked"
        result["summary"] = f"Requested {len(obs['pages'])} pages; recorded {len(obs['forms'])} forms without submitting them; {len(result['findings'])} grouped ZAP passive observations, hardening suggestions or candidates."
        result["limits"].extend(dict.fromkeys(incomplete))
    finally:
        session.close()
        if zap:
            zap.close()
        # Never retain ZAP history databases, generated CA/private keys, API key or raw
        # startup logs: they can contain response bodies, cookies and authorization data.
        shutil.rmtree(private, ignore_errors=True)
    evidence_path = audit_dir / "web-audit.json"
    alerts_path = audit_dir / "zap-alerts-redacted.json"
    result["artifacts"] = [str(evidence_path), str(alerts_path)]
    for path, data in [(evidence_path, result), (alerts_path, alerts)]:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
        path.chmod(0o600)
    return result
