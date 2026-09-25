"""Bounded checks for a single website/server the user is authorized to assess.

Execution status describes this check only, never completion of an assessment.
Nmap references: https://nmap.org/book/man-performance.html,
https://nmap.org/book/man-version-detection.html, and /man-output.html.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests


_MAX_BODY = 131_072
_TIMEOUT = 8
_FORBIDDEN = set(";|&$`<>\\{}()\"'* ")
_HEADERS = ("strict-transport-security", "content-security-policy", "x-frame-options",
            "x-content-type-options", "referrer-policy", "permissions-policy", "server", "content-type")


@dataclass(frozen=True)
class _Target:
    host: str
    url: str
    scheme: str
    port: int | None
    ipv6: bool


def _hostname(value: str) -> tuple[str, bool]:
    if not value or "%" in value:
        raise ValueError("Provide a single hostname or IP address; IPv6 zone identifiers are unsupported.")
    try:
        address = ipaddress.ip_address(value)
        return str(address), address.version == 6
    except ValueError:
        if ":" in value or re.fullmatch(r"[\d.\-]+", value):
            raise ValueError("Invalid IP address.") from None
    try:
        host = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid hostname.") from None
    labels = host.split(".")
    if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                              for label in labels):
        raise ValueError("Invalid hostname; networks, ranges, and wildcards are not accepted.")
    return host, False


def _parse_target(target: str) -> _Target:
    if (not isinstance(target, str) or not target or len(target) > 1500
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in _FORBIDDEN for c in target)):
        raise ValueError("Provide one hostname/IP or HTTP(S) URL without whitespace or shell syntax.")
    if "://" not in target:
        if any(c in target for c in "/?#@"):
            raise ValueError("Use a single hostname/IP, or an explicit HTTP(S) URL. CIDR networks are unsupported.")
        bare = target[1:-1] if target.startswith("[") and target.endswith("]") else target
        host, ipv6 = _hostname(bare)
        authority = f"[{host}]" if ipv6 else host
        return _Target(host, f"https://{authority}/", "https", None, ipv6)
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Only HTTP and HTTPS target URLs are supported.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing credentials are unsupported.")
    host, ipv6 = _hostname(parsed.hostname or "")
    port = parsed.port  # urlsplit validates nonnumeric/out-of-range ports here.
    if port is not None and port < 1:
        raise ValueError("Port must be between 1 and 65535.")
    authority = f"[{host}]" if ipv6 else host
    if port is not None:
        authority += f":{port}"
    return _Target(host, urlunsplit((parsed.scheme, authority, parsed.path or "/", parsed.query, "")),
                   parsed.scheme, port, ipv6)


def _ports(ports: str | None, target: _Target) -> list[int]:
    if ports is None:
        return [target.port] if target.port is not None else [22, 80, 443, 8080, 8443]
    if not isinstance(ports, str) or not re.fullmatch(r"[0-9]+(?:,[0-9]+){0,15}", ports):
        raise ValueError("ports must contain at most 16 individual TCP ports separated by commas; no ranges.")
    values = list(dict.fromkeys(int(value) for value in ports.split(",")))
    if any(not 1 <= value <= 65535 for value in values):
        raise ValueError("Every port must be between 1 and 65535.")
    return values


def _short(value, limit=180):
    return " ".join(str(value).split())[:limit]


def _finding(identifier, evidence, fix, *, classification="hardening", severity="low"):
    return {"id": identifier, "classification": classification, "severity": severity,
            "evidence": evidence, "fix": fix}


class _Title(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inside = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "title":
            self.inside = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.inside = False

    def handle_data(self, data):
        if self.inside:
            self.parts.append(data[:180])


def _web(target: _Target) -> dict:
    result = {"check_status": "complete", "evidence": {}, "findings": []}
    try:
        started = time.monotonic()
        with requests.get(target.url, timeout=(_TIMEOUT, _TIMEOUT), allow_redirects=False, stream=True,
                          headers={"User-Agent": "OrcaBonsai-Security/1.0", "Accept": "text/html,*/*;q=0.5"}) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            evidence = result["evidence"]
            evidence["http_status"] = response.status_code
            evidence["headers"] = {key: _short(headers[key], 140) for key in _HEADERS if key in headers}
            if 300 <= response.status_code < 400 and headers.get("location"):
                location = urljoin(target.url, headers["location"])
                try:
                    redirected = _parse_target(location)
                    evidence["redirect"] = {"followed": False, "same_hostname": redirected.host == target.host}
                    if len(redirected.url) <= 500:
                        evidence["redirect"]["url"] = redirected.url
                    else:
                        evidence["redirect"]["note"] = "Redirect URL omitted because it exceeds the 500-character evidence limit."
                except ValueError:
                    evidence["redirect"] = {"followed": False, "same_hostname": False,
                                            "note": "Invalid, credential-bearing, or unsupported redirect URL omitted."}
            chunks, size, truncated = [], 0, False
            for chunk in response.iter_content(chunk_size=8192):
                if time.monotonic() - started > 20:
                    truncated = True
                    result.update(check_status="partial", error="Stopped reading the response at the 20-second elapsed limit.")
                    break
                remaining = _MAX_BODY - size
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    truncated = True
                    break
                chunks.append(chunk)
                size += len(chunk)
            evidence["body_truncated"] = truncated
            content_type = headers.get("content-type", "").lower()
            is_html = "text/html" in content_type or "application/xhtml+xml" in content_type
            if is_html:
                title = _Title()
                try:
                    text = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
                except LookupError:
                    text = b"".join(chunks).decode("utf-8", errors="replace")
                title.feed(text)
                if title.parts:
                    evidence["title"] = _short(" ".join(title.parts))
            findings = result["findings"]
            successful = 200 <= response.status_code < 300
            if successful and target.scheme == "https" and not headers.get("strict-transport-security", "").strip():
                findings.append(_finding("missing-hsts", "HTTPS response has no Strict-Transport-Security header.",
                                         "Evaluate HSTS after confirming HTTPS works for the intended host and subdomains."))
            # These headers protect browser documents. An API/non-HTML response alone
            # does not establish that the site's browser pages are missing them.
            if successful and is_html:
                csp = headers.get("content-security-policy", "")
                if not csp.strip():
                    findings.append(_finding("missing-csp", "HTML response has no Content-Security-Policy header.",
                                             "Deploy a tested CSP appropriate to this page; start with report-only if needed."))
                has_frame_ancestors = bool(re.search(r"(?:^|;)\s*frame-ancestors\s+", csp, re.I))
                if not headers.get("x-frame-options", "").strip() and not has_frame_ancestors:
                    findings.append(_finding("missing-frame-policy", "HTML response has neither X-Frame-Options nor CSP frame-ancestors.",
                                             "Set CSP frame-ancestors to restrict who can frame this page."))
                if headers.get("x-content-type-options", "").strip().lower() != "nosniff":
                    findings.append(_finding("missing-nosniff", "HTML response does not set X-Content-Type-Options: nosniff.",
                                             "Serve correct Content-Type values and add X-Content-Type-Options: nosniff."))
            if response.status_code >= 400:
                result["check_status"] = "partial"
                result["error"] = f"HTTP {response.status_code}; observations describe the error response only."
            result["limits"] = "One response only; missing headers are hardening observations, not proof of an exploitable vulnerability. Redirects were not followed."
    except requests.exceptions.SSLError:
        result.update(check_status="error", error="HTTPS certificate validation or TLS connection failed; use the TLS check for verification details.")
    except requests.RequestException as exc:
        result.update(check_status="partial" if result["evidence"] else "error",
                      error=f"Web request failed ({type(exc).__name__}); no additional conclusions established.")
    return result


def _name(entries):
    return _short(", ".join(f"{key}={value}" for group in entries for key, value in group), 220)


def _tls(target: _Target) -> dict:
    port = target.port or 443
    result = {"check_status": "complete", "evidence": {"host": target.host, "port": port}, "findings": []}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target.host, port), timeout=_TIMEOUT) as connection:
            with context.wrap_socket(connection, server_hostname=target.host) as secure:
                certificate = secure.getpeercert()
                result["evidence"].update({"certificate_verified": True, "negotiated_version": secure.version(),
                                           "subject": _name(certificate.get("subject", ())),
                                           "issuer": _name(certificate.get("issuer", ())),
                                           "valid_from": _short(certificate.get("notBefore", "")),
                                           "valid_until": _short(certificate.get("notAfter", ""))})
    except ssl.SSLCertVerificationError as exc:
        reason = _short(getattr(exc, "verify_message", "Certificate validation failed."))
        result.update(check_status="complete", validation_result="Certificate validation failed with this machine's trust store; the validation check completed.")
        result["evidence"].update(certificate_verified=False, verify_code=getattr(exc, "verify_code", None), reason=reason)
        result["findings"].append(_finding("tls-certificate-validation", reason,
                                           "Check certificate hostname, validity dates, full chain, and the client's clock/trust store.",
                                           classification="configuration", severity="medium"))
    except (ssl.SSLError, OSError) as exc:
        result.update(check_status="error", error=f"TLS connection failed ({type(exc).__name__}).")
    result["limits"] = "One verified handshake; negotiated TLS version is not an enumeration of supported versions."
    return result


def _parse_nmap(xml: str | bytes, requested_ports: list[int]) -> tuple[list[dict], list[str], bool]:
    """Preserve completed port elements when Nmap was interrupted mid-document."""
    if isinstance(xml, bytes):
        xml = xml.decode("utf-8", errors="replace")
    if len(xml) > _MAX_BODY or re.search(r"<!\s*(?:ENTITY|DOCTYPE).*\[", xml, re.I | re.S):
        return [], ["Nmap XML was oversized or contained an unsupported document definition."], False
    parser = ET.XMLPullParser(events=("start", "end"))
    services, issues, complete = [], [], False
    root_seen = False
    try:
        # Incremental feeds allow completed elements to survive malformed endings.
        for offset in range(0, len(xml), 4096):
            parser.feed(xml[offset:offset + 4096])
            for event, element in parser.read_events():
                if event == "start" and not root_seen:
                    root_seen = True
                    if element.tag != "nmaprun":
                        return [], ["Response is not Nmap XML."], False
                if event != "end":
                    continue
                if element.tag == "port":
                    try:
                        port = int(element.get("portid", ""))
                    except ValueError:
                        issues.append("Nmap returned an invalid port number.")
                        continue
                    state = element.find("state")
                    if (element.get("protocol") != "tcp" or port not in requested_ports
                            or state is None or state.get("state") != "open"):
                        continue
                    service = element.find("service")
                    item = {"port": port, "state": "open"}
                    if service is not None:
                        for field, limit in (("name", 35), ("product", 55), ("version", 35), ("tunnel", 12)):
                            if service.get(field):
                                item[field] = _short(service.get(field), limit)
                    if not any(row["port"] == port for row in services):
                        services.append(item)
                elif element.tag == "host" and element.get("timedout") == "true":
                    issues.append("Nmap reached the host timeout; the port table may be incomplete.")
                elif element.tag == "finished":
                    complete = element.get("exit") == "success"
                    if not complete:
                        issues.append("Nmap did not report successful completion.")
        parser.close()
    except ET.ParseError:
        issues.append("Nmap XML was incomplete or malformed; only fully parsed port results are retained.")
        complete = False
    if not complete and not issues:
        issues.append("Nmap did not supply a successful completion record.")
    return services[:16], list(dict.fromkeys(issues)), complete


def _services(target: _Target, ports: list[int]) -> dict:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return {"check_status": "error", "error": "Run the services check under the regular Kali user account, without sudo.", "evidence": {}, "findings": []}
    nmap = shutil.which("nmap")
    if not nmap:
        return {"check_status": "error", "error": "Nmap is not installed or is not on PATH.", "evidence": {}, "findings": []}
    argv = [nmap, "-sT", "-sV", "--version-light", "-Pn", "-n", "--max-retries", "1",
            "--host-timeout", "45s", "--scan-delay", "100ms", "-p", ",".join(map(str, ports)), "-oX", "-"]
    if target.ipv6:
        argv.append("-6")
    argv.append(target.host)
    timed_out, returncode, stderr = False, None, ""
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
        xml, returncode, stderr = completed.stdout, completed.returncode, completed.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out, xml = True, exc.stdout or ""
        stderr = exc.stderr or ""
    except OSError as exc:
        return {"check_status": "error", "error": f"Could not start Nmap ({type(exc).__name__}).", "evidence": {}, "findings": []}
    observations, issues, complete = _parse_nmap(xml, ports)
    if timed_out:
        issues.insert(0, "Nmap exceeded the 60-second process limit and was terminated.")
    if returncode not in (None, 0):
        issues.append(f"Nmap exited with status {returncode}.")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    if re.search(r"timed?\s*out|timeout|quitting|failed|error", stderr, re.I):
        issues.append("Nmap reported: " + _short(stderr, 240))
    status = "complete" if complete and returncode == 0 and not issues else ("partial" if observations or timed_out or complete else "error")
    result = {"check_status": status, "evidence": {"tcp_ports_checked": ports, "open_services": observations,
                                                    "exit_code": returncode}, "findings": [],
              "limits": "Only listed TCP ports were checked. Banners/version guesses and open ports alone do not prove a vulnerability; no exploit validation was performed."}
    if issues:
        result["error"] = " ".join(issues)[:650]
    return result


def security_check(target: str, check: str = "web", ports: str | None = None) -> dict:
    """Check one explicitly authorized target, returning evidence and bounded findings."""
    try:
        if check not in {"web", "tls", "services"}:
            raise ValueError("check must be web, tls, or services.")
        parsed = _parse_target(target)
        if ports is not None and check != "services":
            raise ValueError("ports is only supported for the services check.")
        chosen_ports = _ports(ports, parsed) if check == "services" else None
        result = _web(parsed) if check == "web" else _tls(parsed) if check == "tls" else _services(parsed, chosen_ports)
        return {"check": check, "target": parsed.url if check == "web" else parsed.host,
                "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **result}
    except (ValueError, TypeError) as exc:
        return {"check_status": "error", "error": str(exc), "evidence": {}, "findings": []}
