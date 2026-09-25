"""Artifact-backed, single-host scanner adapters for authorized assessments.

The adapters never infer that a scanner match proves exploitation. External
programs inherit the agent process group so the GUI Stop action reaches them.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

import requests

from orca_security_checks import _parse_target

WORK = Path(__file__).resolve().parent.parent / "work"
TEMPLATE_ROOT = WORK / "nuclei-templates"
NUCLEI_STATE = WORK / "nuclei-state"
MAX_FINDINGS = 100


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _short(value, limit=600):
    return " ".join(str(value).split())[:limit]


def _directory(path):
    path = Path(path).resolve()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _write(path, content):
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "w", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(content if isinstance(content, str) else json.dumps(content, indent=2, ensure_ascii=False))
    return str(path.resolve())


def _read(path, limit=2_000_000):
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _run(argv, logfile, timeout, *, env=None):
    """Record full output without an in-memory pipe or a detached process group."""
    _write(logfile, "")
    start = time.monotonic()
    try:
        with Path(logfile).open("a", encoding="utf-8") as log:
            done = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                  timeout=max(1, timeout), check=False, env=env, umask=0o077)
        return {"exit_code": done.returncode, "timed_out": False,
                "elapsed_seconds": round(time.monotonic() - start, 2)}
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "timed_out": True,
                "elapsed_seconds": round(time.monotonic() - start, 2),
                "error": f"Process exceeded its {timeout}-second budget; retained all available output."}
    except OSError as exc:
        return {"exit_code": None, "timed_out": False, "error": f"Could not start tool ({type(exc).__name__}): {exc}"}


def _base(tool, status="blocked", summary="", **kwargs):
    return {"status": status, "tool": tool, "summary": summary, "findings": [], "artifacts": [], "limits": [], **kwargs}


def _prepare(target, output_dir, tool):
    try:
        parsed = _parse_target(target)
        directory = _directory(output_dir)
        executable = shutil.which(tool)
        if not executable:
            return None, directory, None, _base(tool, summary=f"{tool} is not installed.", error=f"Missing executable: {tool}.")
        return parsed, directory, executable, None
    except (ValueError, TypeError, OSError) as exc:
        return None, None, None, _base(tool, summary="Scan could not start.", error=str(exc))


def _version(argv):
    try:
        process = subprocess.run(argv, capture_output=True, text=True, timeout=15, check=False)
        text = re.sub(r"\x1b\[[\d;]*m", "", process.stdout + process.stderr)
        if Path(argv[0]).name in {"zaproxy", "zap.sh"}:
            match = re.search(r"^\s*(?:ZAP\s+)?(\d+\.\d+\.\d+)\s*$", text, re.M)
            return "ZAP " + match.group(1) if match else "unavailable"
        return next((line.strip() for line in text.splitlines() if re.search(r"version|Nikto v", line, re.I)), text.splitlines()[0] if text else "unknown")[:180]
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def inventory():
    """Versions, cached distribution candidates, and independently checked releases."""
    tools = {}
    for tool, flag in (("nmap", "--version"), ("nikto", "-Version"), ("nuclei", "-version"), ("zaproxy", "-version")):
        executable = shutil.which(tool)
        row = {"installed": bool(executable), "path": executable,
               "installed_version": _version([executable, flag]) if executable else None,
               "upstream_latest": None, "latest_status": "not verified"}
        try:
            output = subprocess.run(["apt-cache", "policy", tool], capture_output=True, text=True, timeout=10, check=False).stdout
            for label, field in (("Installed", "apt_installed"), ("Candidate", "apt_candidate")):
                match = re.search(rf"^\s*{label}:\s*(.+)$", output, re.M)
                row[field] = match.group(1) if match else None
        except (OSError, subprocess.TimeoutExpired):
            row["apt_candidate"] = None
        tools[tool] = row
    # These release lookups do not install software or refresh the OS package list.
    for tool, endpoint in (("nuclei", "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest"),
                           ("nikto", "https://api.github.com/repos/sullo/nikto/releases/latest"),
                           ("zaproxy", "https://api.github.com/repos/zaproxy/zaproxy/releases/latest")):
        try:
            response = requests.get(endpoint, timeout=8, headers={"User-Agent": "OrcaBonsai/1.0", "Accept": "application/vnd.github+json"})
            response.raise_for_status()
            release = response.json()
            tag = release.get("tag_name")
            if isinstance(tag, str) and re.fullmatch(r"v?\d+(?:\.\d+){1,3}", tag):
                tools[tool]["upstream_latest"] = tag
                tools[tool]["release_source"] = release.get("html_url", endpoint)
                match = re.search(r"\d+(?:\.\d+){1,3}", tools[tool]["installed_version"] or "")
                tools[tool]["latest_status"] = ("matches latest published release" if match and match.group() == tag.lstrip("v")
                                                  else "installed version differs; review package update separately")
        except (requests.RequestException, ValueError, TypeError):
            pass
    return _base("inventory", "complete", "Recorded installed tools and available version information.", tools=tools,
                 checked_at=_now(), limits=["APT candidates use the local package index; package indexes and OS binaries were not changed.",
                                           "An unavailable upstream release lookup is recorded as not verified. Nmap has no upstream comparison here."])


def _port_spec(value):
    if value == "all":
        return "1-65535", 65535
    if not isinstance(value, str) or len(value) > 4096 or not re.fullmatch(r"\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*", value):
        raise ValueError("ports must be all or comma-separated TCP ports/ranges.")
    selected = set()
    for section in value.split(","):
        numbers = [int(part) for part in section.split("-")]
        low, high = (numbers[0], numbers[-1])
        if not 1 <= low <= high <= 65535:
            raise ValueError("Every TCP port/range must be within 1-65535 and ascending.")
        selected.update(range(low, high + 1))
    return value, len(selected)


def _nmap_result(path):
    """Retain parsed port records if the XML ends mid-scan, without a 16-port cap."""
    raw = _read(path, 24_000_000)
    rows, issues, complete, scanned, up = [], [], False, 0, 0
    if not raw or re.search(r"<!\s*(?:ENTITY|DOCTYPE).*\[", raw, re.I | re.S):
        return rows, ["Missing or unsupported Nmap XML."], False, scanned, up
    parser = ET.XMLPullParser(events=("start", "end"))
    root_seen = False
    malformed = False
    try:
        parser.feed(raw)
        parser.close()
    except ET.ParseError:
        malformed = True
    try:
        for event, element in parser.read_events():
            if event == "start" and not root_seen:
                root_seen = True
                if element.tag != "nmaprun":
                    return [], ["Response is not Nmap XML."], False, 0, 0
            if event != "end":
                continue
            if element.tag == "port":
                scanned += 1
                state = element.find("state")
                if state is not None and state.get("state") == "open" and element.get("protocol") == "tcp":
                    try:
                        port = int(element.get("portid", ""))
                    except ValueError:
                        continue
                    if not 1 <= port <= 65535:
                        continue
                    item = {"port": port, "state": "open"}
                    service = element.find("service")
                    if service is not None:
                        for key in ("name", "product", "version", "extrainfo", "tunnel", "method", "conf"):
                            if service.get(key):
                                item[key] = _short(service.get(key), 160)
                        item["cpe"] = [child.text[:250] for child in service.findall("cpe") if child.text][:10]
                    rows.append(item)
                element.clear()
            elif element.tag == "extraports":
                try:
                    scanned += int(element.get("count", "0"))
                except ValueError:
                    pass
            elif element.tag == "host" and element.get("timedout") == "true":
                issues.append("Nmap reached its host deadline; port coverage is incomplete.")
            elif element.tag == "hosts":
                up = int(element.get("up", "0"))
            elif element.tag == "finished":
                complete = element.get("exit") == "success"
                if not complete:
                    issues.append(_short(element.get("errormsg", "Nmap did not report successful completion.")))
    except (ET.ParseError, ValueError):
        malformed = True
    if malformed:
        issues.append("Nmap output is incomplete; only complete port records were retained.")
        complete = False
    if not complete and not issues:
        issues.append("Nmap completion record is missing.")
    return rows, issues, complete and not issues, scanned, up


def run_services(target: str, output_dir: Path, ports: str = "all", timeout: int = 1800):
    parsed, directory, executable, error = _prepare(target, output_dir, "nmap")
    if error:
        return error
    try:
        spec, requested = _port_spec(ports)
        budget = max(5, min(int(timeout), 7200))
    except (ValueError, TypeError) as exc:
        return _base("nmap", summary="Invalid scan settings.", error=str(exc))
    start = time.monotonic()
    # Allocate most of the budget to discovery, leaving time for version probes.
    discovery_budget = max(3, min(1220, int(budget * .72)))
    discovery_xml, discovery_log = directory / "nmap-discovery.xml", directory / "nmap-discovery.log"
    _write(discovery_xml, "")
    common = [executable, "-sT", "-Pn", "-n", "--max-retries", "1", "--max-rate", "100"]
    argv = common + ["--host-timeout", f"{max(1, discovery_budget - 5)}s", "-p-" if ports == "all" else "-p", *([] if ports == "all" else [spec]), "-oX", str(discovery_xml)]
    if parsed.ipv6:
        argv.append("-6")
    argv.append(parsed.host)
    discovery = _run(argv, discovery_log, discovery_budget)
    rows, issues, complete, scanned, up = _nmap_result(discovery_xml)
    artifacts = [str(discovery_xml), str(discovery_log)]
    if discovery.get("error"):
        issues.append(discovery["error"])
    if discovery["exit_code"] not in (0, None):
        issues.append(f"Discovery exited with status {discovery['exit_code']}.")
    if scanned < requested or up < 1:
        issues.append(f"Nmap recorded {scanned} of {requested} requested TCP ports; full coverage was not established.")
    discovery_complete = complete and discovery["exit_code"] == 0 and scanned >= requested and up >= 1
    service_complete = not rows
    if rows:
        version_xml, version_log = directory / "nmap-services.xml", directory / "nmap-services.log"
        _write(version_xml, "")
        remaining = max(1, int(budget - (time.monotonic() - start)))
        open_ports = sorted({item["port"] for item in rows})
        service_argv = common + ["-sV", "--version-light", "--host-timeout", f"{max(1, remaining - 5)}s", "-p", ",".join(map(str, open_ports)), "-oX", str(version_xml)]
        if parsed.ipv6:
            service_argv.append("-6")
        service_argv.append(parsed.host)
        service = _run(service_argv, version_log, remaining)
        versions, version_issues, version_complete, version_scanned, version_up = _nmap_result(version_xml)
        by_port = {item["port"]: item for item in rows}
        by_port.update({item["port"]: item for item in versions})
        rows = [by_port[port] for port in sorted(by_port)]
        issues.extend(version_issues)
        if service.get("error"):
            issues.append(service["error"])
        service_complete = version_complete and service["exit_code"] == 0 and version_scanned >= len(open_ports) and version_up >= 1
        if not service_complete:
            issues.append("Light service identification did not finish for every discovered open port.")
        artifacts.extend([str(version_xml), str(version_log)])
    full = {"target": parsed.host, "ports_requested": spec, "requested_port_count": requested,
            "ports_recorded": scanned, "open_port_count": len(rows), "open_services": rows,
            "discovery_complete": discovery_complete, "service_identification_complete": service_complete}
    artifacts.append(_write(directory / "nmap-observations.json", full))
    status = "complete" if discovery_complete and service_complete and not issues else "partial" if scanned or rows or discovery["timed_out"] else "blocked"
    limited = {**full, "open_services": rows[:100]}
    if len(rows) > 100:
        limited["additional_services_in_artifact"] = len(rows) - 100
    return _base("nmap", status, f"Recorded {len(rows)} open TCP ports; {scanned}/{requested} requested port states recorded.",
                 observations=limited, observations_artifact=str(directory / "nmap-observations.json"), artifacts=artifacts, error=" ".join(dict.fromkeys(issues)) if issues else None,
                 limits=["TCP connect discovery only; UDP, authentication, exploitation, and OS guessing are not included.",
                         "Service banners are observations, not confirmed vulnerabilities.", *list(dict.fromkeys(issues))])


def _nikto_classification(message):
    text = str(message).lower()
    if re.search(r"(?:header.*(?:missing|not (?:defined|present|set))|(?:missing|not (?:defined|present|set)).*header)", text) and any(header in text for header in ("x-frame-options", "x-content-type-options", "content-security-policy", "referrer-policy", "strict-transport-security")):
        return "hardening"
    if re.fullmatch(r"(?:server(?: banner)?|the server banner)\s*(?::|is\b).*", text) or re.search(r"redirect(?:s|ed)? to https://", text):
        return "observation"
    return "candidate"


def _nikto_findings(raw):
    try:
        decoded = json.loads(raw)
    except (ValueError, TypeError):
        return [], [], False
    hosts = decoded if isinstance(decoded, list) else [decoded] if isinstance(decoded, dict) else []
    findings = []
    valid = bool(hosts)
    for host in hosts:
        if not isinstance(host, dict) or not isinstance(host.get("vulnerabilities"), list):
            valid = False
            continue
        if not host.get("end_time"):
            valid = False
        for item in host["vulnerabilities"]:
            if not isinstance(item, dict) or not item.get("msg"):
                continue
            refs = item.get("references", [])
            refs = refs if isinstance(refs, list) else [refs] if refs else []
            findings.append({"id": "nikto-" + _short(item.get("id", len(findings)), 100),
                             "title": _short(item["msg"], 180), "classification": _nikto_classification(item["msg"]), "severity": "unknown",
                             "evidence": _short(f"{item.get('method', '')} {item.get('url', '')}: {item['msg']}", 1000),
                             "references": [_short(ref, 400) for ref in refs][:8],
                             "fix": "Review this scanner match and validate applicability before selecting a fix."})
    return findings, hosts, valid


def _nikto_policy(directory):
    """Constrain the installed database; tuning alone matches mixed risk tags."""
    locations = [Path("/var/lib/nikto"), Path("/usr/share/nikto")]
    installation = next((p for p in locations if (p / "databases/db_tests").is_file()), None)
    if installation is None:
        raise ValueError("Cannot locate the installed Nikto database for request inspection.")
    destination = _directory(directory / "nikto-database")
    skipped, selected, copied = [], 0, []
    for source in sorted((installation / "databases").glob("db_*")):
        if not source.is_file() or source.is_symlink():
            continue
        contents = source.read_text(encoding="utf-8", errors="strict")
        _write(destination / source.name, contents)
        copied.append({"name": source.name, "sha256": hashlib.sha256(contents.encode()).hexdigest()})
    for line in _read(destination / "db_tests", 16_000_000).splitlines():
        if not line.startswith('"'):
            continue
        fields = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"(?:,|$)', line)
        identifier = re.match(r'^"(\d+)"', line)
        if identifier is None:
            raise ValueError("An installed Nikto test could not be identified for request inspection.")
        allowed = len(fields) == 9
        if allowed:
            categories, uri, method, data, headers = fields[2], fields[3], fields[4], fields[7], fields[8]
            allowed = (bool(categories) and set(categories) <= set("123b") and method.upper() in {"GET", "HEAD"}
                       and not data and not headers and "?" not in uri and ".." not in uri and "%" not in uri
                       and not re.search(r"://|@(?:LFI|RFI|JUNK)", uri, re.I)
                       and not re.search(r"(?:^|[/_.-])(?:delete|logout|reboot|shutdown|reset|remove|purge|kill)(?:$|[/_.-])", re.sub(r"@[A-Z0-9_]+", "/", uri), re.I))
        if allowed:
            selected += 1
        else:
            skipped.append(identifier.group(1))
    if not selected:
        raise ValueError("No eligible read-only Nikto database tests were found.")
    config = directory / "nikto-config.conf"
    settings = {"EXECDIR": str(installation), "PLUGINDIR": str(installation / "plugins"), "DBDIR": str(destination),
                "TEMPLATEDIR": str(installation / "templates"), "NIKTODTD": str(installation / "templates/nikto.dtd"),
                "DEFAULTHTTPVER": "1.1", "CHECKMETHODS": "GET", "LW_SSL_ENGINE": "auto", "UPDATES": "no",
                "PROMPTS": "no", "FAILURES": "20", "SKIPIDS": " ".join(skipped)}
    _write(config, "".join(f"{key}={value}\n" for key, value in settings.items()))
    manifest = {"selected_database_tests": selected, "excluded_database_tests": len(skipped), "skipped_ids": skipped,
                "database_files": copied, "policy": "GET/HEAD; only123b categories; no mixed exploit tags, credentials, request bodies, injected headers, queries, traversal, callbacks, or custom user databases."}
    artifact = _write(directory / "nikto-test-selection.json", manifest)
    return {"config": str(config), "manifest": artifact, "selected_database_tests": selected,
            "excluded_database_tests": len(skipped)}


def run_nikto(target, output_dir, timeout=900):
    parsed, directory, executable, error = _prepare(target, output_dir, "nikto")
    if error:
        return error
    try:
        budget = max(5, min(int(timeout), 3600))
    except (ValueError, TypeError):
        return _base("nikto", summary="Invalid timeout.", error="timeout must be a number of seconds.")
    try:
        policy = _nikto_policy(directory)
    except (OSError, ValueError) as exc:
        return _base("nikto", summary="Could not inspect the installed Nikto checks.", error=str(exc))
    raw, log = directory / "nikto.json", directory / "nikto.log"
    _write(raw, "")
    argv = [executable, "-config", policy["config"], "-host", parsed.url, "-ask", "no", "-nocheck", "-nointeractive", "-nocookies",
            "-Tuning", "123b", "-Plugins", "tests;ssl;sitefiles;content_search;report_json",
            "-Pause", "0.2", "-maxtime", f"{max(1, budget - 5)}s", "-timeout", "10", "-Format", "json", "-output", str(raw)]
    process = _run(argv, log, budget)
    findings, hosts, valid = _nikto_findings(_read(raw, 16_000_000))
    logtext = _read(log, 16_000_000)
    issues = []
    for line in logtext.splitlines():
        if re.search(r"\bERROR:|maximum execution time|scan terminated|too many errors", line, re.I):
            issues.append(_short(line, 350))
    if process.get("error"):
        issues.append(process["error"])
    if not valid:
        issues.append("A complete Nikto JSON host report was not produced; inspect the retained log for partial evidence.")
    if process["exit_code"] not in (0, None):
        issues.append(f"Nikto exited with status {process['exit_code']}.")
    # Nikto writes its JSON only at close; retain candidate lines on interruption.
    if not findings and not valid:
        for line in logtext.splitlines():
            if re.match(r"\+ /[^\s]*:", line):
                findings.append({"id": f"nikto-partial-{len(findings) + 1}", "title": _short(line[2:], 180),
                                 "classification": "candidate", "severity": "unknown", "evidence": _short(line, 1000),
                                 "fix": "Validate this partial scanner observation; the scan did not finish."})
    saved = _write(directory / "nikto-findings.json", findings)
    status = "complete" if valid and process["exit_code"] == 0 and not issues else "partial" if findings or hosts or logtext or process["timed_out"] else "blocked"
    return _base("nikto", status, f"Nikto recorded {len(findings)} candidate observations.", findings=findings[:MAX_FINDINGS],
                 observations={"finding_count": len(findings), "hosts_reported": len(hosts), "exit_code": process["exit_code"],
                               "selected_database_tests": policy["selected_database_tests"], "excluded_database_tests": policy["excluded_database_tests"]},
                 artifacts=[str(raw), str(log), saved, policy["config"], policy["manifest"]], findings_artifact=saved, error=" ".join(dict.fromkeys(issues)) if issues else None,
                 limits=["Selected configuration, identification, and disclosure checks only; no injection, exploit, password, or denial-of-service tests.",
                         "Redirects and discovered external links are not followed; authenticated application coverage is not included.", *list(dict.fromkeys(issues))])


def _nuclei_env():
    env = dict(os.environ)
    for key in list(env):
        if key.startswith(("NUCLEI_", "PDCP_", "GITHUB_", "GITLAB_", "AWS_", "AZURE_")):
            env.pop(key, None)
    for field, dirname in (("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data")):
        env[field] = str(_directory(NUCLEI_STATE / dirname))
    for source in ("GITHUB", "GITLAB", "AWS", "AZURE"):
        env[f"DISABLE_NUCLEI_TEMPLATES_{source}_DOWNLOAD"] = "true"
    env["NUCLEI_TEMPLATES_DIR"] = str(TEMPLATE_ROOT)
    return env


def update_nuclei_templates(output_dir, timeout=240):
    """Update official templates in this workspace, independent of user config."""
    directory = _directory(output_dir)
    executable = shutil.which("nuclei")
    if not executable:
        return _base("nuclei-template-update", summary="Nuclei is not installed.")
    config, log = directory / "nuclei-config.yaml", directory / "nuclei-template-update.log"
    _write(config, "{}\n")
    env = _nuclei_env()
    _directory(TEMPLATE_ROOT)
    run = _run([executable, "-config", str(config), "-ut", "-ud", str(TEMPLATE_ROOT), "-nc"], log, timeout, env=env)
    text = _read(log)
    versions = re.findall(r"(?:nuclei-templates\s+(?:are\s+)?(?:updated to|installed|version|latest version)?\s*|version\s*[:=]\s*)(v\d+(?:\.\d+){2})", text, re.I)
    config_path = NUCLEI_STATE / "config" / "nuclei" / ".templates-config.json"
    try:
        metadata = json.loads(_read(config_path))
    except ValueError:
        metadata = {}
    version = metadata.get("nuclei-templates-version") or (versions[-1] if versions else None)
    latest = metadata.get("nuclei-templates-latest-version")
    available = (TEMPLATE_ROOT / "http").is_dir()
    success = run["exit_code"] == 0 and available and not re.search(r"\[(?:ERR|FTL)\]|could not|failed", text, re.I)
    manifest = {"checked_at": _now(), "source": "https://github.com/projectdiscovery/nuclei-templates",
                "directory": str(TEMPLATE_ROOT), "installed_template_version": version,
                "latest_template_version_reported": latest, "update_completed": success,
                "engine_version": _version([executable, "-version"]), "process": run}
    artifact = _write(directory / "nuclei-template-version.json", manifest)
    return _base("nuclei-template-update", "complete" if success else "partial" if available else "blocked",
                 f"Official template update {'completed' if success else 'not completed'}; installed version {version or 'unknown'}.",
                 observations=manifest, artifacts=[str(log), artifact],
                 error=None if success else run.get("error", "Template update did not complete; check its log."))


_UNSAFE_TAGS = {"dos", "fuzz", "fuzzing", "dast", "intrusive", "bruteforce", "brute-force", "default-login",
                "rce", "sqli", "ssrf", "xxe", "lfi", "rfi", "smb", "oast", "file-upload", "upload", "traversal"}


def _template_allowed(document):
    """Static, bounded HTTP retrieval only; no external callbacks or code paths."""
    if not isinstance(document, dict) or set(document) - {"id", "info", "http"}:
        return False
    info = document.get("info", {})
    if not isinstance(info, dict):
        return False
    tags = info.get("tags", [])
    tags = tags.split(",") if isinstance(tags, str) else tags if isinstance(tags, list) else []
    if _UNSAFE_TAGS.intersection(str(tag).lower().strip() for tag in tags):
        return False
    requests_ = document.get("http")
    if not isinstance(requests_, list) or not 1 <= len(requests_) <= 4:
        return False
    count = 0
    for request in requests_:
        if not isinstance(request, dict) or set(request) - {"method", "path", "matchers", "extractors", "matchers-condition", "stop-at-first-match", "redirects", "max-redirects", "host-redirects"}:
            return False
        if request.get("method", "GET") not in {"GET", "HEAD"} or request.get("redirects") or request.get("host-redirects"):
            return False
        paths = request.get("path", [])
        if not isinstance(paths, list) or not paths:
            return False
        count += len(paths)
        if count > 8:
            return False
        for path in paths:
            if not isinstance(path, str) or not re.fullmatch(r"\{\{(?:BaseURL|RootURL)\}\}(?:/[A-Za-z0-9._~/-]*)?", path):
                return False
            tail = path.split("}}", 1)[1]
            if ".." in tail or "//" in tail or re.search(r"(?:^|[/_.-])(?:delete|logout|reboot|shutdown|reset|remove|purge|kill)(?:$|[/_.-])", tail, re.I):
                return False
        for entry in request.get("matchers", []) + request.get("extractors", []):
            if not isinstance(entry, dict) or entry.get("type") not in {"word", "regex", "status", "size", "binary", "kval", "json", "xpath"}:
                return False
    return True


def _select_templates(output_dir):
    try:
        import yaml
    except ImportError:
        return [], {"error": "PyYAML is required to inspect template requests before scanning."}
    directory = _directory(tempfile.mkdtemp(prefix="nuclei-selected-", dir=output_dir))
    selected, rejected, requests_total = [], 0, 0
    for source in sorted((TEMPLATE_ROOT / "http").rglob("*.yaml")):
        if source.is_symlink() or source.stat().st_size > 131072:
            rejected += 1
            continue
        text = _read(source, 131073)
        try:
            document = yaml.safe_load(text)
            allowed = _template_allowed(document) and bool(re.search(r"^# digest:\s*\S+", text, re.M))
        except (yaml.YAMLError, TypeError, AttributeError):
            allowed = False
        if not allowed:
            rejected += 1
            continue
        digest = hashlib.sha256(text.encode()).hexdigest()
        path = directory / (digest + ".yaml")
        _write(path, text)
        count = sum(len(row["path"]) for row in document["http"])
        requests_total += count
        selected.append({"id": document.get("id"), "source": str(source.relative_to(TEMPLATE_ROOT)),
                         "sha256": digest, "path": str(path), "maximum_requests": count})
    manifest = {"directory": str(directory), "selected_count": len(selected), "excluded_count": rejected, "maximum_requests": requests_total,
                "templates": selected, "policy": "Signed official static GET/HEAD templates; <=8 requests each; no bodies, dynamic paths, raw requests, code, redirects, fuzzing, or callbacks."}
    _write(Path(output_dir) / "nuclei-template-selection.json", manifest)
    return selected, manifest


def _nuclei_findings(path):
    rows, issues = [], []
    try:
        source = Path(path).open(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"Cannot read Nuclei JSONL output: {exc}"]
    with source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except ValueError:
                issues.append(f"Invalid or truncated result at JSONL line {number}.")
                continue
            if not isinstance(item, dict) or not isinstance(item.get("info"), dict):
                issues.append(f"Unrecognized result at JSONL line {number}.")
                continue
            info = item["info"]
            references = info.get("reference", [])
            references = references if isinstance(references, list) else [references] if references else []
            severity = str(info.get("severity", "unknown")).lower()
            rows.append({"id": "nuclei-" + _short(item.get("template-id", number), 160),
                         "title": _short(info.get("name", item.get("template-id", "Template match")), 180),
                         "classification": "observation" if severity == "info" else "candidate", "severity": severity,
                         "evidence": _short(json.dumps({"matched_at": item.get("matched-at"), "matcher": item.get("matcher-name"),
                                                         "extracted": item.get("extracted-results", []), "template": item.get("template-id")}, ensure_ascii=False), 1200),
                         "fix": _short(info.get("remediation", "Validate template applicability and follow vendor guidance."), 500),
                         "references": [_short(value, 400) for value in references][:8]})
    return rows, issues


def run_nuclei(target, output_dir, timeout=900):
    parsed, directory, executable, error = _prepare(target, output_dir, "nuclei")
    if error:
        return error
    try:
        budget = max(5, min(int(timeout), 3600))
    except (TypeError, ValueError):
        return _base("nuclei", summary="Invalid timeout.", error="timeout must be a number of seconds.")
    update = update_nuclei_templates(directory)
    if update["status"] == "blocked":
        return _base("nuclei", summary="No official template pack is available.", error=update.get("error"), artifacts=update["artifacts"])
    selected, manifest = _select_templates(directory)
    artifacts = [*update["artifacts"], str(directory / "nuclei-template-selection.json")]
    if not selected:
        return _base("nuclei", summary="No eligible signed HTTP templates were found.", error=manifest.get("error", "Template selection is empty."), artifacts=[p for p in artifacts if Path(p).exists()])
    raw, log, trace, errors = (directory / name for name in ("nuclei.jsonl", "nuclei.log", "nuclei-requests.jsonl", "nuclei-errors.log"))
    for path in (raw, trace, errors):
        _write(path, "")
    argv = [executable, "-config", str(directory / "nuclei-config.yaml"), "-u", parsed.url,
            "-t", manifest.get("directory", str(directory / "nuclei-selected-templates")), "-ud", str(TEMPLATE_ROOT), "-pt", "http",
            "-dut", "-dr", "-ni", "-duc", "-no-stdin", "-nh", "-nc", "-rl", "5", "-c", "2", "-bs", "1",
            "-timeout", "8", "-retries", "0", "-mhe", "20", "-max-time", f"{max(1, budget - 3)}s",
            "-jsonl", "-o", str(raw), "-tlog", str(trace), "-elog", str(errors), "-stats", "-sj", "-si", "10", "-ot"]
    process = _run(argv, log, budget, env=_nuclei_env())
    findings, issues = _nuclei_findings(raw)
    logtext = _read(log, 16_000_000)
    error_text = _read(errors, 16_000_000)
    if process.get("error"):
        issues.append(process["error"])
    if update["status"] != "complete":
        issues.append("Template update could not be verified; available previously downloaded templates were used.")
    loaded = re.search(r"Templates loaded for current scan:\s*(\d+)", logtext)
    skipped = re.search(r"Skipping\s+(\d+)\s+.*templates|Unsigned templates|mismatched signature", logtext, re.I)
    finished = bool(re.search(r"Scan completed|No results found", logtext, re.I))
    if not finished:
        issues.append("Nuclei did not report scan completion.")
    if loaded is None or int(loaded.group(1)) < len(selected):
        issues.append("Not all selected templates were reported loaded; inspect signature and template diagnostics.")
    if skipped:
        issues.append("Nuclei skipped or rejected templates; coverage is incomplete.")
    if error_text.strip() or re.search(r"\[(?:ERR|FTL)\]|max(?:imum)? (?:scan )?time|context deadline|skipp.*unresponsive|max.*host.*error", logtext, re.I):
        issues.append("Nuclei recorded request or execution errors; review error and progress logs.")
    if process["exit_code"] not in (0, None):
        issues.append(f"Nuclei exited with status {process['exit_code']}.")
    stats = []
    for line in logtext.splitlines():
        try:
            item = json.loads(line)
            if isinstance(item, dict) and ("percent" in item or "requests" in item):
                stats.append(item)
        except ValueError:
            pass
    last = stats[-1] if stats else {}
    if last.get("errors") not in (None, 0, "0"):
        issues.append(f"Scanner progress recorded {last['errors']} request errors.")
    if last.get("percent") is not None:
        try:
            if float(str(last["percent"]).rstrip("%")) < 100:
                issues.append(f"Last scanner progress was {last['percent']}%; uncompleted work remains.")
        except ValueError:
            pass
    artifacts.extend([str(raw), str(log), str(trace), str(errors), _write(directory / "nuclei-findings.json", findings)])
    observations = {"selected_templates": len(selected), "excluded_templates": manifest["excluded_count"],
                    "maximum_requests": manifest["maximum_requests"], "templates_reported_loaded": int(loaded.group(1)) if loaded else None,
                    "finding_count": len(findings), "last_progress": last, "template_version": update["observations"].get("installed_template_version"),
                    "scan_budget_seconds": budget, "exit_code": process["exit_code"]}
    return _base("nuclei", "complete" if process["exit_code"] == 0 and finished and not issues else "partial",
                 f"Nuclei selected {len(selected)} HTTP templates and recorded {len(findings)} matches.",
                 findings=findings[:MAX_FINDINGS], observations=observations, artifacts=artifacts,
                 findings_artifact=str(directory / "nuclei-findings.json"),
                 error=" ".join(dict.fromkeys(issues)) if issues else None,
                 limits=["Only selected signed static GET/HEAD detection templates ran; code, JavaScript, headless, fuzzing, out-of-band, exploit, and cross-host requests are excluded.",
                         "Scanner matches are candidates requiring validation; zero matches do not establish security.", *list(dict.fromkeys(issues))])
