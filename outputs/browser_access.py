"""A separate, visible Chromium session for the local Orca agent.

The browser is controlled through agent-browser's JSON CLI. It has its own
profile and daemon namespace, so it never attaches to the user's Firefox tabs.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROJECT_DIR = Path(__file__).resolve().parent.parent
AGENT_BROWSER = PROJECT_DIR / "work/browser-agent/node_modules/.bin/agent-browser"
PROFILE_DIR = PROJECT_DIR / "work/browser-profile"
CHROMIUM = Path("/usr/bin/chromium")
SESSION = "orca-local-agent"
NAMESPACE = "orca-local-agent"
MAX_TEXT = 3_500


def _clip(value: str, limit: int = MAX_TEXT) -> str:
    return value if len(value) <= limit else value[:limit] + f"\n[truncated after {limit} characters]"


def _required_text(args: dict, key: str) -> str | dict:
    value = args.get(key)
    if not isinstance(value, str) or not value.strip():
        return {"success": False, "error": f"{key} must be a non-empty string"}
    return value


def _run(command: list[str], timeout: int = 45) -> dict:
    if not AGENT_BROWSER.is_file() or not os.access(AGENT_BROWSER, os.X_OK):
        return {"success": False, "error": f"Browser tool is missing: {AGENT_BROWSER}"}
    if not CHROMIUM.is_file():
        return {"success": False, "error": f"Chromium is missing: {CHROMIUM}"}

    try:
        PROFILE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        PROFILE_DIR.chmod(0o700)
    except OSError as exc:
        return {"success": False, "error": f"Cannot prepare browser profile: {exc}"}

    argv = [
        str(AGENT_BROWSER),
        "--session", SESSION,
        "--namespace", NAMESPACE,
        "--profile", str(PROFILE_DIR),
        "--headed",
        "--executable-path", str(CHROMIUM),
        "--max-output", str(MAX_TEXT),
        "--json",
        *command,
    ]
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Browser action timed out after {timeout} seconds"}
    except OSError as exc:
        return {"success": False, "error": f"Could not run browser tool: {exc}"}

    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit code {result.returncode}"
        return {"success": False, "error": _clip(detail, 1600)}

    if not isinstance(response, dict):
        return {"success": False, "error": "Browser tool returned an unexpected response"}
    if result.returncode != 0 or not response.get("success"):
        detail = response.get("error") or result.stderr.strip() or f"exit code {result.returncode}"
        return {"success": False, "error": _clip(str(detail), 1600)}

    data = response.get("data")
    if not isinstance(data, dict):
        data = {"result": data}
    # The CLI lifecycle details are useful for diagnostics, but overwhelm the
    # small local model's context on every interaction.
    data.pop("lifecycle", None)
    data.pop("targetId", None)
    if isinstance(data.get("snapshot"), str):
        data["snapshot"] = _clip(data["snapshot"])
        data.pop("refs", None)  # The refs are already shown in the snapshot.
    if isinstance(data.get("content"), str):
        data["content"] = _clip(data["content"])
    for key in ("url", "finalUrl", "origin", "title"):
        if isinstance(data.get(key), str):
            data[key] = _clip(data[key], 500)
    return {"success": True, "data": data}


def browser_action(args: dict) -> dict:
    """Perform one browser action and return a bounded, JSON-safe result.

    References such as ``@e2`` come from the most recent ``snapshot``. The
    ``tabs`` action lists zero-based indices for ``switch_tab``.
    """
    if not isinstance(args, dict):
        return {"success": False, "error": "Browser arguments must be an object"}
    action = args.get("action")

    if action == "open":
        url = _required_text(args, "url")
        if isinstance(url, dict):
            return url
        return _run(["open", url], timeout=60)
    if action == "snapshot":
        return _run(["snapshot", "-i"])
    if action == "read":
        return _run(["read"], timeout=60)
    if action in {"click", "fill", "type"}:
        ref = _required_text(args, "ref")
        if isinstance(ref, dict):
            return ref
        if ref.startswith("e") and ref[1:].isdigit():
            ref = "@" + ref
        command = [action, ref]
        if action in {"fill", "type"}:
            content = args.get("text")
            if not isinstance(content, str):
                return {"success": False, "error": "text must be a string"}
            command.append(content)
        return _run(command)
    if action == "press":
        key = _required_text(args, "key")
        return key if isinstance(key, dict) else _run(["press", key])
    if action == "scroll":
        direction = args.get("direction")
        if direction not in {"up", "down", "left", "right"}:
            return {"success": False, "error": "direction must be up, down, left, or right"}
        pixels = args.get("pixels", 500)
        if isinstance(pixels, bool) or not isinstance(pixels, int) or not 1 <= pixels <= 10000:
            return {"success": False, "error": "pixels must be an integer from 1 to 10000"}
        return _run(["scroll", direction, str(pixels)])
    if action in {"back", "forward", "close"}:
        return _run([action])
    if action == "get_url":
        return _run(["get", "url"])
    if action == "get_title":
        return _run(["get", "title"])
    if action == "tabs":
        result = _run(["tab", "list"])
        if result.get("success"):
            tabs = result["data"].get("tabs") or []
            result["data"] = {
                "tabs": [
                    {
                        "index": index,
                        "tabId": tab.get("tabId"),
                        "active": tab.get("active"),
                        "title": _clip(str(tab.get("title") or ""), 100),
                        "url": _clip(str(tab.get("url") or ""), 160),
                    }
                    for index, tab in enumerate(tabs[:15])
                ],
                "total": len(tabs),
            }
        return result
    if action == "new_tab":
        url = args.get("url")
        if url is not None and (not isinstance(url, str) or not url.strip()):
            return {"success": False, "error": "url must be a non-empty string"}
        return _run(["tab", "new", *([url] if url else [])])
    if action == "switch_tab":
        index = args.get("index")
        if isinstance(index, bool) or not isinstance(index, int) or index < 0:
            return {"success": False, "error": "index must be a non-negative integer from tabs"}
        listed = _run(["tab", "list"])
        if not listed.get("success"):
            return listed
        tabs = listed["data"].get("tabs") or []
        if index >= len(tabs):
            return {"success": False, "error": f"Tab index {index} is out of range (0 to {len(tabs) - 1})"}
        return _run(["tab", tabs[index]["tabId"]])
    if action == "close_tab":
        return _run(["tab", "close"])

    return {"success": False, "error": f"Unknown browser action: {action}"}
