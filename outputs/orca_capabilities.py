"""Small, read-only inventory of the local account and available programs.

Presence on PATH is not a successful functional test. User-supplied program
names are looked up only; the only commands executed are the fixed local
network-status queries below. No scans, privilege escalation, or changes.
"""
from __future__ import annotations

import getpass
import os
import platform
import re
import shutil
import subprocess
import tempfile

from orca_terminal_text import sanitize_terminal_text


DEFAULT_PROGRAMS = (
    "python3", "bash", "git", "curl", "openssl", "ip", "iw", "rfkill",
    "nmcli", "ffmpeg", "ffprobe", "xdotool",
)
_PROGRAM_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}\Z")
_NETWORK_COMMANDS = (
    ("default_routes", ("ip", "route", "show", "default")),
    ("wireless_interfaces", ("iw", "dev")),
    ("radio_blocks", ("rfkill", "list")),
    ("network_devices", ("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status")),
)
_OUTPUT_LIMIT = 4096
_TIMEOUT = 3


def _clean(value: object, limit: int = 200) -> str:
    return sanitize_terminal_text(str(value))[:limit]


def _arguments(args: dict | None) -> tuple[list[str], bool]:
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ValueError("Capability options must be an object.")
    names = args.get("programs", list(DEFAULT_PROGRAMS))
    if not isinstance(names, list) or len(names) > 12:
        raise ValueError("programs must be a list of at most 12 executable names.")
    if any(not isinstance(name, str) or not _PROGRAM_NAME.fullmatch(name) for name in names):
        raise ValueError("Use executable names only, without paths, spaces, or shell commands.")
    network = args.get("network", True)
    if not isinstance(network, bool):
        raise ValueError("network must be true or false.")
    return list(dict.fromkeys(names)), network


def _query(name: str, arguments: tuple[str, ...]) -> dict:
    result = {"name": name, "command": list(arguments), "status": "unavailable",
              "exit_code": None, "stdout": "", "stderr": "", "truncated": False}
    executable = shutil.which(arguments[0])
    if not executable:
        result["error"] = f"{arguments[0]} is not installed or not on PATH."
        return result
    # Files avoid retaining arbitrarily long command output in process memory.
    # These fixed queries read local state only and do not accept user arguments.
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            with subprocess.Popen(
                [executable, *arguments[1:]], stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, shell=False,
                env={**os.environ, "LC_ALL": "C", "PAGER": "cat"},
            ) as process:
                try:
                    process.wait(timeout=_TIMEOUT)
                    result["status"] = "ok" if process.returncode == 0 else "error"
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    result["status"] = "timeout"
                    result["error"] = "Local status query timed out after 3 seconds."
                result["exit_code"] = process.returncode
            for key, stream in (("stdout", stdout), ("stderr", stderr)):
                stream.seek(0)
                data = stream.read(_OUTPUT_LIMIT + 1)
                result["truncated"] |= len(data) > _OUTPUT_LIMIT
                result[key] = sanitize_terminal_text(data[:_OUTPUT_LIMIT].decode("utf-8", "replace"))
            if result["status"] == "error":
                result["error"] = f"Local status query exited with code {result['exit_code']}."
    except OSError as exc:
        result["status"] = "error"
        result["error"] = _clean(exc, 300)
    return result


def check_capabilities(args: dict | None = None) -> dict:
    """Return bounded local facts; never execute names passed in ``programs``."""
    programs, network = _arguments(args)
    try:
        account = getpass.getuser()
    except (KeyError, OSError):
        account = "unknown"
    system = {
        "os": _clean(platform.system()),
        "kernel": _clean(platform.release()),
        "architecture": _clean(platform.machine()),
        "account": _clean(account),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "display_available": bool(os.environ.get("DISPLAY")),
        "wayland_display_available": bool(os.environ.get("WAYLAND_DISPLAY")),
    }
    available = []
    for name in programs:
        path = shutil.which(name)
        available.append({"name": name, "installed": path is not None,
                          "path": _clean(path, 1024) if path else None, "tested": False})
    return {
        "system": system,
        "programs": available,
        "network_requested": network,
        "network_checks": [_query(name, command) for name, command in _NETWORK_COMMANDS] if network else [],
        "note": "Program presence is not a functional test. Local status checks do not verify internet access, administrator access, or wireless monitor-mode support.",
    }


def format_capabilities(result: dict) -> str:
    """Format a concise plain-text report for either the GUI or terminal."""
    system = result.get("system", {})
    lines = ["Local capabilities", "",
             f"System: {_clean(system.get('os', 'unknown'), 80)} · {_clean(system.get('kernel', 'unknown'), 100)} · {_clean(system.get('architecture', 'unknown'), 40)}",
             f"Account: {_clean(system.get('account', 'unknown'), 80)} (UID {system.get('uid', 'unknown')})",
             f"Desktop session: X11 {'available' if system.get('display_available') else 'not detected'}; Wayland {'available' if system.get('wayland_display_available') else 'not detected'}",
             "", "Programs (presence only; not functionally tested):"]
    for item in result.get("programs", [])[:12]:
        lines.append(f"• {_clean(item.get('name', '?'), 64)}: {'installed' if item.get('installed') else 'not on PATH'}")
    if result.get("network_requested"):
        lines.extend(["", "Local network status:"])
        for item in result.get("network_checks", [])[:4]:
            lines.append(f"• {_clean(item.get('name', '?'), 40).replace('_', ' ')}: {_clean(item.get('status', 'unknown'), 20)}")
            details = item.get("stderr") or item.get("stdout") or item.get("error") or "No output."
            detail = " ".join(_clean(details, 550).split())
            if len(detail) > 360:
                detail = detail[:359] + "…"
            lines.append("  " + detail)
            if item.get("status") in {"error", "timeout"} and item.get("error"):
                lines.append("  " + _clean(item["error"], 100))
            if item.get("truncated"):
                lines.append("  Output shortened.")
    else:
        lines.extend(["", "Local network queries skipped."])
    lines.extend(["", _clean(result.get("note", ""), 240)])
    text = "\n".join(lines)
    return text if len(text) <= 3000 else text[:2976].rstrip() + "\n[Report shortened]"
