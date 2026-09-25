"""Read a small, bounded accessibility snapshot of the active X11 window.

This module only inspects the current desktop. It does not click, type, or
change accessibility settings. GTK applications generally expose useful
controls; some Electron and browser windows may expose little or no content.
"""

from __future__ import annotations

import json
import subprocess
from collections import deque
from typing import Any


_MAX_NODES = 50
_MAX_RESULT_CHARS = 4000
_MAX_VISITED = 400
_MAX_CHILDREN = 80
_TEXT_ROLES = {
    "text",
    "entry",
    "label",
    "paragraph",
    "static",
    "terminal",
    "document text",
}
_UNNAMED_ROLES = {
    "frame",
    "window",
    "dialog",
    "button",
    "toggle button",
    "check box",
    "radio button",
    "combo box",
    "entry",
    "text",
    "menu",
    "menu item",
    "list",
    "table",
    "terminal",
}


def _short(value: Any, limit: int) -> str:
    """Keep control text on one line and within the response budget."""
    cleaned = " ".join(str(value or "").split())
    return cleaned[: limit - 1] + "…" if len(cleaned) > limit else cleaned


def _active_x11_window() -> tuple[str, int | None]:
    try:
        title_result = subprocess.run(
            ["xdotool", "getactivewindow", "getwindowname"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        pid_result = subprocess.run(
            ["xdotool", "getactivewindow", "getwindowpid"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        title = _short(title_result.stdout, 160) if title_result.returncode == 0 else ""
        pid = int(pid_result.stdout.strip()) if pid_result.returncode == 0 else None
        return title, pid
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return "", None
    except ValueError:
        return title, None


def _is_active(window: Any, atspi: Any) -> bool:
    try:
        return bool(window.get_state_set().contains(atspi.StateType.ACTIVE))
    except Exception:
        return False


def _bounds(node: Any, atspi: Any) -> dict[str, int] | None:
    try:
        component = node.get_component_iface()
        if component is None:
            return None
        rect = component.get_extents(atspi.CoordType.SCREEN)
        if rect.width <= 0 or rect.height <= 0:
            return None
        return {
            "x": int(rect.x),
            "y": int(rect.y),
            "width": int(rect.width),
            "height": int(rect.height),
        }
    except Exception:
        return None


def _text(node: Any, role: str, atspi: Any) -> str:
    # Password controls can expose their contents via accessibility APIs.
    if "password" in role.lower():
        return ""
    try:
        if node.get_state_set().contains(atspi.StateType.PROTECTED):
            return ""
    except Exception:
        pass
    if role.lower() not in _TEXT_ROLES:
        return ""
    try:
        text_iface = node.get_text_iface()
        if text_iface is None:
            return ""
        count = min(max(int(text_iface.get_character_count()), 0), 140)
        return _short(text_iface.get_text(0, count), 120) if count else ""
    except Exception:
        return ""


def _fits(result: dict[str, Any]) -> bool:
    return len(json.dumps(result, ensure_ascii=False)) <= _MAX_RESULT_CHARS


def inspect_desktop(max_nodes: int = 40) -> dict[str, Any]:
    """Return the active window and up to 50 accessible controls.

    The result is JSON serializable and limited to about 4,000 characters.
    ``truncated`` means the control tree or output budget was exhausted.
    Failures are returned in ``error`` instead of raising into the agent.
    """
    try:
        limit = max(1, min(int(max_nodes), _MAX_NODES))
    except (TypeError, ValueError, OverflowError):
        limit = 40

    x11_title, x11_pid = _active_x11_window()
    result: dict[str, Any] = {
        "active_window": x11_title,
        "application": "",
        "bounds": None,
        "elements": [],
        "truncated": False,
    }

    try:
        import gi

        gi.require_version("Atspi", "2.0")
        from gi.repository import Atspi

        desktop = Atspi.get_desktop(0)
        if desktop is None:
            result["error"] = "AT-SPI desktop is unavailable"
            return result

        windows: list[tuple[Any, str, str, int | None]] = []
        for app_index in range(min(desktop.get_child_count(), 120)):
            try:
                app = desktop.get_child_at_index(app_index)
                if app is None:
                    continue
                app_name = _short(app.get_name(), 80)
                try:
                    app_pid = int(app.get_process_id())
                except Exception:
                    app_pid = None
                for window_index in range(min(app.get_child_count(), 25)):
                    window = app.get_child_at_index(window_index)
                    if window is not None:
                        windows.append((window, app_name, _short(window.get_name(), 160), app_pid))
            except Exception:
                continue

        active = None
        if x11_pid is not None and x11_title:
            active = next(
                (item for item in windows if item[3] == x11_pid and item[2] == x11_title and _is_active(item[0], Atspi)),
                None,
            )
        if active is None and x11_pid is not None and x11_title:
            active = next((item for item in windows if item[3] == x11_pid and item[2] == x11_title), None)
        if active is None and x11_pid is not None:
            active = next((item for item in windows if item[3] == x11_pid and _is_active(item[0], Atspi)), None)
        if active is None and x11_pid is not None:
            active = next((item for item in windows if item[3] == x11_pid), None)
        if active is None and x11_title and x11_pid is None:
            active = next((item for item in windows if item[2] == x11_title), None)
        if active is None and x11_title and x11_pid is None:
            active = next(
                (item for item in windows if item[2] and (item[2] in x11_title or x11_title in item[2])),
                None,
            )
        if active is None and not x11_title and x11_pid is None:
            active = next((item for item in windows if _is_active(item[0], Atspi)), None)
        if active is None:
            result["error"] = "The active window has no available accessibility tree"
            return result

        window, app_name, window_name, _ = active
        result["active_window"] = window_name or x11_title
        result["application"] = app_name
        result["bounds"] = _bounds(window, Atspi)

        queue = deque([(window, 0)])
        visited = 0
        while queue and visited < _MAX_VISITED and len(result["elements"]) < limit:
            node, depth = queue.popleft()
            if node is None:
                continue
            visited += 1
            try:
                role = _short(node.get_role_name(), 40)
                name = _short(node.get_name(), 100)
                snippet = _text(node, role, Atspi)
                bounds = _bounds(node, Atspi)
                if name or snippet or role.lower() in _UNNAMED_ROLES:
                    element: dict[str, Any] = {"role": role, "depth": depth}
                    if name:
                        element["name"] = name
                    if snippet and snippet != name:
                        element["text"] = snippet
                    if bounds is not None:
                        element["bounds"] = bounds
                    result["elements"].append(element)
                    if not _fits(result):
                        result["elements"].pop()
                        result["truncated"] = True
                        break
                if depth < 12:
                    for index in range(min(node.get_child_count(), _MAX_CHILDREN)):
                        try:
                            child = node.get_child_at_index(index)
                            if child is not None:
                                queue.append((child, depth + 1))
                        except Exception:
                            continue
            except Exception:
                continue

        result["truncated"] = result["truncated"] or bool(queue) or visited >= _MAX_VISITED
        return result
    except Exception as exc:
        result["error"] = _short(f"Desktop accessibility is unavailable: {exc}", 180)
        return result


if __name__ == "__main__":
    print(json.dumps(inspect_desktop(), ensure_ascii=False, separators=(",", ":")))
