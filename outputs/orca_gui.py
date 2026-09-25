#!/usr/bin/env python3
"""Desktop chat window for the local Orca Bonsai agent.

The GUI talks to the existing agent over newline-delimited JSON. It never
loads the model itself. Conversation history and reference files stay local.
"""

from __future__ import annotations

import html
import json
import os
from pathlib import Path
import queue
import re
import signal
import subprocess
import sys
import threading
import urllib.parse

from PySide6.QtCore import Qt, QTimer, Signal, QUrl
from PySide6.QtGui import QIcon, QImageReader, QKeyEvent, QDesktopServices, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QToolButton,
    QWidget,
)

from orca_memory import MemoryStore
from orca_task_evidence import result_failed
from orca_terminal_text import sanitize_terminal_text


OUTPUT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = OUTPUT_DIR.parent
LAUNCHER = OUTPUT_DIR / "start_orca_agent.sh"
ASKPASS = OUTPUT_DIR / "orca_askpass.sh"
ICON = OUTPUT_DIR / "orca-bonsai.png"
WEB_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}
VIDEO_EXTENSIONS = {".mp4", ".mkv", ".mov", ".webm", ".avi", ".m4v"}
MAX_ATTACHMENTS = 4
DEFAULT_MEDIA_QUESTION = "Describe these images and videos."


def _schedule_group_cleanup(pgid: int, grace_seconds: float = 3.0,
                            kill_seconds: float = 2.0) -> threading.Thread | None:
    """Reap the captured backend group even after its leader exits/restarts.

    This worker is independent of the Qt event loop and window lifetime. It is
    intentionally non-daemon so closing the GUI still completes bounded cleanup.
    The model server starts in a separate session and is not in this group.
    """
    if not isinstance(pgid, int) or pgid <= 1 or pgid == os.getpgrp():
        return None

    def cleanup():
        for delay, sig in ((grace_seconds, signal.SIGTERM), (kill_seconds, signal.SIGKILL)):
            if delay > 0:
                threading.Event().wait(delay)
            try:
                os.killpg(pgid, sig)
            except ProcessLookupError:
                return
            except OSError:
                return

    worker = threading.Thread(target=cleanup, name=f"OrcaStop-{pgid}", daemon=False)
    worker.start()
    return worker


STYLE = """
QWidget { background: #191a1b; color: #e5e5e2; font-family: 'Noto Sans', sans-serif; font-size: 13px; }
QLabel { background: transparent; }
QFrame#Sidebar, QWidget#SidebarContent { background: #141516; }
QFrame#Sidebar { border-right: 1px solid #242627; }
QFrame#Topbar, QFrame#ComposerPanel { background: #191a1b; }
QFrame#ComposerBox { background: #222425; border: 1px solid #353738; border-radius: 18px; }
QFrame#AssistantBubble { background: transparent; border: none; }
QFrame#UserBubble { background: #2b2d2e; border: none; border-radius: 16px; }
QFrame#NoticeBubble { background: #29271f; border: 1px solid #454133; border-radius: 12px; }
QFrame#Activity { background: transparent; border: 1px solid #303334; border-radius: 10px; }
QLabel#Brand { color: #f2f2ec; font-weight: 600; font-size: 18px; }
QLabel#Title { color: #b9bcb9; font-weight: 500; font-size: 13px; }
QLabel#WelcomeTitle { color: #edeee7; font-weight: 500; font-size: 28px; }
QLabel#WelcomeText { color: #929793; font-size: 13px; }
QLabel#Subtle { color: #878d89; font-size: 11px; }
QLabel#Section { color: #7e8580; font-size: 11px; font-weight: 500; }
QLabel#Sender { color: #a1aba2; font-size: 11px; font-weight: 600; }
QLabel#StatusDot { color: #b3bc92; font-size: 11px; }
QLabel#StatusText, QLabel#ModelName { color: #959d97; font-size: 11px; }
QPlainTextEdit#Composer { background: transparent; color: #ebeee8; border: none; padding: 2px; font-size: 14px; selection-background-color: #465848; }
QPlainTextEdit#ActivityDetails { background: #151718; color: #b7c0b9; border: none; border-radius: 6px; padding: 8px; font-family: monospace; font-size: 11px; }
QPushButton, QToolButton { border: none; border-radius: 8px; padding: 8px 10px; font-weight: 500; }
QPushButton#Primary { background: #c2cfad; color: #1e281b; font-size: 21px; padding: 0px; border-radius: 16px; }
QPushButton#Primary:hover { background: #d4dfc4; }
QPushButton#Primary:disabled { background: #393e37; color: #71796d; }
QPushButton#Secondary { background: #282b2a; color: #c9d0ca; border: 1px solid #383d39; }
QPushButton#Secondary:hover { background: #343a35; }
QPushButton:disabled, QToolButton:disabled { color: #5d635f; }
QPushButton#NewChat { background: #222624; color: #d4dfd3; border: 1px solid #363f36; text-align: left; padding: 10px 12px; }
QPushButton#NewChat:hover { background: #2e352e; }
QToolButton#Quiet, QPushButton#Quiet { background: transparent; color: #a4ada5; text-align: left; }
QToolButton#Quiet:hover, QPushButton#Quiet:hover { background: #2b2f2c; color: #e2e9df; }
QToolButton::menu-indicator { image: none; width: 0px; }
QPushButton#ActivityToggle { background: transparent; color: #9ca79e; border: none; text-align: left; padding: 5px 8px; font-size: 11px; }
QScrollArea { border: none; background: transparent; }
QListWidget { background: transparent; border: none; outline: none; padding: 0px; }
QListWidget::item { padding: 10px 9px; border-radius: 7px; color: #979e99; }
QListWidget::item:hover { background: #202421; color: #d4dcd4; }
QListWidget::item:selected { background: #282e28; color: #dce7d7; }
QScrollBar:vertical { background: transparent; width: 6px; margin: 0px; }
QScrollBar::handle:vertical { background: #3c423e; border-radius: 3px; min-height: 25px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QProgressBar { border: none; background: transparent; }
QProgressBar::chunk { background: #a4b793; }
QMenu { background: #242725; color: #d8e0d8; border: 1px solid #3a413b; border-radius: 8px; padding: 6px; }
QMenu::item { padding: 9px 18px; border-radius: 5px; }
QMenu::item:selected { background: #363f35; }
QMenu::item:disabled { color: #687069; }
QMenu::separator { height: 1px; background: #393e39; margin: 5px 8px; }
QToolTip { background: #292e29; color: #e3e9df; border: 1px solid #424b41; padding: 5px; }
QMessageBox QPushButton, QInputDialog QPushButton { background: #30382e; min-width: 65px; }
"""


def _safe_detail(value: object, limit: int = 3000) -> str:
    """Format clean terminal text while hiding common credential fields."""

    def redact(item: object) -> object:
        if isinstance(item, dict):
            hidden = ("password", "passwd", "secret", "token", "api_key", "authorization", "cookie")
            return {
                str(key): "[hidden]" if any(word in str(key).lower() for word in hidden) else redact(val)
                for key, val in item.items()
            }
        if isinstance(item, (list, tuple)):
            return [redact(part) for part in item]
        if isinstance(item, str):
            return sanitize_terminal_text(item)
        return item

    redacted = redact(value)
    try:
        rendered = json.dumps(redacted, ensure_ascii=False, indent=2)
    except (TypeError, ValueError):
        rendered = sanitize_terminal_text(str(redacted))
    if len(rendered) > limit:
        return rendered[:limit] + "\n… [more hidden]"
    return rendered


def _answer_html(text: str) -> str:
    """Link only HTTP(S) URLs while treating all model text as plain text."""
    parts: list[str] = []
    position = 0
    for match in WEB_URL.finditer(text):
        parts.append(html.escape(text[position:match.start()]).replace("\n", "<br>"))
        candidate = match.group()
        url = candidate.rstrip(".,;:!?)]}")
        tail = candidate[len(url):]
        try:
            parsed = urllib.parse.urlsplit(url)
            valid_web_url = parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)
        except ValueError:
            valid_web_url = False
        if valid_web_url:
            escaped = html.escape(url, quote=True)
            parts.append(f'<a href="{escaped}" style="color:#79dcc4;text-decoration:underline;">{escaped}</a>')
        else:
            parts.append(html.escape(url))
        parts.append(html.escape(tail))
        position = match.end()
    parts.append(html.escape(text[position:]).replace("\n", "<br>"))
    return "".join(parts)


class Composer(QPlainTextEdit):
    send_requested = Signal()

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in (Qt.Key_Return, Qt.Key_Enter) and not (event.modifiers() & Qt.ShiftModifier):
            # The window also accepts an attachment-only message.
            self.send_requested.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class ActivityWidget(QFrame):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("Activity")
        self.setMaximumWidth(760)
        self.entries: list[dict] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 5, 8, 8)
        layout.setSpacing(2)
        self.toggle = QPushButton("›  Activity", self)
        self.toggle.setObjectName("ActivityToggle")
        self.toggle.setCursor(Qt.PointingHandCursor)
        layout.addWidget(self.toggle)
        self.details = QPlainTextEdit(self)
        self.details.setObjectName("ActivityDetails")
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(110)
        self.details.setMaximumHeight(210)
        self.details.hide()
        layout.addWidget(self.details)
        self.toggle.clicked.connect(self._toggle)

    def _toggle(self) -> None:
        expanded = not self.details.isVisible()
        self.details.setVisible(expanded)
        self._refresh_heading()

    def _refresh_heading(self) -> None:
        arrow = "⌄" if self.details.isVisible() else "›"
        count = len(self.entries)
        noun = "tool call" if count == 1 else "tool calls"
        states = [self._entry_state(entry) for entry in self.entries]
        summary = "".join(
            f" · {states.count(state)} {state}" for state in ("failed", "timed out", "reused", "running")
            if state in states
        )
        self.toggle.setText(f"{arrow}  Activity · {count} {noun}{summary}")

    @staticmethod
    def _entry_state(entry: dict) -> str:
        if entry.get("cached", False):
            return "reused"
        if not entry.get("completed", entry.get("result") is not None):
            return "running"
        result = entry.get("result")
        if isinstance(result, dict):
            if result.get("timed_out") is True:
                return "timed out"
            # Colored CLI diagnostics must be classified as their plain text.
            clean_result = {
                key: sanitize_terminal_text(value) if key in {"stdout", "stderr"} and isinstance(value, str) else value
                for key, value in result.items()
            }
            return "failed" if result_failed(clean_result) else "done"
        return "failed" if result is None else "done"

    def tool_start(self, step: object, name: object, args: object) -> None:
        self.entries.append({"step": step, "name": str(name), "args": args, "result": None, "completed": False})
        self._refresh()

    def tool_result(self, step: object, name: object, result: object, cached: bool = False) -> None:
        for entry in reversed(self.entries):
            if not entry.get("completed", entry["result"] is not None) and entry["name"] == str(name) and entry["step"] == step:
                entry["result"] = result
                entry["cached"] = cached
                entry["completed"] = True
                self._refresh()
                return
        self.entries.append({"step": step, "name": str(name), "args": None, "result": result, "cached": cached, "completed": True})
        self._refresh()

    def _refresh(self) -> None:
        self._refresh_heading()
        lines = []
        for entry in self.entries:
            cached = entry.get("cached", False)
            state = self._entry_state(entry)
            lines.append(f"[{entry['step']}] {entry['name']} · {state}")
            if cached:
                lines.append("Previous result reused; this tool did not run again.")
            if entry["args"] is not None:
                lines.append("Input: " + _safe_detail(entry["args"], 1200))
            if entry.get("completed", entry["result"] is not None):
                lines.append("Result: " + _safe_detail(entry["result"], 1800))
            lines.append("")
        self.details.setPlainText("\n".join(lines).strip())


class OrcaWindow(QMainWindow):
    """One local chat session. All process I/O runs outside the UI thread."""

    process_line = Signal(int, str, str)
    process_exit = Signal(int, int)
    write_error = Signal(int, str)

    def __init__(self, auto_start: bool = True, memory_store=None) -> None:
        super().__init__()
        self.setWindowTitle("Orca Bonsai")
        self.resize(1120, 780)
        self.setMinimumSize(730, 520)
        if ICON.is_file():
            self.setWindowIcon(QIcon(str(ICON)))
        self.setStyleSheet(STYLE)

        self._process: subprocess.Popen[str] | None = None
        self._generation = 0
        self._write_queue: queue.Queue[dict | None] | None = None
        self._ready = False
        self._busy = False
        self._stopping = False
        self._restart_after_exit = False
        self._closing = False
        self._model = "Local model"
        self._activity: ActivityWidget | None = None
        self._welcome: QWidget | None = None
        self._full_scan_draft: tuple[str, dict] | None = None
        self._attachments: list[str] = []
        self._report_path: Path | None = None
        self._memory = memory_store if memory_store is not None else MemoryStore()
        self._conversation_id = self._memory.current_conversation_id() or self._memory.new_conversation()
        self._reference_documents: list[dict] = []

        self._build_ui()
        self.process_line.connect(self._on_process_line)
        self.process_exit.connect(self._on_process_exit)
        self.write_error.connect(self._on_write_error)
        self._load_conversation()
        self._refresh_history()
        self._refresh_reference_files()
        self._set_status("Starting local model…", "starting")
        self._refresh_controls()
        if auto_start:
            QTimer.singleShot(0, self.start_backend)

    def _build_ui(self) -> None:
        root = QWidget(self)
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.sidebar = QFrame(root)
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(224)
        side = QVBoxLayout(self.sidebar)
        side.setContentsMargins(16, 24, 16, 18)
        side.setSpacing(10)
        brand = QLabel("Orca Bonsai", self.sidebar)
        brand.setObjectName("Brand")
        side.addWidget(brand)
        side.addSpacing(18)
        self.new_chat_button = QPushButton("＋   New chat", self.sidebar)
        self.new_chat_button.setObjectName("NewChat")
        self.new_chat_button.setCursor(Qt.PointingHandCursor)
        self.new_chat_button.clicked.connect(self.new_chat)
        side.addWidget(self.new_chat_button)
        side.addSpacing(14)
        history_heading = QLabel("Recent chats", self.sidebar)
        history_heading.setObjectName("Section")
        side.addWidget(history_heading)
        self.history_list = QListWidget(self.sidebar)
        self.history_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.history_list.setTextElideMode(Qt.ElideRight)
        self.history_list.setAccessibleName("Recent conversations saved on this computer")
        self.history_list.setToolTip("Select a chat to continue. Use the chat menu to delete history.")
        self.history_list.itemClicked.connect(self._select_conversation)
        side.addWidget(self.history_list, 1)

        self.references_menu = QMenu(self)
        self.reference_button = self.references_menu.addAction("Add reference files…")
        self.reference_button.triggered.connect(self.choose_reference_files)
        self.remove_reference_button = self.references_menu.addAction("Remove reference file…")
        self.remove_reference_button.triggered.connect(self.remove_reference_file)
        self.references_toggle = QToolButton(self.sidebar)
        self.references_toggle.setText("Reference files  ⌄")
        self.references_toggle.setObjectName("Quiet")
        self.references_toggle.setPopupMode(QToolButton.InstantPopup)
        self.references_toggle.setMenu(self.references_menu)
        self.references_toggle.setToolTip("Add or remove documents Orca can use in answers.")
        self.references_toggle.setCursor(Qt.PointingHandCursor)
        side.addWidget(self.references_toggle)
        self.reference_label = QLabel("No files added", self.sidebar)
        self.reference_label.setObjectName("Subtle")
        self.reference_label.setWordWrap(True)
        side.addWidget(self.reference_label)
        side.addSpacing(12)
        self.model_label = QLabel("Local model", self.sidebar)
        self.model_label.setObjectName("ModelName")
        self.model_label.setWordWrap(True)
        side.addWidget(self.model_label)
        footer = QLabel("Saved on this computer", self.sidebar)
        footer.setObjectName("Subtle")
        side.addWidget(footer)
        outer.addWidget(self.sidebar)

        main = QWidget(root)
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        outer.addWidget(main, 1)
        topbar = QFrame(main)
        topbar.setObjectName("Topbar")
        topbar.setFixedHeight(62)
        top = QHBoxLayout(topbar)
        top.setContentsMargins(16, 0, 20, 0)
        top.setSpacing(8)
        self.sidebar_toggle = QToolButton(topbar)
        self.sidebar_toggle.setText("☰")
        self.sidebar_toggle.setObjectName("Quiet")
        self.sidebar_toggle.setToolTip("Show or hide recent chats")
        self.sidebar_toggle.setAccessibleName("Toggle sidebar")
        self.sidebar_toggle.setCheckable(True)
        self.sidebar_toggle.setChecked(True)
        self.sidebar_toggle.toggled.connect(self.sidebar.setVisible)
        top.addWidget(self.sidebar_toggle)
        self.chat_title = QLabel("New chat", topbar)
        self.chat_title.setObjectName("Title")
        self.chat_title.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        top.addWidget(self.chat_title, 1)
        self.status_dot = QLabel("●", topbar)
        self.status_dot.setObjectName("StatusDot")
        top.addWidget(self.status_dot)
        self.status_label = QLabel("Starting…", topbar)
        self.status_label.setObjectName("StatusText")
        self.status_label.setMaximumWidth(135)
        top.addWidget(self.status_label)

        tools_menu = QMenu(self)
        self.capabilities_action = tools_menu.addAction("Check capabilities")
        self.capabilities_action.triggered.connect(self.check_capabilities)
        tools_menu.addSeparator()
        self.security_button = tools_menu.addAction("Full security scan…")
        self.security_button.triggered.connect(self.compose_security_check)
        self.report_button = tools_menu.addAction("Open scan report")
        self.report_button.setEnabled(False)
        self.report_button.triggered.connect(self.open_scan_report)
        self.tools_button = QToolButton(topbar)
        self.tools_button.setText("Tools  ⌄")
        self.tools_button.setObjectName("Quiet")
        self.tools_button.setMenu(tools_menu)
        self.tools_button.setPopupMode(QToolButton.InstantPopup)
        self.tools_button.setCursor(Qt.PointingHandCursor)
        top.addWidget(self.tools_button)
        self.chat_menu = QMenu(self)
        self.delete_chat_action = self.chat_menu.addAction("Delete chat…")
        self.delete_chat_action.triggered.connect(self.delete_current_conversation)
        self.chat_menu.addSeparator()
        self.clear_history_action = self.chat_menu.addAction("Clear chat history…")
        self.clear_history_action.triggered.connect(self.clear_chat_history)
        self.chat_menu_button = QToolButton(topbar)
        self.chat_menu_button.setText("•••")
        self.chat_menu_button.setObjectName("Quiet")
        self.chat_menu_button.setToolTip("Chat options")
        self.chat_menu_button.setAccessibleName("Chat options")
        self.chat_menu_button.setMenu(self.chat_menu)
        self.chat_menu_button.setPopupMode(QToolButton.InstantPopup)
        self.chat_menu_button.setCursor(Qt.PointingHandCursor)
        top.addWidget(self.chat_menu_button)
        main_layout.addWidget(topbar)

        self.progress = QProgressBar(main)
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(2)
        main_layout.addWidget(self.progress)
        self.scroll = QScrollArea(main)
        self.scroll.setWidgetResizable(True)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        chat_inner = QWidget(self.scroll)
        chat_shell = QHBoxLayout(chat_inner)
        chat_shell.setContentsMargins(0, 0, 0, 0)
        chat_shell.setSpacing(0)
        chat_column = QWidget(chat_inner)
        chat_column.setMaximumWidth(880)
        self.chat_layout = QVBoxLayout(chat_column)
        self.chat_layout.setContentsMargins(24, 22, 24, 24)
        self.chat_layout.setSpacing(24)
        self.chat_layout.addStretch(1)
        chat_shell.addStretch()
        chat_shell.addWidget(chat_column, 1)
        chat_shell.addStretch()
        self.scroll.setWidget(chat_inner)
        main_layout.addWidget(self.scroll, 1)

        composer_panel = QFrame(main)
        composer_panel.setObjectName("ComposerPanel")
        composer_shell = QHBoxLayout(composer_panel)
        composer_shell.setContentsMargins(0, 0, 0, 0)
        composer_shell.setSpacing(0)
        composer_column = QWidget(composer_panel)
        composer_column.setMaximumWidth(880)
        bottom = QVBoxLayout(composer_column)
        bottom.setContentsMargins(24, 10, 24, 16)
        bottom.setSpacing(9)
        self.attachment_panel = QWidget(composer_column)
        self.attachment_layout = QVBoxLayout(self.attachment_panel)
        self.attachment_layout.setContentsMargins(0, 0, 0, 0)
        self.attachment_layout.setSpacing(4)
        self.attachment_panel.hide()
        bottom.addWidget(self.attachment_panel)
        composer_box = QFrame(composer_column)
        composer_box.setObjectName("ComposerBox")
        compose = QVBoxLayout(composer_box)
        compose.setContentsMargins(14, 12, 12, 10)
        compose.setSpacing(4)
        self.composer = Composer(composer_box)
        self.composer.setObjectName("Composer")
        self.composer.setPlaceholderText("Ask anything, or add an image or video…")
        self.composer.setFixedHeight(57)
        self.composer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.composer.send_requested.connect(self.send_message)
        self.composer.textChanged.connect(self._refresh_controls)
        compose.addWidget(self.composer)
        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.attach_button = QPushButton("＋  Attach", composer_box)
        self.attach_button.setObjectName("Quiet")
        self.attach_button.setCursor(Qt.PointingHandCursor)
        self.attach_button.setToolTip("Choose up to 4 local images or videos. Videos use sampled frames; audio is not included.")
        self.attach_button.setAccessibleName("Attach local images or videos")
        self.attach_button.clicked.connect(self.choose_attachments)
        actions.addWidget(self.attach_button)
        self.clear_attachments_button = QPushButton("Clear", composer_box)
        self.clear_attachments_button.setObjectName("Quiet")
        self.clear_attachments_button.setAccessibleName("Clear attachments")
        self.clear_attachments_button.setCursor(Qt.PointingHandCursor)
        self.clear_attachments_button.clicked.connect(self.clear_attachments)
        self.clear_attachments_button.hide()
        actions.addWidget(self.clear_attachments_button)
        actions.addStretch(1)
        self.stop_button = QPushButton("Stop", composer_box)
        self.stop_button.setObjectName("Secondary")
        self.stop_button.setCursor(Qt.PointingHandCursor)
        self.stop_button.clicked.connect(self.stop_task)
        actions.addWidget(self.stop_button)
        self.send_button = QPushButton("↑", composer_box)
        self.send_button.setFixedSize(32, 32)
        self.send_button.setObjectName("Primary")
        self.send_button.setToolTip("Send message")
        self.send_button.setAccessibleName("Send message")
        self.send_button.setCursor(Qt.PointingHandCursor)
        self.send_button.clicked.connect(self.send_message)
        actions.addWidget(self.send_button)
        compose.addLayout(actions)
        bottom.addWidget(composer_box)
        hint = QLabel("Enter to send · Shift+Enter for a new line", composer_column)
        hint.setObjectName("Subtle")
        hint.setAlignment(Qt.AlignCenter)
        bottom.addWidget(hint)
        composer_shell.addStretch()
        composer_shell.addWidget(composer_column, 1)
        composer_shell.addStretch()
        main_layout.addWidget(composer_panel)

    def _clear_chat(self) -> None:
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()
        self._activity = None
        self._welcome = None
        self._full_scan_draft = None
        self.clear_attachments()

    def _show_welcome(self) -> None:
        self._welcome = QWidget()
        layout = QVBoxLayout(self._welcome)
        layout.setContentsMargins(8, 100, 8, 36)
        layout.setSpacing(12)
        title = QLabel("What can I help with?", self._welcome)
        title.setObjectName("WelcomeTitle")
        title.setAlignment(Qt.AlignCenter)
        title.setWordWrap(True)
        layout.addWidget(title)
        subtitle = QLabel("Ask a question, add a file, or pick up a recent chat.", self._welcome)
        subtitle.setObjectName("WelcomeText")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)
        self.chat_layout.insertWidget(0, self._welcome)

    def _refresh_history(self) -> None:
        self.history_list.clear()
        for conversation in self._memory.list_conversations(limit=20):
            item = QListWidgetItem(str(conversation.get("title") or "New chat"))
            item.setData(Qt.UserRole, conversation["id"])
            item.setToolTip(str(conversation.get("title") or "New chat"))
            self.history_list.addItem(item)
            if conversation["id"] == self._conversation_id:
                self.history_list.setCurrentItem(item)
                self._set_chat_title(item.text())

    def _set_chat_title(self, title: str) -> None:
        self.chat_title.setText(title if len(title) <= 34 else title[:31] + "…")
        self.chat_title.setToolTip(title)

    def _load_conversation(self) -> None:
        self._clear_chat()
        messages = self._memory.load_messages(self._conversation_id, limit=40)
        if not messages:
            self._show_welcome()
        for message in messages:
            role = message.get("role")
            if role in {"user", "assistant"}:
                self._add_message(role, str(message.get("content") or ""))

    def _select_conversation(self, item: QListWidgetItem) -> None:
        if self._busy or self._stopping:
            return
        conversation_id = item.data(Qt.UserRole)
        if not conversation_id or conversation_id == self._conversation_id:
            return
        self._memory.set_current_conversation(conversation_id)
        self._conversation_id = conversation_id
        self._set_chat_title(item.text())
        self.composer.clear()
        self._load_conversation()
        self.composer.setFocus()

    def _restore_after_deletion(self) -> None:
        conversations = self._memory.list_conversations(limit=1)
        if conversations:
            self._conversation_id = conversations[0]["id"]
            self._memory.set_current_conversation(self._conversation_id)
        else:
            self._conversation_id = self._memory.new_conversation()
        self.composer.clear()
        self._report_path = None
        self.report_button.setEnabled(False)
        self._load_conversation()
        self._refresh_history()
        self._refresh_controls()
        self.composer.setFocus()

    def delete_current_conversation(self) -> None:
        if self._busy or self._stopping:
            return
        confirmed = QMessageBox.question(
            self, "Delete chat?",
            "Delete this chat and its saved conversation memory? This cannot be undone.\n\nReference files will be kept.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        # A nested dialog runs the Qt event loop; check again before mutating.
        if confirmed != QMessageBox.Yes or self._busy or self._stopping:
            return
        try:
            self._memory.delete_conversation(self._conversation_id)
            self._restore_after_deletion()
        except Exception as exc:
            QMessageBox.warning(self, "Could not delete chat", str(exc))

    def clear_chat_history(self) -> None:
        if self._busy or self._stopping:
            return
        confirmed = QMessageBox.question(
            self, "Clear chat history?",
            "Delete all chats and their saved conversation memory? This cannot be undone.\n\nReference files will be kept.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if confirmed != QMessageBox.Yes or self._busy or self._stopping:
            return
        try:
            self._memory.clear_conversations()
            self._restore_after_deletion()
        except Exception as exc:
            QMessageBox.warning(self, "Could not clear history", str(exc))

    def _refresh_reference_files(self) -> None:
        documents = self._memory.list_documents()
        self._reference_documents = documents
        count = len(documents)
        self.reference_label.setText(f"{count} {'file' if count == 1 else 'files'} available" if count else "No files added")
        self.reference_label.setToolTip("\n".join(str(document.get("name") or document.get("path") or "") for document in documents))
        self.remove_reference_button.setVisible(bool(documents))
        self._refresh_controls()

    def remove_reference_file(self) -> None:
        if self._busy or self._stopping:
            return
        documents = self._memory.list_documents()
        if not documents:
            return
        choices = [f"{document['name']} — {document['path']}" for document in documents]
        choice, accepted = QInputDialog.getItem(
            self, "Remove reference file",
            "Choose a saved reference to remove. The original file will stay on this computer:",
            choices, 0, False,
        )
        if accepted and choice in choices:
            document = documents[choices.index(choice)]
            self._memory.remove_document(document["id"])
            self._refresh_reference_files()
            self._add_message("notice", f"Removed {document['name']} from saved references.")

    def choose_reference_files(self) -> None:
        if not self._ready or self._busy or self._stopping or self._write_queue is None:
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Add local reference files", "",
            "Reference files (*.txt *.md *.markdown *.csv *.json *.log *.pdf *.docx)",
        )
        paths = list(dict.fromkeys(str(Path(path).expanduser().absolute()) for path in paths))
        if not paths:
            return
        if len(paths) > 20:
            self._add_message("notice", "You can add up to 20 reference files at a time. The first 20 selected files will be added.")
            paths = paths[:20]
        self._busy = True
        self._activity = None
        self._set_status("Adding reference files…", "working")
        self._refresh_controls()
        self._write_queue.put_nowait({"type": "index_documents", "paths": paths})

    def _scroll_bottom(self) -> None:
        QTimer.singleShot(0, lambda: self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum()))

    def _add_message(self, role: str, text: str) -> None:
        if self._welcome is not None:
            self.chat_layout.removeWidget(self._welcome)
            self._welcome.hide()
            self._welcome.deleteLater()
            self._welcome = None
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(0)
        bubble = QFrame(row)
        bubble.setObjectName({"user": "UserBubble", "assistant": "AssistantBubble"}.get(role, "NoticeBubble"))
        bubble.setMaximumWidth(640 if role == "user" else 800)
        bubble.setMinimumWidth(0)
        bubble_layout = QVBoxLayout(bubble)
        bubble_layout.setContentsMargins(15, 11, 15, 13)
        bubble_layout.setSpacing(5)
        sender = QLabel({"user": "YOU", "assistant": "ORCA"}.get(role, "NOTICE"), bubble)
        sender.setObjectName("Sender")
        bubble_layout.addWidget(sender)
        body = QLabel(bubble)
        if role == "assistant":
            body.setTextFormat(Qt.RichText)
            body.setText(_answer_html(str(text)))
            body.setOpenExternalLinks(True)
        else:
            body.setTextFormat(Qt.PlainText)
            body.setText(str(text))
        body.setWordWrap(True)
        body.setMinimumWidth(0)
        body.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        body.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse)
        bubble_layout.addWidget(body)
        if role == "user":
            row_layout.addStretch(1)
            row_layout.addWidget(bubble)
        else:
            row_layout.addWidget(bubble, 1)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, row)
        self._scroll_bottom()

    def _ensure_activity(self) -> ActivityWidget:
        if self._activity is None:
            self._activity = ActivityWidget()
            self.chat_layout.insertWidget(self.chat_layout.count() - 1, self._activity, 0, Qt.AlignLeft)
            self._scroll_bottom()
        return self._activity

    def _set_status(self, text: str, state: str) -> None:
        clean = " ".join(str(text).split())
        if len(clean) > 70:
            clean = clean[:67] + "…"
        self.status_label.setText(clean)
        self.status_label.setToolTip(str(text))
        color = {"ready": "#56c7a9", "working": "#69b8f0", "starting": "#e7b55f", "error": "#ef807a"}.get(state, "#e7b55f")
        self.status_dot.setStyleSheet(f"color: {color};")
        self.progress.setVisible(state in {"working", "starting"})

    def _refresh_controls(self) -> None:
        can_edit_attachments = not self._busy and not self._stopping
        can_send = self._ready and self._write_queue is not None and can_edit_attachments and bool(self.composer.toPlainText().strip() or self._attachments)
        self.send_button.setEnabled(can_send)
        self.send_button.setVisible(not self._busy)
        self.stop_button.setEnabled(self._busy and not self._stopping)
        self.stop_button.setVisible(self._busy or self._stopping)
        self.new_chat_button.setEnabled(can_edit_attachments)
        self.delete_chat_action.setEnabled(can_edit_attachments)
        self.clear_history_action.setEnabled(can_edit_attachments)
        self.security_button.setEnabled(not self._busy and not self._stopping)
        self.attach_button.setEnabled(can_edit_attachments and len(self._attachments) < MAX_ATTACHMENTS)
        self.clear_attachments_button.setEnabled(can_edit_attachments)
        self.clear_attachments_button.setVisible(bool(self._attachments))
        self.attachment_panel.setEnabled(can_edit_attachments)
        self.history_list.setEnabled(can_edit_attachments)
        self.reference_button.setEnabled(self._ready and can_edit_attachments and self._write_queue is not None)
        self.capabilities_action.setEnabled(self._ready and can_edit_attachments and self._write_queue is not None)
        self.remove_reference_button.setEnabled(can_edit_attachments and bool(self._reference_documents))

    def check_capabilities(self) -> None:
        if not self._ready or self._busy or self._stopping or self._write_queue is None:
            return
        text = "Check available tools and computer capabilities."
        self._add_message("user", text)
        self._busy = True
        self._activity = None
        self._set_status("Checking capabilities…", "working")
        self._refresh_controls()
        self._write_queue.put_nowait({
            "type": "capabilities", "text": text, "conversation_id": self._conversation_id,
        })

    def choose_attachments(self) -> None:
        if self._busy or self._stopping:
            return
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Attach local images or videos", "",
            "Images and videos (*.jpg *.jpeg *.png *.webp *.bmp *.gif *.mp4 *.mkv *.mov *.webm *.avi *.m4v);;"
            "Images (*.jpg *.jpeg *.png *.webp *.bmp *.gif);;Videos (*.mp4 *.mkv *.mov *.webm *.avi *.m4v)",
        )
        self.add_attachments(paths)

    def add_attachments(self, paths: list[str]) -> None:
        if self._busy or self._stopping:
            return
        added = False
        exceeded = False
        unsupported = False
        for value in paths:
            path = Path(value).expanduser().absolute()
            if path.suffix.lower() not in IMAGE_EXTENSIONS | VIDEO_EXTENSIONS:
                unsupported = True
                continue
            local_path = str(path)
            if local_path in self._attachments:
                continue
            if len(self._attachments) >= MAX_ATTACHMENTS:
                exceeded = True
                continue
            self._attachments.append(local_path)
            added = True
        if added:
            # Choosing media cancels any untouched generated scan draft. Edited
            # text remains the user's question, but stale scan metadata never runs.
            if self._full_scan_draft and self.composer.toPlainText().strip() == self._full_scan_draft[0]:
                self.composer.clear()
            self._full_scan_draft = None
            self._refresh_attachments()
            self.composer.setFocus()
        if exceeded:
            self._add_message("notice", "You can attach up to 4 files at a time. Remove an attachment to choose another.")
        if unsupported:
            self._add_message("notice", "Choose JPG, PNG, WEBP, BMP or GIF images, or MP4, MKV, MOV, WEBM, AVI or M4V videos.")
        self._refresh_controls()

    def _refresh_attachments(self) -> None:
        while self.attachment_layout.count():
            item = self.attachment_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for local_path in self._attachments:
            path = Path(local_path)
            row = QWidget(self.attachment_panel)
            layout = QHBoxLayout(row)
            layout.setContentsMargins(0, 0, 0, 0)
            preview = QLabel(row)
            preview.setFixedSize(42, 32)
            preview.setAlignment(Qt.AlignCenter)
            preview.setText("Video" if path.suffix.lower() in VIDEO_EXTENSIONS else "Image")
            preview.setObjectName("Subtle")
            if path.suffix.lower() in IMAGE_EXTENSIONS:
                reader = QImageReader(str(path))
                reader.setAutoTransform(True)
                size = reader.size()
                if size.isValid():
                    reader.setScaledSize(size.scaled(42, 32, Qt.KeepAspectRatio))
                    thumbnail = reader.read()
                    if not thumbnail.isNull():
                        preview.setPixmap(QPixmap.fromImage(thumbnail).scaled(42, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            layout.addWidget(preview)
            name = QLabel(path.name, row)
            name.setTextFormat(Qt.PlainText)
            name.setWordWrap(True)
            name.setToolTip(local_path)
            name.setAccessibleName(f"Attached file: {path.name}")
            layout.addWidget(name, 1)
            remove = QPushButton("Remove", row)
            remove.setObjectName("Secondary")
            remove.setCursor(Qt.PointingHandCursor)
            remove.setAccessibleName(f"Remove {path.name}")
            remove.clicked.connect(lambda checked=False, attached=local_path: self.remove_attachment(attached))
            layout.addWidget(remove)
            self.attachment_layout.addWidget(row)
        self.attachment_panel.setVisible(bool(self._attachments))

    def remove_attachment(self, local_path: str) -> None:
        if self._busy or self._stopping:
            return
        if local_path in self._attachments:
            self._attachments.remove(local_path)
            self._refresh_attachments()
            self._refresh_controls()

    def clear_attachments(self) -> None:
        self._attachments.clear()
        self._refresh_attachments()
        self._refresh_controls()

    def compose_security_check(self) -> None:
        target, accepted = QInputDialog.getText(
            self, "Full security scan", "Website or server you own or have permission to test:", text="https://"
        )
        target = target.strip()
        if not accepted or target in {"", "http://", "https://"}:
            return
        choice, accepted = QInputDialog.getItem(
            self, "Scan coverage", "Choose which TCP ports to check. A full scan can take tens of minutes.",
            ["All TCP ports", "Selected ports"], 0, False
        )
        if not accepted:
            return
        ports = "all"
        if choice == "Selected ports":
            ports, accepted = QInputDialog.getText(self, "Selected ports", "TCP ports or ranges:", text="80,443,8080,8443")
            if not accepted or not ports.strip():
                return
            ports = ports.strip()
        draft = (
            f"Run a full security assessment of this authorized target: {target}\n"
            f"TCP port scope: {ports}. Run every configured stage: web/TLS checks, port discovery and services, "
            "a limited crawl with ZAP passive analysis, Nikto, selected Nuclei checks, and current advisory lookup. "
            "Coordinate the results into a saved report with evidence, candidate findings, fixes and incomplete coverage."
        )
        self.clear_attachments()
        existing = self.composer.toPlainText().strip()
        final_draft = existing + "\n\n" + draft if existing else draft
        self.composer.setPlainText(final_draft)
        # An edited draft goes through normal chat so additional scope limits
        # cannot be silently ignored by stale GUI metadata.
        self._full_scan_draft = (final_draft, {"target": target, "ports": ports}) if not existing else None
        self.composer.setFocus()

    def open_scan_report(self) -> None:
        if self._report_path and self._report_path.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self._report_path)))

    def start_backend(self) -> None:
        if self._closing or (self._process is not None and self._process.poll() is None):
            return
        if not LAUNCHER.is_file():
            self._set_status("Launcher is missing", "error")
            self._add_message("notice", f"Cannot find the agent launcher: {LAUNCHER}")
            return
        self._generation += 1
        generation = self._generation
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        env["ORCA_ASKPASS"] = str(ASKPASS)
        try:
            process = subprocess.Popen(
                [str(LAUNCHER), "--jsonl"],
                cwd=str(PROJECT_DIR),
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except OSError as exc:
            self._set_status("Could not start agent", "error")
            self._add_message("notice", f"Could not start the local agent: {exc}")
            return
        self._process = process
        self._write_queue = queue.Queue()
        self._ready = False
        self._busy = False
        self._stopping = False
        self._restart_after_exit = False
        self._set_status("Starting local model…", "starting")
        self._refresh_controls()
        stdout_thread = threading.Thread(
            target=self._read_stream, args=(generation, "stdout", process.stdout), daemon=True
        )
        stderr_thread = threading.Thread(
            target=self._read_stream, args=(generation, "stderr", process.stderr), daemon=True
        )
        stdout_thread.start()
        stderr_thread.start()
        threading.Thread(
            target=self._write_loop, args=(generation, process, self._write_queue), daemon=True
        ).start()
        threading.Thread(
            target=self._wait_loop, args=(generation, process, stdout_thread, stderr_thread), daemon=True
        ).start()

    def _read_stream(self, generation: int, kind: str, stream) -> None:
        if stream is None:
            return
        try:
            for line in stream:
                try:
                    self.process_line.emit(generation, kind, line.rstrip("\r\n"))
                except RuntimeError:
                    return  # Window closed while the reader was finishing.
        except (OSError, UnicodeError) as exc:
            try:
                self.process_line.emit(generation, "stderr", f"Reading agent output failed: {exc}")
            except RuntimeError:
                pass

    def _write_loop(self, generation: int, process: subprocess.Popen[str], items: queue.Queue) -> None:
        while True:
            payload = items.get()
            if payload is None:
                return
            try:
                if process.stdin is None:
                    raise BrokenPipeError("Agent input is unavailable")
                process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
                process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                try:
                    self.write_error.emit(generation, f"Could not send message to agent: {exc}")
                except RuntimeError:
                    pass
                return

    def _wait_loop(
        self,
        generation: int,
        process: subprocess.Popen[str],
        stdout_thread: threading.Thread,
        stderr_thread: threading.Thread,
    ) -> None:
        code = process.wait()
        stdout_thread.join(timeout=2)
        stderr_thread.join(timeout=2)
        try:
            self.process_exit.emit(generation, code)
        except RuntimeError:
            pass  # The GUI is already gone.

    def _on_process_line(self, generation: int, kind: str, line: str) -> None:
        if generation != self._generation or self._closing or not line:
            return
        if kind == "stderr":
            if not self._stopping:
                self._set_status(line, "starting" if not self._ready else "error")
            return
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            if not self._stopping:
                self._set_status(line, "starting" if not self._ready else "working")
            return
        if not isinstance(event, dict):
            return
        event_type = event.get("type") or event.get("event")
        if self._stopping and event_type not in {"error"}:
            return
        if event_type == "ready":
            self._ready = True
            self._model = str(event.get("model") or "Local model")
            model_name = Path(self._model).stem.replace("-PTQ1_0", "").replace("Ternary-", "").replace("-", " ")
            self.model_label.setText(model_name)
            self.model_label.setToolTip(self._model)
            self._set_status("Ready", "ready")
            self._refresh_controls()
            self.composer.setFocus()
        elif event_type == "tool_start":
            self._ensure_activity().tool_start(event.get("step", "?"), event.get("name", "tool"), event.get("args"))
            self._set_status(f"Using {event.get('name', 'a tool')}…", "working")
        elif event_type == "tool_result":
            self._ensure_activity().tool_result(
                event.get("step", "?"), event.get("name", "tool"), event.get("result"),
                cached=event.get("cached") is True,
            )
            self._set_status("Thinking…", "working")
        elif event_type == "status":
            self._set_status(str(event.get("message") or "Working…"), "working")
        elif event_type == "answer":
            self._add_message("assistant", str(event.get("text") or ""))
        elif event_type == "assessment_report":
            path = Path(str(event.get("path", ""))).resolve()
            if path.is_relative_to(OUTPUT_DIR / "security-reports") and path.suffix == ".md" and path.is_file():
                self._report_path = path
                self.report_button.setEnabled(True)
        elif event_type == "conversation_saved":
            self._refresh_history()
        elif event_type == "documents_indexed":
            results = event.get("results") or []
            indexed = sum(result.get("status") == "indexed" for result in results)
            unchanged = sum(result.get("status") == "unchanged" for result in results)
            errors = [result for result in results if result.get("status") == "error"]
            message = f"Reference files: {indexed} added or updated"
            if unchanged:
                message += f", {unchanged} already available"
            message += "."
            for result in errors:
                message += f"\nCould not add {result.get('name') or Path(str(result.get('path') or '')).name}: {result.get('error') or 'File could not be read.'}"
            for result in results:
                limits = result.get("limits") or []
                if limits:
                    message += f"\n{result.get('name') or 'Reference file'}: " + "; ".join(str(limit) for limit in limits)
            self._add_message("notice", message)
            self._refresh_reference_files()
            self._busy = False
            self._set_status("Ready", "ready")
            self._refresh_controls()
        elif event_type == "task_done":
            self._busy = False
            self._activity = None
            self._set_status("Ready", "ready")
            self._refresh_controls()
            self.composer.setFocus()
        elif event_type == "error":
            message = str(event.get("message") or "Agent error")
            self._add_message("notice", message)
            self._set_status("Agent error", "error")
            self._busy = False
            self._activity = None
            self._refresh_controls()

    def _on_write_error(self, generation: int, message: str) -> None:
        if generation != self._generation or self._closing:
            return
        self._add_message("notice", message)
        self._set_status("Agent connection lost", "error")
        self._busy = False
        self._refresh_controls()

    def _on_process_exit(self, generation: int, code: int) -> None:
        if generation != self._generation or self._closing:
            return
        was_stopping = self._stopping
        should_restart = self._restart_after_exit
        # Unexpected parent exits can leave command children alive too. A normal
        # Stop already scheduled cleanup for this captured group before signalling.
        if not was_stopping and self._process is not None:
            _schedule_group_cleanup(self._process.pid, grace_seconds=0)
        self._process = None
        self._write_queue = None
        self._ready = False
        self._busy = False
        self._stopping = False
        self._activity = None
        self._refresh_controls()
        if should_restart:
            self._restart_after_exit = False
            if was_stopping:
                self._set_status("Restarting local agent…", "starting")
            QTimer.singleShot(0, self.start_backend)
        else:
            self._set_status("Agent stopped", "error")
            self._add_message("notice", f"The local agent stopped (exit code {code}). Choose New chat to restart it.")

    def send_message(self) -> None:
        text = self.composer.toPlainText().strip()
        if not (text or self._attachments) or not self._ready or self._busy or self._stopping or self._write_queue is None:
            return
        attachments = self._attachments.copy()
        if attachments and not text:
            text = DEFAULT_MEDIA_QUESTION
        display_text = text
        if attachments:
            display_text += "\n\nAttachments: " + ", ".join(Path(path).name for path in attachments)
        self._add_message("user", display_text)
        payload = {"type": "task", "text": text}
        if attachments:
            payload = {"type": "media_task", "text": text, "attachments": attachments}
        elif self._full_scan_draft and text == self._full_scan_draft[0]:
            payload = {"type": "full_assessment", "text": text, **self._full_scan_draft[1]}
        payload["conversation_id"] = self._conversation_id
        self._full_scan_draft = None
        self.composer.clear()
        self.clear_attachments()
        self._activity = None
        self._busy = True
        self._set_status("Thinking…", "working")
        self._refresh_controls()
        self._write_queue.put_nowait(payload)

    def _signal_process(self, sig: int) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        except OSError as exc:
            self._set_status(f"Could not stop agent: {exc}", "error")

    def stop_task(self) -> None:
        if not self._busy or self._stopping:
            return
        self._stopping = True
        self._restart_after_exit = True
        self._set_status("Stopping task…", "starting")
        self._refresh_controls()
        if self._process is not None:
            _schedule_group_cleanup(self._process.pid)
        self._signal_process(signal.SIGINT)
        self._add_message("notice", "Stopping the current task. Orca will reconnect with a fresh model conversation; this chat remains visible.")

    def new_chat(self) -> None:
        if self._busy or self._stopping:
            return
        self._conversation_id = self._memory.new_conversation()
        self._refresh_history()
        self._clear_chat()
        self._show_welcome()
        self.composer.clear()
        self._ready = False
        self._busy = False
        self._refresh_controls()
        if self._process is None or self._process.poll() is not None:
            self.start_backend()
            return
        self._stopping = True
        self._restart_after_exit = True
        self._set_status("Starting new chat…", "starting")
        _schedule_group_cleanup(self._process.pid)
        self._signal_process(signal.SIGINT)

    def closeEvent(self, event) -> None:
        self._closing = True
        if self._write_queue is not None:
            self._write_queue.put_nowait({"type": "quit"})
            self._write_queue.put_nowait(None)
        if self._process is not None:
            _schedule_group_cleanup(self._process.pid, grace_seconds=0, kill_seconds=2)
        self._signal_process(signal.SIGTERM)
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Orca Bonsai")
    app.setOrganizationName("Orca Local")
    window = OrcaWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
