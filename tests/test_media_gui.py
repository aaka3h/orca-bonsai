"""Headless checks for local media, reference files and conversation routing."""
from pathlib import Path
import os
import queue
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QImage, QKeyEvent
from PySide6.QtWidgets import QApplication, QLabel, QPushButton
import orca_gui as gui


class Memory:
    """An isolated store so GUI checks never change the user's saved chats."""
    def __init__(self):
        self.current = "first"
        self.conversations = [{"id": "first", "title": "First chat"}, {"id": "older", "title": "Older chat"}]
        self.messages = {"older": [{"role": "user", "content": "Previous question"}, {"role": "assistant", "content": "Previous answer"}]}
        self.documents = []

    def current_conversation_id(self):
        return self.current

    def new_conversation(self):
        self.current = "new-" + str(len(self.conversations))
        self.conversations.insert(0, {"id": self.current, "title": "New chat"})
        return self.current

    def set_current_conversation(self, value):
        self.current = value

    def list_conversations(self, limit=20):
        return self.conversations[:limit]

    def load_messages(self, conversation_id, limit=40):
        return self.messages.get(conversation_id, [])[-limit:]

    def list_documents(self):
        return self.documents

    def remove_document(self, document_id):
        self.documents = [document for document in self.documents if document["id"] != document_id]


class MediaGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.memory = Memory()
        self.window = gui.OrcaWindow(auto_start=False, memory_store=self.memory)
        self.window._ready = True
        self.window._write_queue = queue.Queue()
        self.window._refresh_controls()
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.image = Path(self.temp.name).resolve() / "sample image.png"
        bitmap = QImage(100, 50, QImage.Format_RGB32)
        bitmap.fill(Qt.red)
        self.assertTrue(bitmap.save(str(self.image)))
        self.video = Path(self.temp.name).resolve() / "clip.MP4"
        self.video.write_bytes(b"validated by backend")

    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()
        self.temp.cleanup()

    def payload(self):
        return self.window._write_queue.get_nowait()

    def test_attachment_only_enter_uses_default_question(self):
        self.window.add_attachments([str(self.image), str(self.video)])
        self.assertTrue(self.window.send_button.isEnabled())
        self.app.sendEvent(self.window.composer, QKeyEvent(QEvent.KeyPress, Qt.Key_Return, Qt.NoModifier))
        self.assertEqual(self.payload(), {
            "type": "media_task", "text": gui.DEFAULT_MEDIA_QUESTION,
            "attachments": [str(self.image), str(self.video)], "conversation_id": "first",
        })
        self.assertEqual(self.window._attachments, [])
        self.assertEqual(self.window.composer.toPlainText(), "")
        self.assertFalse(self.window.attach_button.isEnabled())
        self.assertTrue(self.window.stop_button.isEnabled())

    def test_question_and_media_route_wins_over_stale_scan_metadata(self):
        self.window.add_attachments([str(self.image)])
        self.window.composer.setPlainText("What is shown?")
        self.window._full_scan_draft = ("What is shown?", {"target": "https://example.test", "ports": "all"})
        self.window.send_message()
        self.assertEqual(self.payload(), {
            "type": "media_task", "text": "What is shown?", "attachments": [str(self.image)], "conversation_id": "first",
        })
        self.assertIsNone(self.window._full_scan_draft)

    def test_unready_and_disconnected_preserve_question_and_files(self):
        self.window.add_attachments([str(self.image)])
        self.window.composer.setPlainText("Please describe")
        for ready, channel in [(False, queue.Queue()), (True, None)]:
            self.window._ready = ready
            self.window._write_queue = channel
            self.window._refresh_controls()
            self.assertFalse(self.window.send_button.isEnabled())
            self.window.send_message()
            self.assertEqual(self.window._attachments, [str(self.image)])
            self.assertEqual(self.window.composer.toPlainText(), "Please describe")
            self.assertFalse(self.window._busy)

    def test_thumbnail_remove_and_clear_controls(self):
        self.window.add_attachments([str(self.image), str(self.video)])
        previews = self.window.attachment_panel.findChildren(QLabel)
        self.assertTrue(any(not label.pixmap().isNull() for label in previews))
        remove = next(button for button in self.window.attachment_panel.findChildren(QPushButton)
                      if button.accessibleName() == "Remove " + self.image.name)
        remove.click()
        self.assertEqual(self.window._attachments, [str(self.video)])
        self.window.clear_attachments_button.click()
        self.assertEqual(self.window._attachments, [])
        self.assertTrue(self.window.attachment_panel.isHidden())
        self.assertFalse(self.window.send_button.isEnabled())

    def test_maximum_duplicate_and_supported_types(self):
        paths = [str(Path(self.temp.name).resolve() / ("file" + ext)) for ext in sorted(gui.IMAGE_EXTENSIONS | gui.VIDEO_EXTENSIONS)]
        with patch.object(self.window, "_add_message") as notice:
            self.window.add_attachments(paths + paths[:1])
            self.assertEqual(self.window._attachments, paths[:4])
            self.assertEqual(notice.call_count, 1)
        self.assertFalse(self.window.attach_button.isEnabled())
        self.window.remove_attachment(paths[0])
        self.assertTrue(self.window.attach_button.isEnabled())
        self.window.add_attachments([paths[1]])
        self.assertEqual(len(self.window._attachments), 3)

    def test_picker_cancel_preserves_scan_but_media_choice_cancels_it(self):
        self.window.composer.setPlainText("Generated scan")
        self.window._full_scan_draft = ("Generated scan", {"target": "https://example.test", "ports": "all"})
        with patch.object(gui.QFileDialog, "getOpenFileNames", return_value=([], "")):
            self.window.choose_attachments()
        self.assertIsNotNone(self.window._full_scan_draft)
        with patch.object(gui.QFileDialog, "getOpenFileNames", return_value=([str(self.image)], "")):
            self.window.choose_attachments()
        self.assertIsNone(self.window._full_scan_draft)
        self.assertEqual(self.window.composer.toPlainText(), "")

    def test_full_scan_choice_clears_media_and_keeps_dedicated_route(self):
        self.window.add_attachments([str(self.image)])
        with patch.object(gui.QInputDialog, "getText", return_value=("https://example.test", True)), \
             patch.object(gui.QInputDialog, "getItem", return_value=("All TCP ports", True)):
            self.window.security_button.trigger()
        self.assertEqual(self.window._attachments, [])
        self.window.send_message()
        payload = self.payload()
        self.assertEqual(payload["type"], "full_assessment")
        self.assertEqual(payload["target"], "https://example.test")
        self.assertEqual(payload["ports"], "all")
        self.assertEqual(payload["conversation_id"], "first")
        self.assertNotIn("attachments", payload)

    def test_plain_chat_and_edited_scan_preserve_normal_route(self):
        for text in ("Hello", "Edited scan with limits"):
            self.window._busy = False
            self.window._full_scan_draft = ("Original scan", {"target": "https://example.test", "ports": "all"})
            self.window.composer.setPlainText(text)
            self.window.send_message()
            self.assertEqual(self.payload(), {"type": "task", "text": text, "conversation_id": "first"})

    def test_new_chat_clears_drafts_and_changes_conversation(self):
        self.window.add_attachments([str(self.image)])
        self.window.composer.setPlainText("Draft")
        with patch.object(self.window, "start_backend") as start:
            self.window.new_chat()
        start.assert_called_once()
        self.assertEqual(self.window._attachments, [])
        self.assertEqual(self.window.composer.toPlainText(), "")
        self.assertNotEqual(self.window._conversation_id, "first")
        self.assertEqual(self.window._conversation_id, self.memory.current)

    def test_history_load_switch_and_send(self):
        with patch.object(self.window, "_add_message") as messages:
            self.window._select_conversation(self.window.history_list.item(1))
        self.assertEqual(self.window._conversation_id, "older")
        self.assertEqual([call.args for call in messages.call_args_list], [
            ("user", "Previous question"), ("assistant", "Previous answer"),
        ])
        self.window.composer.setPlainText("Follow-up")
        self.window.send_message()
        self.assertEqual(self.payload()["conversation_id"], "older")
        self.assertFalse(self.window.history_list.isEnabled())
        self.window._select_conversation(self.window.history_list.item(0))
        self.assertEqual(self.window._conversation_id, "older")

    def test_reference_ingest_and_result_notice(self):
        path = str(Path(self.temp.name).resolve() / "notes.md")
        self.window.add_attachments([str(self.image)])
        self.window.composer.setPlainText("Keep my draft")
        with patch.object(gui.QFileDialog, "getOpenFileNames", return_value=([path, path], "")):
            self.window.reference_button.trigger()
        self.assertEqual(self.payload(), {"type": "index_documents", "paths": [path]})
        self.assertTrue(self.window._busy)
        self.assertFalse(self.window.reference_button.isEnabled())
        self.assertEqual(self.window._attachments, [str(self.image)])
        self.memory.documents = [{"id": "notes", "name": "notes.md", "path": path, "chunks": 2}]
        with patch.object(self.window, "_add_message") as message:
            self.window._on_process_line(0, "stdout", '{"type":"documents_indexed","results":[{"name":"notes.md","status":"indexed","chunks":2,"limits":[]}]}')
        self.assertIn("1 added or updated", message.call_args.args[1])
        self.assertIn("1 file available", self.window.reference_label.text())
        self.assertFalse(self.window._busy)
        self.assertEqual(self.window.composer.toPlainText(), "Keep my draft")

    def test_busy_prevents_media_changes_and_stop_remains_available(self):
        self.window.add_attachments([str(self.image)])
        self.window._busy = True
        self.window._refresh_controls()
        self.window.add_attachments([str(self.video)])
        self.window.remove_attachment(str(self.image))
        self.assertEqual(self.window._attachments, [str(self.image)])
        self.assertFalse(self.window.attach_button.isEnabled())
        self.assertFalse(self.window.clear_attachments_button.isEnabled())
        self.assertTrue(self.window.stop_button.isEnabled())

    def test_reference_remove_is_explicit_and_original_file_is_preserved(self):
        document = {"id": "sample", "name": self.image.name, "path": str(self.image), "chunks": 1}
        self.memory.documents = [document]
        self.window._refresh_reference_files()
        choice = f"{document['name']} — {document['path']}"
        with patch.object(gui.QInputDialog, "getItem", return_value=(choice, False)):
            self.window.remove_reference_file()
        self.assertEqual(len(self.memory.documents), 1)
        with patch.object(gui.QInputDialog, "getItem", return_value=(choice, True)):
            self.window.remove_reference_file()
        self.assertEqual(self.memory.documents, [])
        self.assertTrue(self.image.is_file())
        self.assertFalse(self.window.remove_reference_button.isVisible())


if __name__ == "__main__":
    unittest.main()
