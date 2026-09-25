"""Deleting saved chats through the GUI, using a disposable real database."""
import os
from pathlib import Path
import queue
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
from PySide6.QtWidgets import QApplication, QLabel
import orca_gui as gui
from orca_memory import MemoryStore


class HistoryDeletionGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name).resolve()
        self.store = MemoryStore(self.root / "private" / "memory.sqlite3")
        self.older = self.store.new_conversation()
        self.store.append_message(self.older, "user", "Earlier conversation survives one deletion.")
        self.store.append_message(self.older, "assistant", "Earlier answer remains available.")
        self.selected = self.store.new_conversation()
        self.store.append_message(self.selected, "user", "Zephyrtrace selected chat should be deleted.")
        self.store.append_message(self.selected, "assistant", "Zephyrtrace saved answer.")
        self.reference = self.root / "reference.txt"
        self.reference.write_text("The durable handbook contains the cobalt guidance.", encoding="utf-8")
        self.assertEqual(self.store.index_document(str(self.reference))["status"], "indexed")
        self.documents_before = self.store.list_documents()
        self.window = gui.OrcaWindow(auto_start=False, memory_store=self.store)
        self.prevent_backend = patch.object(self.window, "start_backend")
        self.prevent_backend.start()
        self.window._ready = True
        self.window._write_queue = queue.Queue()
        self.window._refresh_controls()

    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        self.app.processEvents()
        self.prevent_backend.stop()
        self.temp.cleanup()

    def current_transcript(self):
        parts = []
        for index in range(self.window.chat_layout.count()):
            widget = self.window.chat_layout.itemAt(index).widget()
            if widget is not None:
                parts.extend(label.text() for label in widget.findChildren(QLabel))
        return "\n".join(parts)

    def set_draft(self):
        self.window.add_attachments([str(self.root / "draft-video.mp4")])
        self.window.composer.setPlainText("An unsent draft")
        self.window._full_scan_draft = ("An unsent draft", {"target": "https://example.test", "ports": "443"})

    def assert_draft_cleared(self):
        self.assertEqual(self.window.composer.toPlainText(), "")
        self.assertEqual(self.window._attachments, [])
        self.assertIsNone(self.window._full_scan_draft)

    def assert_references_unchanged(self):
        self.assertEqual(self.store.list_documents(), self.documents_before)
        self.assertEqual(len(self.store.search_documents("cobalt")), 1)
        self.assertTrue(self.reference.is_file())

    def assert_safe_confirmation(self, question):
        question.assert_called_once()
        args, kwargs = question.call_args
        buttons = kwargs.get("buttons", args[3] if len(args) > 3 else None)
        default = kwargs.get("defaultButton", args[4] if len(args) > 4 else None)
        self.assertEqual(buttons, gui.QMessageBox.Yes | gui.QMessageBox.No)
        self.assertEqual(default, gui.QMessageBox.No)

    def test_cancel_deletion_preserves_selected_chat_transcript_and_draft(self):
        self.set_draft()
        before = self.store.list_conversations()
        transcript = self.current_transcript()
        for method in (self.window.delete_current_conversation, self.window.clear_chat_history):
            with self.subTest(action=method.__name__), \
                 patch.object(gui.QMessageBox, "question", return_value=gui.QMessageBox.No) as question:
                method()
                self.assert_safe_confirmation(question)
                self.assertEqual(self.store.list_conversations(), before)
                self.assertEqual(self.window._conversation_id, self.selected)
                self.assertEqual(self.current_transcript(), transcript)
                self.assertEqual(self.window.composer.toPlainText(), "An unsent draft")
                self.assertEqual(len(self.window._attachments), 1)
                self.assertIsNotNone(self.window._full_scan_draft)
        self.assert_references_unchanged()

    def test_delete_selected_chat_selects_remaining_conversation_and_clears_draft(self):
        self.set_draft()
        with patch.object(gui.QMessageBox, "question", return_value=gui.QMessageBox.Yes) as question:
            self.window.delete_chat_action.trigger()
        self.assert_safe_confirmation(question)
        self.assertEqual([chat["id"] for chat in self.store.list_conversations()], [self.older])
        self.assertEqual(self.window._conversation_id, self.older)
        self.assertEqual(self.store.current_conversation_id(), self.older)
        self.assertEqual(self.store.load_messages(self.selected), [])
        self.assertNotIn("Zephyrtrace", self.current_transcript())
        self.assertIn("Earlier conversation survives", self.current_transcript())
        self.assertEqual(self.store.context(self.older, "Remember Zephyrtrace")["past_conversations"], [])
        self.assert_draft_cleared()
        self.assert_references_unchanged()
        self.window._ready = True
        self.window._write_queue = queue.Queue()
        self.window.composer.setPlainText("Continue this surviving chat")
        self.window.send_message()
        self.assertEqual(self.window._write_queue.get_nowait()["conversation_id"], self.older)

    def test_deleting_last_chat_creates_one_empty_conversation(self):
        self.store.delete_conversation(self.older)
        self.window._refresh_history()
        self.set_draft()
        with patch.object(gui.QMessageBox, "question", return_value=gui.QMessageBox.Yes):
            self.window.delete_current_conversation()
        conversations = self.store.list_conversations()
        self.assertEqual(len(conversations), 1)
        fresh = conversations[0]["id"]
        self.assertNotIn(fresh, {self.selected, self.older})
        self.assertEqual(self.window._conversation_id, fresh)
        self.assertEqual(self.store.current_conversation_id(), fresh)
        self.assertEqual(self.store.load_messages(fresh), [])
        self.assertNotIn("Zephyrtrace", self.current_transcript())
        self.assert_draft_cleared()
        self.assert_references_unchanged()

    def test_clear_history_leaves_one_fresh_chat_and_keeps_reference_library(self):
        self.set_draft()
        with patch.object(gui.QMessageBox, "question", return_value=gui.QMessageBox.Yes) as question:
            self.window.clear_history_action.trigger()
        self.assert_safe_confirmation(question)
        conversations = self.store.list_conversations()
        self.assertEqual(len(conversations), 1)
        fresh = conversations[0]["id"]
        self.assertNotIn(fresh, {self.selected, self.older})
        self.assertEqual(self.window._conversation_id, fresh)
        self.assertEqual(self.store.current_conversation_id(), fresh)
        self.assertEqual(self.store.load_messages(self.older), [])
        self.assertEqual(self.store.load_messages(self.selected), [])
        self.assertEqual(self.store.load_messages(fresh), [])
        self.assertEqual(self.window.history_list.count(), 1)
        self.assertNotIn("Zephyrtrace", self.current_transcript())
        self.assertNotIn("Earlier answer", self.current_transcript())
        self.assertEqual(self.store.context(fresh, "Remember Zephyrtrace")["past_conversations"], [])
        self.assert_draft_cleared()
        self.assert_references_unchanged()

    def test_clear_history_includes_chats_outside_recent_twenty(self):
        old_ids = {self.older, self.selected}
        for index in range(25):
            conversation = self.store.new_conversation()
            old_ids.add(conversation)
            self.store.append_message(conversation, "user", f"Archived Zephyrtrace conversation {index}")
        self.store.set_current_conversation(self.selected)
        self.window._refresh_history()
        self.assertEqual(self.window.history_list.count(), 20)
        with patch.object(gui.QMessageBox, "question", return_value=gui.QMessageBox.Yes):
            self.window.clear_chat_history()
        remaining = self.store.list_conversations(limit=200)
        self.assertEqual(len(remaining), 1)
        self.assertNotIn(remaining[0]["id"], old_ids)
        for conversation in old_ids:
            self.assertEqual(self.store.load_messages(conversation), [])
        self.assertEqual(self.store.context(remaining[0]["id"], "Remember Zephyrtrace")["past_conversations"], [])
        self.assert_references_unchanged()

    def test_busy_or_stopping_prevents_both_delete_actions_and_confirmation(self):
        self.set_draft()
        before = self.store.list_conversations()
        for busy, stopping in ((True, False), (False, True)):
            self.window._busy, self.window._stopping = busy, stopping
            self.window._refresh_controls()
            self.assertFalse(self.window.delete_chat_action.isEnabled())
            self.assertFalse(self.window.clear_history_action.isEnabled())
            for method in (self.window.delete_current_conversation, self.window.clear_chat_history):
                with self.subTest(action=method.__name__, busy=busy, stopping=stopping), \
                     patch.object(gui.QMessageBox, "question", return_value=gui.QMessageBox.Yes) as question:
                    method()
                    question.assert_not_called()
                    self.assertEqual(self.store.list_conversations(), before)
                    self.assertEqual(self.window._conversation_id, self.selected)
                    self.assertEqual(self.window.composer.toPlainText(), "An unsent draft")
                    self.assertEqual(len(self.window._attachments), 1)
        self.window._busy = self.window._stopping = False
        self.assert_references_unchanged()


if __name__ == "__main__":
    unittest.main()
