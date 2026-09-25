"""Saved task and JSONL integration against an isolated real SQLite store."""
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_agent as agent
import orca_media
from orca_memory import MemoryStore


def completion(text):
    return {"choices": [{"finish_reason": "stop", "message": {"content": text}}]}


def tool_request(query, identifier):
    return {"choices": [{"finish_reason": "tool_calls", "message": {"content": None, "tool_calls": [
        {"id": identifier, "type": "function", "function": {
            "name": "search_knowledge", "arguments": json.dumps({"query": query}),
        }},
    ]}}]}


class MemoryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name).resolve()
        self.environment = patch.dict(os.environ, {"ORCA_MEMORY_DB": str(self.root / "private" / "memory.sqlite3")})
        self.environment.start()
        self.store = MemoryStore()
        self.conversation = self.store.new_conversation()
        self.reference = self.root / "Asterlake-notes.md"
        self.reference.write_text("Asterlake review interval is 19 days. The release color is violet.\n", encoding="utf-8")
        result = self.store.index_document(str(self.reference))
        self.assertEqual(result["status"], "indexed", result)
        self.store.append_message(self.conversation, "user", "My project codename is Asterlake.")
        self.store.append_message(self.conversation, "assistant", "I will use Asterlake for this project.")
        self.previous = self.store.load_messages(self.conversation)

    def tearDown(self):
        self.environment.stop()
        self.temp.cleanup()

    def request(self, kind="task", text="What is the Asterlake review interval?", **extra):
        return {"type": kind, "text": text, "conversation_id": self.conversation, **extra}

    def run_jsonl(self, requests):
        events = []
        incoming = "\n".join(json.dumps(request) for request in [*requests, {"type": "quit"}]) + "\n"
        with patch.object(sys, "argv", ["orca_agent.py", "--jsonl", "--model", "test-model"]), \
             patch.object(sys, "stdin", io.StringIO(incoming)), \
             patch.object(agent, "JSONL_MODE", False), \
             patch.object(agent, "emit_jsonl", side_effect=events.append):
            self.assertEqual(agent.main(), 0)
        return events

    def assert_prompt_context(self, payload):
        rendered = json.dumps(payload["messages"], ensure_ascii=False)
        self.assertIn("Asterlake review interval is 19 days", rendered)
        self.assertIn("My project codename is Asterlake", rendered)
        self.assertIn("untrusted", rendered.lower())
        self.assertIn("Asterlake-notes.md", rendered)

    def test_normal_tasks_restore_history_and_references_across_wrapper_calls(self):
        first_events = []
        with patch.object(agent, "request_json", return_value=completion("The interval is 19 days [D1].")) as model:
            agent.run_saved_task(self.request(), "test-model", 3, first_events.append)
        self.assert_prompt_context(model.call_args.args[1])
        first_answer = next(event["text"] for event in first_events if event["type"] == "answer")
        self.assertIn("Asterlake-notes.md", first_answer)
        self.assertEqual(first_events[-1], {"type": "conversation_saved", "conversation_id": self.conversation})
        reloaded = MemoryStore()
        messages = reloaded.load_messages(self.conversation)
        self.assertEqual(messages[:2], self.previous)
        self.assertEqual(messages[-1], {"role": "assistant", "content": first_answer})
        with patch.object(agent, "request_json", return_value=completion("The release color is violet [D1].")) as model:
            agent.run_saved_task(self.request(text="What color did we choose for Asterlake?"), "test-model", 3, lambda event: None)
        rendered = json.dumps(model.call_args.args[1]["messages"])
        self.assertIn("The interval is 19 days", rendered)
        self.assertEqual(len(MemoryStore().load_messages(self.conversation)), 6)
        self.assertIsNone(agent.ACTIVE_MEMORY)
        self.assertIsNone(agent.ACTIVE_CONVERSATION_ID)
        self.assertEqual(agent.ACTIVE_SOURCES, {})

    def test_media_route_receives_saved_context_and_saves_observations(self):
        media_path = str(self.root / "diagram.png")
        observation = {"status": "complete", "limits": [], "media": [{
            "name": "diagram.png", "kind": "image", "limits": [],
            "frames": [{"timestamp_seconds": None, "description": "The diagram shows a violet circle."}],
        }]}
        events = []
        with patch.object(orca_media, "analyze_media_files", return_value=observation) as vision, \
             patch.object(agent, "request_json", return_value=completion("The violet diagram agrees with the Asterlake notes [D1].")) as model:
            agent.run_saved_task(self.request("media_task", attachments=[media_path]), "test-model", event_sink=events.append)
        self.assertEqual(vision.call_args.args[0], [media_path])
        payload = model.call_args.args[1]
        self.assert_prompt_context(payload)
        self.assertEqual(payload["tools"], [])
        self.assertIn("violet circle", json.dumps(payload["messages"]))
        messages = MemoryStore().load_messages(self.conversation)
        self.assertIn(media_path, messages[-2]["content"])
        self.assertIn("Asterlake-notes.md", messages[-1]["content"])
        self.assertEqual(messages[-1]["content"], next(event["text"] for event in events if event["type"] == "answer"))

    def test_full_assessment_receives_context_and_preserves_direct_scan_route(self):
        assessment = {
            "assessment_status": "partial", "target": "https://example.test",
            "coverage": [{"stage": "services", "status": "partial"}], "findings": [],
            "counts": {"total": 0, "candidate": 0, "confirmed_exploits": 0},
            "report_path": str(self.root / "REPORT.md"), "manifest_path": str(self.root / "manifest.json"),
            "limits": ["Test fixture; no network scan was run."],
        }
        events = []
        with patch.object(agent, "tool_full_security_assessment", return_value=assessment) as scan, \
             patch.object(agent, "request_json", return_value=completion("Review service coverage using the Asterlake interval [D1].")) as model:
            agent.run_saved_task(self.request("full_assessment", target="https://example.test", ports="443"), "test-model", event_sink=events.append)
        self.assertEqual(scan.call_args.args[0], {"target": "https://example.test", "ports": "443"})
        payload = model.call_args.args[1]
        self.assert_prompt_context(payload)
        self.assertEqual(payload["tools"], [])
        saved_answer = MemoryStore().load_messages(self.conversation)[-1]["content"]
        self.assertIn("incomplete", saved_answer)
        self.assertIn("Asterlake-notes.md", saved_answer)
        self.assertIn("REPORT.md", saved_answer)

    def test_model_failure_preserves_existing_history_and_emits_finished_turn(self):
        with patch.object(agent, "request_json", side_effect=RuntimeError("Test model unavailable")):
            events = self.run_jsonl([self.request(text="Asterlake failed question")])
        self.assertEqual([event["type"] for event in events], ["ready", "conversation_saved", "error", "task_done"])
        self.assertIn("Test model unavailable", events[-2]["message"])
        messages = MemoryStore().load_messages(self.conversation)
        self.assertEqual(messages[:2], self.previous)
        self.assertEqual(messages[-1], {"role": "user", "content": "Asterlake failed question"})
        self.assertEqual(len(messages), 3)
        self.assertIsNone(agent.ACTIVE_MEMORY)
        self.assertEqual(agent.ACTIVE_SOURCES, {})

    def test_reference_index_events_leave_history_unchanged_and_keep_previous_index_on_failure(self):
        with patch.object(agent, "request_json") as model:
            events = self.run_jsonl([{"type": "index_documents", "paths": [str(self.reference), str(self.root / "missing.txt")]}])
        model.assert_not_called()
        statuses = [event for event in events if event["type"] == "status"]
        self.assertEqual(len(statuses), 2)
        results = next(event["results"] for event in events if event["type"] == "documents_indexed")
        self.assertEqual([result["status"] for result in results], ["unchanged", "error"])
        self.assertEqual(events[-1]["type"], "task_done")
        self.assertEqual(MemoryStore().load_messages(self.conversation), self.previous)
        self.reference.write_bytes(b"binary\0changed")
        events = self.run_jsonl([{"type": "index_documents", "paths": [str(self.reference)]}])
        results = next(event["results"] for event in events if event["type"] == "documents_indexed")
        self.assertEqual(results[0]["status"], "error")
        self.assertIn("19 days", MemoryStore().search_documents("Asterlake")[0]["text"])
        self.assertEqual(MemoryStore().load_messages(self.conversation), self.previous)

    def test_bad_ingest_request_emits_error_and_done_without_chat_changes(self):
        events = self.run_jsonl([{"type": "index_documents", "paths": []}])
        self.assertEqual([event["type"] for event in events], ["ready", "error", "task_done"])
        self.assertEqual(MemoryStore().load_messages(self.conversation), self.previous)

    def test_retrieval_tool_keeps_distinct_source_labels_across_searches(self):
        for filename, content in [("zirconium.txt", "Zirconium marker equals amber."), ("neptunium.txt", "Neptunium marker equals teal.")]:
            path = self.root / filename
            path.write_text(content, encoding="utf-8")
            self.assertEqual(self.store.index_document(str(path))["status"], "indexed")
        events, payloads = [], []
        def model(path, payload, timeout=600):
            payloads.append(payload)
            if len(payloads) == 1:
                return tool_request("zirconium", "search-one")
            if len(payloads) == 2:
                return tool_request("neptunium", "search-two")
            return completion("Both reference markers were found.")
        with patch.object(agent, "request_json", side_effect=model):
            agent.run_saved_task(self.request(text="Find the two markers in references."), "test-model", 4, events.append)
        searches = [event["result"]["sources"][0] for event in events if event["type"] == "tool_result"]
        self.assertEqual([source["name"] for source in searches], ["zirconium.txt", "neptunium.txt"])
        self.assertNotEqual(searches[0]["source_id"], searches[1]["source_id"])
        answer = next(event["text"] for event in events if event["type"] == "answer")
        for source in searches:
            self.assertIn(f"[{source['source_id']}] {source['name']}", answer)


if __name__ == "__main__":
    unittest.main()
