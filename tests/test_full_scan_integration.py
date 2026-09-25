"""Full-scan GUI/backend routing and bounded model review; no remote scans."""
import io
import json
import os
from pathlib import Path
import queue
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_agent as agent
from orca_security_context import compact_assessment
from orca_task_evidence import TaskEvidence


def record():
    return {"assessment_status": "partial", "target": "https://example.test/",
            "coverage": [{"stage": s, "status": "partial" if s == "services" else "complete"}
                         for s in ("inventory", "web", "tls", "services", "web_audit", "nikto", "nuclei", "advisories")],
            "counts": {"total": 125, "candidate": 125, "confirmed_exploits": 0},
            "findings": [{"id": f"candidate-{n}", "classification": "candidate", "severity": "medium",
                          "title": "Candidate to verify", "evidence": ["x" * 5000], "sources": ["scanner"]} for n in range(8)],
            "report_path": "/tmp/assessment/REPORT.md", "manifest_path": "/tmp/assessment/manifest.json",
            "limits": ["Selected checks; incomplete service scan; candidates are unverified."]}


class FullRouteTests(unittest.TestCase):
    def test_equivalent_full_port_scopes_share_cache(self):
        def key(ports):
            return agent.check_cache_key("full_security_assessment", {"target": "https://example.test", "ports": ports})
        self.assertEqual(key("80,443,8000-8002"), key("443,80,8000,8001,8002"))
        self.assertEqual(key("all"), key("1-65535"))
        self.assertNotEqual(key("80"), key("443"))

    def test_pipeline_precedes_tool_free_review_and_coverage_survives(self):
        calls, events, messages = [], [], []
        def pipeline(*args):
            calls.append("pipeline")
            return record()
        def model(path, payload, timeout):
            calls.append("review")
            self.assertEqual(payload["tools"], [])
            self.assertEqual(payload["tool_choice"], "none")
            evidence = json.loads(payload["messages"][1]["content"])
            self.assertEqual(evidence["assessment_status"], "partial")
            self.assertEqual(len(evidence["coverage"]), 8)
            self.assertGreater(evidence["omitted_findings"], 0)
            return {"choices": [{"finish_reason": "stop", "message": {"content": "Scanner candidates require verification."}}]}
        with patch.object(agent, "tool_full_security_assessment", side_effect=pipeline), patch.object(agent, "request_json", side_effect=model):
            agent.run_full_scan_task(messages, "test-model", "Assess my target", "https://example.test", event_sink=events.append)
        self.assertEqual(calls, ["pipeline", "review"])
        answer = next(e["text"] for e in events if e["type"] == "answer")
        self.assertIn("incomplete stages", answer)
        self.assertIn("services: partial", answer)
        self.assertIn("/tmp/assessment/REPORT.md", answer)

    def test_failed_review_still_returns_durable_report(self):
        events = []
        with patch.object(agent, "tool_full_security_assessment", return_value=record()), patch.object(agent, "request_json", side_effect=RuntimeError("offline")):
            agent.run_full_scan_task([], "m", "scan", "example.test", event_sink=events.append)
        answer = next(e["text"] for e in events if e["type"] == "answer")
        self.assertIn("could not review", answer)
        self.assertIn("/tmp/assessment/REPORT.md", answer)

    def test_invalid_request_does_not_ask_model(self):
        events = []
        with patch.object(agent, "tool_full_security_assessment", return_value={"error": "Invalid target"}), patch.object(agent, "request_json") as model:
            agent.run_full_scan_task([], "m", "scan", "bad", event_sink=events.append)
        model.assert_not_called()
        self.assertEqual(events[-1]["text"], "Invalid target")

    def test_full_scan_result_reused_in_chat_even_if_partial(self):
        response = {"choices": [{"message": {"tool_calls": [{"id": "a", "type": "function", "function": {
            "name": "full_security_assessment", "arguments": json.dumps({"target": "https://example.test", "ports": "443"})}}]}}]}
        events = []
        with patch.object(agent, "request_json", side_effect=[response, response, {"choices": [{"message": {"content": "Review the report."}}]}]), \
             patch.object(agent, "review_progress", return_value=None), \
             patch.object(agent, "tool_full_security_assessment", return_value=record()) as pipeline:
            agent.run_task([{"role": "system", "content": "test"}], "m", "full scan", 4, events.append)
        pipeline.assert_called_once()
        self.assertEqual([e["cached"] for e in events if e["type"] == "tool_result"], [False, True])

    def test_compact_review_and_history_remain_valid_json(self):
        for limit in (0, 1, 100, 500, 1000, 1700, 6500):
            compact = compact_assessment(record(), limit)
            self.assertLessEqual(len(compact), limit)
            if compact:
                json.loads(compact)
        evidence = TaskEvidence()
        evidence.add("full_security_assessment", {"target": "example.test"}, record())
        for limit in (500, 1100, 4500):
            payload = json.loads(evidence.render(limit).split("Result: ", 1)[1])
            self.assertIn("note", payload)
        self.assertIn("REPORT.md", evidence.render(4500))

    def test_jsonl_uses_direct_route(self):
        request = {"type": "full_assessment", "text": "scan", "target": "example.test", "ports": "443"}
        with tempfile.TemporaryDirectory() as directory, \
             patch.dict(os.environ, {"ORCA_MEMORY_DB": str(Path(directory) / "memory.sqlite3")}), \
             patch.object(sys, "argv", ["orca_agent.py", "--jsonl"]), \
             patch.object(sys, "stdin", io.StringIO(json.dumps(request) + "\n")), \
             patch.object(agent, "choose_model", return_value="m"), \
             patch.object(agent, "run_full_scan_task") as full, patch.object(agent, "run_task") as chat, \
             patch.object(agent, "emit_jsonl") as events:
            self.assertEqual(agent.main(), 0)
        full.assert_called_once()
        self.assertEqual(full.call_args.args[3:5], ("example.test", "443"))
        chat.assert_not_called()
        self.assertEqual(events.call_args.args[0]["type"], "task_done")
        agent.JSONL_MODE = False


class FullGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import orca_gui
        cls.gui = orca_gui
        cls.app = orca_gui.QApplication.instance() or orca_gui.QApplication([])

    def setUp(self):
        self.window = self.gui.OrcaWindow(auto_start=False)
        self.window._ready = True
        self.window._write_queue = queue.Queue()
        self.addCleanup(self.window.close)

    def prepare(self):
        with patch.object(self.gui.QInputDialog, "getText", return_value=("https://example.test", True)), \
             patch.object(self.gui.QInputDialog, "getItem", return_value=("All TCP ports", True)):
            self.window.compose_security_check()

    def test_unedited_scan_draft_uses_direct_pipeline(self):
        self.prepare()
        self.window.send_message()
        payload = self.window._write_queue.get_nowait()
        self.assertEqual(payload["type"], "full_assessment")
        self.assertEqual(payload["ports"], "all")
        self.assertEqual(payload["target"], "https://example.test")

    def test_edited_scope_is_not_overridden_by_hidden_metadata(self):
        self.prepare()
        self.window.composer.setPlainText(self.window.composer.toPlainText() + " Only check TLS.")
        self.window.send_message()
        self.assertEqual(self.window._write_queue.get_nowait()["type"], "task")

    def test_report_available_before_task_done_and_outside_path_ignored(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(self.gui, "OUTPUT_DIR", Path(temp)):
            report = Path(temp) / "security-reports" / "scan" / "REPORT.md"
            report.parent.mkdir(parents=True)
            report.write_text("Running; stages pending")
            event = {"type": "assessment_report", "path": str(report)}
            self.window._on_process_line(0, "stdout", json.dumps(event))
            self.assertTrue(self.window.report_button.isEnabled())
            self.assertEqual(self.window._report_path, report)
            event["path"] = __file__
            self.window._on_process_line(0, "stdout", json.dumps(event))
            self.assertEqual(self.window._report_path, report)


if __name__ == "__main__":
    unittest.main()
