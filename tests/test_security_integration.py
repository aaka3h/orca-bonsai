"""Guard against lost qualifications and repeated structured scans."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_agent as agent
from orca_task_evidence import TaskEvidence, result_failed


class SecurityIntegrationTests(unittest.TestCase):
    def test_service_keys_follow_effective_scope(self):
        a = agent.check_cache_key("security_check", {"target": "https://EXAMPLE.test:443/", "check": "services"})
        b = agent.check_cache_key("security_check", {"target": "example.test", "check": "services", "ports": "443"})
        self.assertEqual(a, b)
        self.assertNotEqual(a, agent.check_cache_key("security_check", {"target": "example.test", "check": "services"}))
        self.assertNotEqual(a, agent.check_cache_key("security_check", {"target": "other.test", "check": "services", "ports": "443"}))
        self.assertNotEqual(agent.check_cache_key("security_check", {"target": "https://example.test/a", "check": "web"}),
                            agent.check_cache_key("security_check", {"target": "https://example.test/b", "check": "web"}))

    def test_equivalent_scope_reuses_a_single_scan(self):
        responses = []
        for args in [{"target": "https://example.test:443", "check": "services"},
                     {"target": "example.test", "check": "services", "ports": "443"}]:
            responses.append({"choices": [{"message": {"content": None, "tool_calls": [{"id": "call", "type": "function",
                "function": {"name": "security_check", "arguments": json.dumps(args)}}]}}]})
        responses.append({"choices": [{"message": {"content": "Port observed, no vulnerability proven."}}]})
        events = []
        with patch.object(agent, "request_json", side_effect=responses), \
             patch.object(agent, "review_progress", return_value=None), \
             patch.dict(agent.DISPATCH, {"security_check": lambda args: {"check_status": "complete", "evidence": {"open_services": [{"port": 443}]}}}):
            agent.run_task([{"role": "system", "content": agent.SYSTEM_PROMPT}], "model", "Assess my server", 5, events.append)
        self.assertEqual([e["cached"] for e in events if e["type"] == "tool_result"], [False, True])

    def test_partial_results_are_retryable(self):
        self.assertTrue(result_failed({"check_status": "partial", "evidence": {"open_services": []}}))
        self.assertFalse(result_failed({"check_status": "complete", "findings": [{"classification": "hardening"}]}))

    def test_security_evidence_recompacts_whole_qualified_records(self):
        evidence = TaskEvidence()
        raw = {"check": "web", "target": "https://example.test", "check_status": "complete",
               "findings": [{"id": "missing-csp", "classification": "hardening", "severity": "low",
                             "evidence": "HTML response lacks CSP.", "fix": "Configure a tested CSP."}],
               "evidence": {"http_status": 200}, "limits": "One response only."}
        evidence.add("security_check", {"target": raw["target"], "check": "web"}, raw)
        for budget in (500, 1100, 4500, 8000):
            rendered = evidence.render(budget)
            self.assertLessEqual(len(rendered), budget)
            payload = json.loads(rendered.split("Result: ", 1)[1])
            for finding in payload.get("findings", []):
                self.assertEqual(finding["classification"], "hardening")
                self.assertIn("evidence", finding)
            self.assertIn("note", payload)
        self.assertIn("missing-csp", evidence.render(4500))
        raw["findings"][0]["classification"] = "changed"
        self.assertNotIn("changed", evidence.render(4500))


if __name__ == "__main__":
    unittest.main()
