"""Regression checks for stopping actions and reporting saved evidence.

Every completion and tool handler is mocked. No terminal commands or network
requests are run by these tests.
"""

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_agent as agent


def completion(content=None, calls=None, finish_reason="stop"):
    return {"choices": [{"message": {"content": content, "tool_calls": calls or []}, "finish_reason": finish_reason}]}


def call(command, call_id="check"):
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": "run_command", "arguments": json.dumps({"command": command})},
    }


class RecordedRequests:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def __call__(self, path, payload=None, timeout=600):
        self.requests.append({"path": path, "payload": copy.deepcopy(payload), "timeout": timeout})
        response = next(self.responses)
        if isinstance(response, BaseException):
            raise response
        return copy.deepcopy(response)


class TaskFinalizationTests(unittest.TestCase):
    def run_task(self, responses, *, max_steps=1, results=None, messages=None):
        request = RecordedRequests(responses)
        events = []
        executed = []
        history = messages if messages is not None else [{"role": "system", "content": agent.SYSTEM_PROMPT}]
        result_values = iter(results) if results is not None else None

        def handler(args):
            executed.append(copy.deepcopy(args))
            if result_values is not None:
                return next(result_values)
            return {"exit_code": 0, "stdout": "SAVED_OBSERVATION", "stderr": ""}

        with patch.object(agent, "request_json", side_effect=request), patch.object(agent, "review_progress", return_value=None), patch.dict(agent.DISPATCH, {"run_command": handler}):
            agent.run_task(history, "test-model", "Report the observed facts", max_steps, events.append)
        return request.requests, executed, events, history

    def answers(self, events):
        return [event["text"] for event in events if event["type"] == "answer"]

    def assert_summary_request(self, request):
        self.assertEqual(request["timeout"], 120)
        self.assertEqual(request["payload"]["tools"], [])
        self.assertEqual(request["payload"]["tool_choice"], "none")
        self.assertTrue(all(message["role"] != "tool" for message in request["payload"]["messages"]))

    def test_one_step_executes_once_and_publishes_one_summary(self):
        requests, executed, events, history = self.run_task([
            completion(calls=[call("dig example.test")]),
            completion("Observed facts summarized."),
        ])
        self.assertEqual(len(executed), 1)
        self.assertEqual(len(requests), 2)
        self.assert_summary_request(requests[-1])
        answers = self.answers(events)
        self.assertEqual(len(answers), 1)
        self.assertTrue(answers[0].startswith("I reached the 1-step work limit"))
        self.assertTrue(answers[0].endswith("Observed facts summarized."))
        self.assertEqual(history[-1], {"role": "assistant", "content": answers[0]})

    def test_varying_and_mixed_calls_finish_at_budget(self):
        requests, executed, events, _ = self.run_task([
            completion(calls=[call("dig first.test", "first")]),
            completion(calls=[call("dig first.test", "reused"), call("dig second.test", "second")]),
            completion(calls=[call("dig third.test", "third")]),
            completion("Partial findings."),
        ], max_steps=3)
        self.assertEqual(len(executed), 3)
        self.assertEqual(len(requests), 4)
        self.assert_summary_request(requests[-1])
        self.assertEqual(sum(event.get("cached", False) for event in events), 1)
        self.assertIn("3-step work limit", self.answers(events)[0])
        self.assertTrue(self.answers(events)[0].endswith("Partial findings."))

    def test_summary_keeps_early_fact_and_late_failure_after_history_trims(self):
        steps = 8
        results = [{"exit_code": 0, "stdout": "EARLIEST_SENTINEL\n" + "filler " * 450}]
        results.extend({"exit_code": 0, "stdout": f"intermediate {i}\n" + "filler " * 450} for i in range(1, steps - 1))
        results.append({"exit_code": 3, "stderr": "LATEST_FAILURE_SENTINEL", "stdout": ""})
        responses = [completion(calls=[call(f"dig item{i}.test", str(i))]) for i in range(steps)]
        responses.append(completion("Partial report includes limits."))
        requests, executed, events, _ = self.run_task(responses, max_steps=steps, results=results)
        self.assertEqual(len(executed), steps)
        final_action_messages = requests[-2]["payload"]["messages"]
        retained_tool_history = json.dumps([item for item in final_action_messages if item["role"] == "tool"])
        self.assertNotIn("EARLIEST_SENTINEL", retained_tool_history)
        summary_input = json.dumps(requests[-1]["payload"]["messages"])
        self.assertIn("EARLIEST_SENTINEL", summary_input)
        self.assertIn("LATEST_FAILURE_SENTINEL", summary_input)
        self.assertEqual(len(self.answers(events)), 1)

    def test_summary_tool_calls_never_execute_and_use_fallback(self):
        requests, executed, events, _ = self.run_task([
            completion(calls=[call("dig example.test")]),
            completion("UNTRUSTED_SUMMARY", calls=[call("never-execute", "bad-summary-call")]),
        ])
        self.assertEqual(executed, [{"command": "dig example.test"}])
        self.assert_summary_request(requests[-1])
        answer = self.answers(events)[0]
        self.assertIn("The model could not write a summary", answer)
        self.assertIn("SAVED_OBSERVATION", answer)
        self.assertNotIn("UNTRUSTED_SUMMARY", answer)

    def test_unusable_summary_responses_fall_back_to_evidence(self):
        variants = {
            "empty": completion("  "),
            "no choices": {"choices": []},
            "missing choices": {},
            "malformed message": {"choices": [{"message": "bad message"}]},
            "malformed result": None,
            "nontext content": completion({"content": "bad"}),
            "truncated": completion("TRUNCATED_RESPONSE", finish_reason="length"),
            "runtime error": RuntimeError("Model server unavailable"),
        }
        for name, result in variants.items():
            with self.subTest(name=name):
                requests, executed, events, history = self.run_task([
                    completion(calls=[call("dig example.test")]), result,
                ])
                self.assertEqual(len(executed), 1)
                self.assertEqual(len(requests), 2)
                answers = self.answers(events)
                self.assertEqual(len(answers), 1)
                self.assertIn("1-step work limit", answers[0])
                self.assertIn("The model could not write a summary", answers[0])
                self.assertIn("SAVED_OBSERVATION", answers[0])
                self.assertEqual(history[-1]["content"], answers[0])

    def test_direct_answer_is_unchanged(self):
        requests, executed, events, history = self.run_task([completion("Direct answer.")])
        self.assertEqual(len(requests), 1)
        self.assertEqual(executed, [])
        self.assertEqual(self.answers(events), ["Direct answer."])
        self.assertEqual(history[-1], {"role": "assistant", "content": "Direct answer."})

    def test_evidence_and_check_cache_reset_between_tasks(self):
        history = [{"role": "system", "content": agent.SYSTEM_PROMPT}]
        _, first_executed, _, _ = self.run_task([
            completion(calls=[call("dig example.test")]), completion("First task report."),
        ], results=[{"exit_code": 0, "stdout": "FIRST_TASK_SENTINEL"}], messages=history)
        requests, second_executed, events, _ = self.run_task([
            completion(calls=[call("dig example.test")]), completion("Second task report."),
        ], results=[{"exit_code": 0, "stdout": "SECOND_TASK_SENTINEL"}], messages=history)
        self.assertEqual(len(first_executed), 1)
        self.assertEqual(len(second_executed), 1)
        second_summary = json.dumps(requests[-1]["payload"]["messages"])
        self.assertIn("SECOND_TASK_SENTINEL", second_summary)
        self.assertNotIn("FIRST_TASK_SENTINEL", second_summary)
        self.assertFalse(any(event.get("cached", False) for event in events))


if __name__ == "__main__":
    unittest.main(verbosity=2)
