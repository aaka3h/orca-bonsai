"""Checkpoint contract tests; all model requests are mocked, with no tools run."""

import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
from orca_task_planner import review_progress


def plan(decision="continue", **changes):
    value = {
        "decision": decision,
        "remaining": "Read back the three files." if decision == "continue" else "",
        "next_action": "Read the saved files and compare their contents." if decision == "continue" else "",
        "reason": "Creation succeeded; the requested readback is still unverified.",
    }
    return {**value, **changes}


def completion(value=None, *, content=None, finish_reason="stop", **message_changes):
    message = {"content": json.dumps(value) if content is None else content, "tool_calls": []}
    message.update(message_changes)
    return {"choices": [{"message": message, "finish_reason": finish_reason}]}


class TaskPlannerTests(unittest.TestCase):
    def review(self, response, **kwargs):
        requests = []

        def request(path, payload, timeout):
            requests.append((path, copy.deepcopy(payload), timeout))
            if isinstance(response, BaseException):
                raise response
            return response

        result = review_progress(
            "local-model", kwargs.get("task", "Create three files and read them back."),
            kwargs.get("evidence", "Three file writes reported success."),
            kwargs.get("previous"), request,
        )
        self.assertEqual(len(requests), 1)
        return result, requests[0]

    def test_continue_has_one_pending_outcome_and_tool_free_request(self):
        expected = plan()
        result, (path, payload, timeout) = self.review(completion(expected))
        self.assertEqual(result, expected)
        self.assertEqual(path, "/chat/completions")
        self.assertEqual(timeout, 90)
        self.assertEqual(payload["tools"], [])
        self.assertEqual(payload["tool_choice"], "none")
        self.assertEqual(payload["response_format"], {"type": "json_object"})
        self.assertEqual(payload["max_tokens"], 350)
        self.assertEqual(payload["temperature"], 0.0)
        self.assertFalse(payload["chat_template_kwargs"]["enable_thinking"])
        self.assertEqual(len(payload["messages"]), 2)
        data = json.loads(payload["messages"][1]["content"])
        self.assertEqual(data["original_request"], "Create three files and read them back.")
        self.assertIn("Three file writes", data["recorded_tool_results"])

    def test_finish_may_report_unresolved_outcome_without_next_action(self):
        expected = plan("finish", remaining="One script failed.", reason="Available checks completed; report the observed limitations.")
        result, _ = self.review(completion(expected))
        self.assertEqual(result, expected)

    def test_inputs_are_bounded_and_prior_remains_valid_json(self):
        previous = plan(remaining="r" * 200, next_action="a" * 200, reason="b" * 200)
        _, (_, payload, _) = self.review(completion(plan()), task="t" * 5000,
                                         evidence="e" * 12000, previous=previous)
        data = json.loads(payload["messages"][1]["content"])
        self.assertLessEqual(len(data["original_request"]), 1200)
        self.assertLessEqual(len(data["recorded_tool_results"]), 4500)
        self.assertLessEqual(len(json.dumps(data["previous_checkpoint"], ensure_ascii=False)), 650)
        self.assertEqual(data["previous_checkpoint"]["decision"], "continue")
        self.assertEqual(previous["remaining"], "r" * 200)

    def test_invalid_prior_is_omitted(self):
        _, (_, payload, _) = self.review(completion(plan()), previous={"arbitrary": "data"})
        self.assertIsNone(json.loads(payload["messages"][1]["content"])["previous_checkpoint"])

    def test_unusable_responses_never_prove_completion(self):
        invalid_plan = plan()
        del invalid_plan["remaining"]
        variants = {
            "missing field": completion(invalid_plan),
            "extra field": completion(plan(unexpected="field")),
            "unknown decision": completion(plan("maybe")),
            "empty remaining": completion(plan(remaining=" ")),
            "empty next action": completion(plan(next_action="")),
            "empty reason": completion(plan(reason="")),
            "finish with action": completion(plan("finish", next_action="Do more work")),
            "wrong type": completion(plan(remaining=[])),
            "long action field": completion(plan(next_action="x" * 201)),
            "oversized reason": completion(plan(reason="x" * 801)),
            "nonobject": completion([plan()]),
            "invalid json": completion(content='{"decision": "finish"'),
            "fenced json": completion(content="```json\n" + json.dumps(plan()) + "\n```"),
            "oversized content": completion(content=" " * 1601),
            "empty content": completion(content=""),
            "nontext content": {"choices": [{"message": {"content": plan()}}]},
            "truncated": completion(plan("finish"), finish_reason="length"),
            "tools returned": completion(plan("finish"), tool_calls=[{"function": {"name": "run_command"}}]),
            "legacy call returned": completion(plan("finish"), function_call={"name": "run_command"}),
            "no choices": {"choices": []},
            "no message": {"choices": [{}]},
            "malformed message": {"choices": [{"message": "broken"}]},
            "nonresponse": None,
            "request failed": RuntimeError("model unavailable"),
            "timeout": TimeoutError("timed out"),
        }
        for label, response in variants.items():
            with self.subTest(label=label):
                result, _ = self.review(response)
                self.assertIsNone(result)

    def test_long_explanatory_reason_does_not_discard_valid_finish(self):
        result, _ = self.review(completion(plan("finish", reason="The checks are complete. " * 15)))
        self.assertEqual(result["decision"], "finish")
        self.assertLessEqual(len(result["reason"]), 200)
        self.assertEqual(result["next_action"], "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
