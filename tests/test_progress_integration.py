"""Exercise task checkpoints with fake completions and in-memory tool results.

No commands, files, model requests, or network checks execute in these tests.
"""

import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_agent as agent


def completion(content=None, calls=None):
    return {"choices": [{"message": {"content": content, "tool_calls": calls or []}, "finish_reason": "stop"}]}


def call(command, call_id="check"):
    return {
        "id": call_id, "type": "function",
        "function": {"name": "run_command", "arguments": json.dumps({"command": command})},
    }


def plan(decision, next_action="", remaining="", reason="Evidence reviewed."):
    return {"decision": decision, "next_action": next_action, "remaining": remaining, "reason": reason}


class ProgressIntegrationTests(unittest.TestCase):
    def run_task(self, responses, decisions, *, task="Inspect the local report and read it back before answering.",
                 max_steps=12, history=None, results=None):
        requests, reviews, executed, events = [], [], [], []
        responses = iter(responses)
        decisions = iter(decisions)
        results = iter(results) if results is not None else None
        history = history if history is not None else [{"role": "system", "content": agent.SYSTEM_PROMPT}]

        def request(path, payload, timeout=600):
            requests.append({"path": path, "payload": copy.deepcopy(payload), "timeout": timeout})
            return copy.deepcopy(next(responses))

        def review(**kwargs):
            reviews.append({key: copy.deepcopy(value) for key, value in kwargs.items() if key != "request_json"})
            self.assertTrue(callable(kwargs["request_json"]))
            return copy.deepcopy(next(decisions))

        def handler(args):
            executed.append(copy.deepcopy(args))
            return next(results) if results is not None else {"exit_code": 0, "stdout": "Observed " + args["command"]}

        with patch.object(agent, "request_json", side_effect=request), patch.object(agent, "review_progress", side_effect=review), patch.dict(agent.DISPATCH, {"run_command": handler}):
            agent.run_task(history, "test-model", task, max_steps, events.append)
        return requests, reviews, executed, events, history

    def test_checkpoint_continues_to_readback_then_finishes_without_extra_actions(self):
        commands = ["dig report.test", "whois report.test", "curl https://report.test"]
        next_step = "Read the saved report once and summarize the observed contents."
        continuing = plan("continue", next_step, "The report readback is still missing.")
        finishing = plan("finish", reason="The report contents have now been observed.")
        responses = [completion(calls=[call(command, str(i))]) for i, command in enumerate(commands)]
        responses += [
            completion(calls=[call("cat /tmp/report.txt", "readback")]),
            completion(calls=[call(commands[0], "repeated-check")]),
            completion("Report contents and limits summarized."),
        ]
        first_result = {"exit_code": 0, "stdout": "EARLY_EVIDENCE_SENTINEL\n" + "Verbose material\n" * 300}
        results = [first_result,
                   {"exit_code": 0, "stdout": "Registration observation"},
                   {"exit_code": 0, "stdout": "Web observation"},
                   {"exit_code": 0, "stdout": "READBACK_EVIDENCE_SENTINEL"}]
        requests, reviews, executed, events, history = self.run_task(responses, [continuing, finishing], results=results)

        self.assertEqual([args["command"] for args in executed], commands + ["cat /tmp/report.txt"])
        self.assertEqual(len(requests), 6)
        self.assertEqual(len(reviews), 2)
        self.assertIsNone(reviews[0]["previous_plan"])
        self.assertEqual(reviews[1]["previous_plan"], continuing)
        for review in reviews:
            self.assertEqual(review["model"], "test-model")
            self.assertEqual(review["task"], "Inspect the local report and read it back before answering.")
            self.assertIn("EARLY_EVIDENCE_SENTINEL", review["evidence_text"])
            self.assertLessEqual(len(review["evidence_text"]), 4500)
        self.assertIn("READBACK_EVIDENCE_SENTINEL", reviews[-1]["evidence_text"])
        self.assertIn(next_step, json.dumps(requests[3]["payload"]["messages"]))
        self.assertNotIn(next_step, json.dumps(history))
        self.assertEqual(requests[-1]["payload"]["tools"], [])
        self.assertEqual(requests[-1]["payload"]["tool_choice"], "none")
        self.assertEqual(sum(event.get("cached", False) for event in events), 1)
        answers = [event["text"] for event in events if event["type"] == "answer"]
        self.assertEqual(len(answers), 1)
        self.assertIn("Report contents and limits summarized.", answers[0])

    def test_finish_at_first_checkpoint_never_requests_another_action(self):
        commands = ["dig one.test", "dig two.test", "dig three.test"]
        requests, reviews, executed, events, _ = self.run_task(
            [*[completion(calls=[call(command, str(i))]) for i, command in enumerate(commands)], completion("Finished from observations.")],
            [plan("finish", reason="Enough observations to answer the request.")],
        )
        self.assertEqual(len(executed), 3)
        self.assertEqual(len(reviews), 1)
        self.assertEqual(len(requests), 4)
        self.assertEqual(requests[-1]["payload"]["tool_choice"], "none")
        self.assertEqual(len([event for event in events if event["type"] == "answer"]), 1)

    def test_knowledge_answer_uses_one_request_and_no_checkpoint(self):
        requests, reviews, executed, events, _ = self.run_task(
            [completion("A concise answer from model knowledge.")], [], task="Explain what a text file is.",
        )
        self.assertEqual(len(requests), 1)
        self.assertEqual(reviews, [])
        self.assertEqual(executed, [])
        self.assertEqual(events[-1], {"type": "answer", "text": "A concise answer from model knowledge."})

    def test_plan_is_reset_for_the_next_task(self):
        history = [{"role": "system", "content": agent.SYSTEM_PROMPT}]
        first_plan = plan("continue", "FIRST_TASK_PLAN_SENTINEL", "FIRST_TASK_REMAINING_SENTINEL")
        first_responses = [completion(calls=[call(f"dig first{i}.test", str(i))]) for i in range(3)]
        first_responses.append(completion("First task answered."))
        first = self.run_task(first_responses, [first_plan], history=history, task="First task")
        self.assertEqual(len(first[1]), 1)
        second_responses = [completion(calls=[call(f"dig second{i}.test", str(i))]) for i in range(3)]
        second_responses.append(completion("Second task answered."))
        second = self.run_task(second_responses, [plan("finish")], history=history, task="Second task")
        requests, reviews, executed, _, _ = second
        self.assertEqual(len(executed), 3)
        self.assertEqual(len(reviews), 1)
        self.assertIsNone(reviews[0]["previous_plan"])
        self.assertEqual(reviews[0]["task"], "Second task")
        self.assertNotIn("first0.test", reviews[0]["evidence_text"])
        self.assertNotIn("FIRST_TASK_PLAN_SENTINEL", json.dumps(requests))
        self.assertNotIn("FIRST_TASK_REMAINING_SENTINEL", json.dumps(requests))

    def test_invalid_checkpoint_keeps_the_existing_bounded_flow(self):
        responses = [completion(calls=[call(f"dig item{i}.test", str(i))]) for i in range(4)]
        responses.append(completion("Partial findings at the work limit."))
        requests, reviews, executed, events, _ = self.run_task(responses, [None], max_steps=4)
        self.assertEqual(len(executed), 4)
        self.assertEqual(len(reviews), 1)
        self.assertEqual(len(requests), 5)
        self.assertEqual(requests[-1]["payload"]["tool_choice"], "none")
        self.assertIn("4-step work limit", events[-1]["text"])

    def test_partial_failure_can_retry_before_success_is_reused(self):
        command = "nmap --script ssh-hostkey example.test | tail -40"
        responses = [completion(calls=[call(command, str(i))]) for i in range(3)]
        responses.append(completion("The retry succeeded."))
        results = [
            {"exit_code": 0, "stdout": "22/tcp open ssh\n|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)"},
            {"exit_code": 0, "stdout": "22/tcp open ssh\n|_ssh-hostkey: PUBLIC_HOST_KEY_OBSERVATION"},
        ]
        requests, reviews, executed, events, _ = self.run_task(
            responses, [plan("finish")], results=results,
        )
        self.assertEqual([args["command"] for args in executed], [command, command])
        outcomes = [event for event in events if event["type"] == "tool_result"]
        self.assertEqual([outcome["cached"] for outcome in outcomes], [False, False, True])
        self.assertIn("PUBLIC_HOST_KEY_OBSERVATION", outcomes[-1]["result"]["stdout"])
        self.assertNotIn("ERROR", outcomes[-1]["result"]["stdout"])
        self.assertEqual(len(requests), 4)
        self.assertEqual(len(reviews), 1)
        self.assertIn("partial failure (exit 0)", reviews[0]["evidence_text"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
