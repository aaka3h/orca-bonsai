import io
import json
import sys
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, "outputs")
import orca_agent as agent


def run_recovery_case():
    requests = []
    executed = []
    events = []

    def fake_request(path, payload, timeout=600):
        requests.append(payload)
        if len(requests) == 1:
            raise agent.ToolCallParseError("The model produced an incomplete tool command.")
        if len(requests) == 2:
            return {
                "choices": [{
                    "message": {
                        "content": None,
                        "tool_calls": [{
                            "id": "call_test",
                            "type": "function",
                            "function": {"name": "run_command", "arguments": '{"command":"safe-check"}'},
                        }],
                    }
                }]
            }
        return {"choices": [{"message": {"content": "Done.", "tool_calls": []}}]}

    def safe_handler(args):
        executed.append(args)
        return {"exit_code": 0, "stdout": "ok", "stderr": ""}

    history = [{"role": "system", "content": agent.SYSTEM_PROMPT}]
    with patch.object(agent, "request_json", side_effect=fake_request), patch.dict(agent.DISPATCH, {"run_command": safe_handler}):
        agent.run_task(history, "mock", "Check something", 3, events.append)
    assert len(executed) == 1, executed
    assert len(requests) == 3, len(requests)
    assert any("invalid JSON" in item.get("content", "") for item in requests[1]["messages"])
    assert len(history) == 5, history
    assert events[-1] == {"type": "answer", "text": "Done."}, events


def run_invalid_arguments_case():
    requests = []
    executed = []

    def fake_request(path, payload, timeout=600):
        requests.append(payload)
        if len(requests) == 1:
            return {
                "choices": [{
                    "message": {
                        "content": None,
                        "tool_calls": [{
                            "id": "call_bad",
                            "type": "function",
                            "function": {"name": "run_command", "arguments": '{"command":"unfinished'},
                        }],
                    }
                }]
            }
        return {"choices": [{"message": {"content": "Could not run that command.", "tool_calls": []}}]}

    history = [{"role": "system", "content": agent.SYSTEM_PROMPT}]
    with patch.object(agent, "request_json", side_effect=fake_request), patch.dict(agent.DISPATCH, {"run_command": lambda args: executed.append(args)}):
        agent.run_task(history, "mock", "Check something", 2)
    assert not executed, executed
    assert json.loads(history[2]["tool_calls"][0]["function"]["arguments"]) == {}
    assert "Invalid tool arguments" in history[3]["content"]


def run_http_classification_case():
    body = b'{"error":{"code":500,"message":"Failed to parse tool call arguments as JSON: missing closing quote"}}'
    error = HTTPError("http://localhost", 500, "Internal Server Error", {}, io.BytesIO(body))
    with patch.object(agent.urllib.request, "urlopen", side_effect=error):
        try:
            agent.request_json("/chat/completions", {})
        except agent.ToolCallParseError:
            pass
        else:
            raise AssertionError("Expected ToolCallParseError")


def run_bounded_failure_case():
    calls = []

    def always_invalid(path, payload, timeout=600):
        calls.append(payload)
        raise agent.ToolCallParseError("The model produced an incomplete tool command.")

    with patch.object(agent, "request_json", side_effect=always_invalid):
        try:
            agent.run_task([{"role": "system", "content": agent.SYSTEM_PROMPT}], "mock", "Check something", 4)
        except RuntimeError as exc:
            assert "three attempts" in str(exc), str(exc)
        else:
            raise AssertionError("Expected bounded failure")
    assert len(calls) == 3, len(calls)


run_recovery_case()
run_invalid_arguments_case()
run_http_classification_case()
run_bounded_failure_case()
print("Tool-call recovery checks passed")
