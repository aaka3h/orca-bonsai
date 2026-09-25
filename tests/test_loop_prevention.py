import json
import sys
from unittest.mock import patch

sys.path.insert(0, "outputs")
import orca_agent as agent


def tool_call(call_id):
    return {
        "id": call_id,
        "type": "function",
        "function": {
            "name": "run_command",
            "arguments": json.dumps({"command": "whois example.test | head -5"}),
        },
    }


requests = []
executed = []
events = []


def fake_request(path, payload, timeout=600):
    requests.append(payload)
    if len(requests) == 1:
        calls = [tool_call("one"), tool_call("two")]
    elif len(requests) in (2, 3):
        calls = [tool_call(f"repeat_{len(requests)}")]
    else:
        return {"choices": [{"message": {"content": "Found the registration facts.", "tool_calls": []}}]}
    return {"choices": [{"message": {"content": None, "tool_calls": calls}}]}


def fake_handler(args):
    executed.append(args)
    return {"exit_code": 0, "stdout": "Registrar: Example\n", "stderr": ""}


with patch.object(agent, "request_json", side_effect=fake_request), patch.object(agent, "review_progress", return_value=None), patch.dict(
    agent.DISPATCH, {"run_command": fake_handler}
):
    agent.run_task([{"role": "system", "content": agent.SYSTEM_PROMPT}], "mock", "Check example.test", 5, events.append)

assert len(executed) == 1, executed
assert len(requests) == 4, len(requests)
assert requests[-1]["tool_choice"] == "none", requests[-1]
assert events[-1]["type"] == "answer", events[-1]
assert events[-1]["text"].startswith("I stopped further actions because the same requests kept repeating without new information."), events[-1]
assert events[-1]["text"].endswith("Found the registration facts."), events[-1]
assert any("previous result was reused" in str(event) for event in events), events
assert not agent.cacheable_check("run_command", {"command": "curl -X POST https://example.test"})
print("Loop prevention checks passed")
