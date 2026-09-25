"""Exercise weather routing, preserved API links and bounded loop recovery."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_agent as agent
from orca_task_evidence import TaskEvidence


def completion(name=None, args=None, text=None):
    calls = [] if not name else [{
        "id": "call", "type": "function",
        "function": {"name": name, "arguments": json.dumps(args)},
    }]
    return {"choices": [{"message": {"content": text, "tool_calls": calls}, "finish_reason": "stop"}]}


CONTINUE = {"decision": "continue", "remaining": "Current conditions are missing.",
            "next_action": "Use get_weather for NYC.", "reason": "Only metadata was returned."}
POINTS = {
    "@context": ["https://example.test/context" + str(i) for i in range(100)],
    "geometry": {"coordinates": [-74.0, 40.7]},
    "properties": {
        "observationStations": "https://api.weather.gov/gridpoints/OKX/33,35/stations",
        "forecast": "https://api.weather.gov/gridpoints/OKX/33,35/forecast",
        "timeZone": "America/New_York",
    },
}


class Response:
    def __init__(self, data, url):
        self.status_code, self.url, self.encoding = 200, url, "utf-8"
        self.headers = {"Content-Type": "application/geo+json"}
        self.data = data
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def iter_content(self, **kwargs):
        yield json.dumps(self.data).encode()


class WeatherFlowTests(unittest.TestCase):
    def run_agent(self, responses, decisions, handlers):
        requests, events, calls = [], [], []
        def request(path, payload, **kwargs):
            requests.append(copy.deepcopy(payload))
            return responses.pop(0)
        def wrapped(name, handler):
            def perform(args):
                calls.append((name, args))
                return handler(args)
            return perform
        with patch.object(agent, "request_json", side_effect=request), \
             patch.object(agent, "review_progress", side_effect=decisions), \
             patch.dict(agent.DISPATCH, {name: wrapped(name, handler) for name, handler in handlers.items()}):
            agent.run_task([{"role": "system", "content": agent.SYSTEM_PROMPT}],
                           "model", "what is weather in NYC", 12, events.append)
        return requests, events, calls

    def test_points_links_survive_fetch_history_and_evidence(self):
        url = "https://api.weather.gov/points/40.7,-74.0"
        with patch("requests.get", return_value=Response(POINTS, url)):
            result = agent.tool_fetch_url({"url": url})
        self.assertNotIn("error", result)
        self.assertNotIn("@context", result["text"])
        history = [{"role": "system", "content": "System"},
                   {"role": "user", "content": "Find current weather"},
                   {"role": "tool", "name": "fetch_url", "content": json.dumps(result)}]
        # Make a long response that requires history compaction.
        result["text"] = agent.compact_json_content({**POINTS, "description": "Unhelpful prose " * 200})
        history[-1]["content"] = json.dumps(result)
        agent.shorten_history(history, char_limit=100)
        compact = json.loads(history[-1]["content"])
        self.assertLessEqual(len(history[-1]["content"]), 1000)
        self.assertIn(POINTS["properties"]["observationStations"], json.dumps(compact))
        evidence = TaskEvidence()
        evidence.add("fetch_url", {"url": url}, result)
        self.assertIn(POINTS["properties"]["observationStations"], evidence.render(4500))

    def test_follow_points_stations_and_observation_without_losing_link(self):
        point_url = "https://api.weather.gov/points/40.7,-74.0"
        station_url = POINTS["properties"]["observationStations"]
        latest_url = "https://api.weather.gov/stations/KNYC/observations/latest"
        responses = {
            point_url: POINTS,
            station_url: {"features": [{"properties": {"stationIdentifier": "KNYC", "name": "Central Park"}}]},
            latest_url: {"properties": {"timestamp": "2026-09-23T00:00:00Z", "textDescription": "Clear",
                                       "temperature": {"unitCode": "wmoUnit:degC", "value": 20}}},
        }
        def provider(url, **kwargs):
            return Response(responses[url], url)
        with patch("requests.get", side_effect=provider):
            requests, events, calls = self.run_agent([
                *[completion("fetch_url", {"url": url}) for url in responses],
                completion(text="Central Park: 20°C, clear, valid at 00:00 UTC."),
            ], [{"decision": "finish", "remaining": "", "next_action": "", "reason": "Timestamped temperature obtained."}],
                {"fetch_url": agent.tool_fetch_url})
        self.assertEqual(len(calls), 3)
        self.assertIn("20", json.dumps(requests[-1]))
        self.assertIn("20°C", events[-1]["text"])

    def test_recovery_can_use_new_tool_after_repeated_metadata(self):
        repeated = lambda: completion("fetch_url", {"url": "https://example.test/metadata"})
        requests, events, calls = self.run_agent([
            repeated(), repeated(), repeated(), completion("get_weather", {"location": "NYC"}),
            completion(text="New York: 20°C, model estimate at the reported time."),
        ], [CONTINUE, CONTINUE], {
            "fetch_url": lambda args: {"url": args["url"], "status": 200, "text": "Location metadata only"},
            "get_weather": lambda args: {"location": "New York, US", "temperature_c": 20, "valid_at": "2026-09-23T00:00:00Z"},
        })
        self.assertEqual([name for name, args in calls], ["fetch_url", "get_weather"])
        self.assertEqual(sum(event.get("cached", False) for event in events), 2)
        notes = [event["result"]["note"] for event in events if event.get("cached")]
        self.assertTrue(all("Summarize" not in note and "already succeeded" not in note for note in notes))
        self.assertIn("get_weather", json.dumps(requests[3]["messages"]))
        self.assertEqual(requests[-1]["tool_choice"], "auto")

    def test_recovery_still_stops_a_persistent_loop(self):
        responses = [completion("fetch_url", {"url": "https://example.test/metadata"}) for i in range(4)]
        responses.append(completion(text="No current weather was obtained."))
        requests, events, calls = self.run_agent(responses, [CONTINUE, CONTINUE], {
            "fetch_url": lambda args: {"url": args["url"], "status": 200, "text": "Location metadata only"},
        })
        self.assertEqual(len(calls), 1)
        self.assertEqual(requests[-1]["tool_choice"], "none")
        self.assertIn("without new information", events[-1]["text"])
        self.assertEqual(sum(event.get("cached", False) for event in events), 3)

    def test_weather_evidence_retains_units_and_field_names(self):
        evidence = TaskEvidence()
        evidence.add("get_weather", {"location": "NYC"}, {
            "temperature_c": 20, "temperature_f": 68, "humidity_percent": 55,
            "valid_time": "2026-09-23T00:00:00Z", "source_kind": "modeled estimate",
        })
        rendered = evidence.render(4500)
        self.assertIn("temperature_c: 20", rendered)
        self.assertIn("temperature_f: 68", rendered)
        self.assertIn("humidity_percent: 55", rendered)

    def test_weather_source_link_and_values_survive_history_compaction(self):
        source = "https://api.open-meteo.com/v1/forecast?latitude=40.71&longitude=-74.0&current=temperature_2m,weather_code"
        result = {"temperature_c": 20, "temperature_f": 68, "condition": "Clear", "source_url": source,
                  "valid_time": "2026-09-23T00:00:00Z", "source_kind": "modeled estimate",
                  "location_note": "Long note " * 150}
        history = [{"role": "system", "content": "System"}, {"role": "user", "content": "Weather?"},
                   {"role": "tool", "name": "get_weather", "content": json.dumps(result)}]
        agent.shorten_history(history, char_limit=100)
        compact = json.loads(history[-1]["content"])
        self.assertLessEqual(len(history[-1]["content"]), 1000)
        self.assertIn(source, json.dumps(compact))
        self.assertEqual(compact["fields"]["/temperature_c"], 20)
        self.assertEqual(compact["fields"]["/source_kind"], "modeled estimate")


if __name__ == "__main__":
    unittest.main(verbosity=2)
