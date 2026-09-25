"""Regression cases for JSON API excerpts, using local fixtures only."""

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
from orca_web_content import compact_json_content, compact_tool_result


class WebContentTests(unittest.TestCase):
    def fields(self, data, limit=3000):
        text = compact_json_content(data, limit)
        self.assertLessEqual(len(text), limit)
        return json.loads(text)["fields"]

    def test_nws_points_keeps_links_before_verbose_metadata(self):
        stations = "https://api.weather.gov/gridpoints/OKX/33,35/stations"
        forecast = "https://api.weather.gov/gridpoints/OKX/33,35/forecast"
        data = {
            "@context": {"schema": "irrelevant " * 10000},
            "geometry": {"coordinates": [-74.006, 40.7128]},
            "properties": {
                "relativeLocation": {"properties": {"city": "New York", "state": "NY"}},
                "forecast": forecast, "observationStations": stations,
            },
        }
        text = compact_json_content(data, 900)
        fields = json.loads(text)["fields"]
        self.assertEqual(fields["/properties/observationStations"], stations)
        self.assertEqual(fields["/properties/forecast"], forecast)
        self.assertIn("New York", text)
        self.assertNotIn("schema", text)
        self.assertNotIn("coordinates", text)

    def test_stations_collection_preserves_identifier_and_station_url(self):
        data = {"features": [
            {"id": "https://api.weather.gov/stations/KNYC",
             "geometry": {"coordinates": [-73.966, 40.779]},
             "properties": {"stationIdentifier": "KNYC", "name": "Central Park"}},
        ]}
        fields = self.fields(data)
        self.assertEqual(fields["/features/0/properties/stationIdentifier"], "KNYC")
        self.assertEqual(fields["/features/0/id"], "https://api.weather.gov/stations/KNYC")

    def test_observation_keeps_timestamp_value_units_and_nulls(self):
        fields = self.fields({"properties": {
            "timestamp": "2026-09-23T00:00:00+00:00", "textDescription": "Clear",
            "temperature": {"unitCode": "wmoUnit:degC", "value": 21.1, "qualityControl": "V"},
            "windSpeed": {"unitCode": "wmoUnit:km_h-1", "value": None},
        }})
        self.assertEqual(fields["/properties/temperature/value"], 21.1)
        self.assertEqual(fields["/properties/temperature/unitCode"], "wmoUnit:degC")
        self.assertIsNone(fields["/properties/windSpeed/value"])
        self.assertEqual(fields["/properties/timestamp"], "2026-09-23T00:00:00+00:00")

    def test_generic_api_next_links_and_data(self):
        fields = self.fields({"items": [{"name": "Example", "price": 12.3}],
                              "links": {"next": "/api/items?page=2"}})
        self.assertEqual(next(iter(fields)), "/links/next")
        self.assertEqual(fields["/links/next"], "/api/items?page=2")
        self.assertEqual(fields["/items/0/price"], 12.3)

    def test_never_emits_partial_url(self):
        large_url = "https://example.com/" + "x" * 2000
        text = compact_json_content({"url": large_url, "name": "Short fact"}, 150)
        self.assertLessEqual(len(text), 150)
        self.assertNotIn("https://example.com", text)
        self.assertEqual(json.loads(text)["fields"]["/name"], "Short fact")

    def test_output_remains_valid_and_bounded(self):
        data = {"name": 'Quoted " text ☀' * 500, "next": "https://example.com/next"}
        for limit in (0, 1, 2, 25, 60, 120, 3000):
            text = compact_json_content(data, limit)
            self.assertLessEqual(len(text), limit)
            if text:
                json.loads(text)

    def test_work_is_bounded_for_deep_wide_and_cyclic_values(self):
        deep = {}; cursor = deep
        for _ in range(1000):
            cursor["child"] = {}; cursor = cursor["child"]
        cyclic = {}; cyclic["self"] = cyclic
        for data in (deep, cyclic, list(range(100000)), {str(i): i for i in range(10000)}):
            text = compact_json_content(data, 400)
            self.assertLessEqual(len(text), 400)
            self.assertTrue(json.loads(text)["truncated"])

    def test_pointer_names_escape_slashes_and_tildes(self):
        fields = self.fields({"a/b": {"~key": "value"}})
        self.assertEqual(fields["/a~1b/~0key"], "value")

    def test_tool_json_preserves_endpoint_under_history_and_evidence_budgets(self):
        stations = "https://api.weather.gov/gridpoints/OKX/33,35/stations"
        data = {"@context": "ignored " * 1000, "properties": {
            "observationStations": stations, "city": "New York",
            "forecast": "https://api.weather.gov/gridpoints/OKX/33,35/forecast",
        }}
        for body in (json.dumps(data), compact_json_content(data)):
            result = {"url": "https://api.weather.gov/points/40.7128,-74.0060", "status": 200,
                      "content_type": "application/geo+json", "text": body, "note": "Previous response reused."}
            for limit in (1000, 1700):
                text = compact_tool_result(result, limit)
                self.assertLessEqual(len(text), limit)
                output = json.loads(text)
                self.assertEqual(output["data"]["/properties/observationStations"], stations)
                self.assertEqual(output["data"]["/properties/city"], "New York")
                self.assertEqual(output["url"], result["url"])
                self.assertEqual(output["status"], 200)
                self.assertEqual(output["note"], result["note"])

    def test_tool_observation_preserves_numbers_and_units(self):
        result = {"status": 200, "url": "https://api.weather.gov/stations/KNYC/observations/latest",
                  "content_type": "application/geo+json", "text": json.dumps({"properties": {
                      "timestamp": "2026-09-23T00:00:00Z", "temperature": {"value": 21.1, "unitCode": "wmoUnit:degC"},
                      "textDescription": "Clear", "windSpeed": {"value": None, "unitCode": "wmoUnit:km_h-1"},
                  }})}
        output = json.loads(compact_tool_result(result, 1000))
        self.assertEqual(output["data"]["/properties/temperature/value"], 21.1)
        self.assertEqual(output["data"]["/properties/temperature/unitCode"], "wmoUnit:degC")
        self.assertEqual(output["data"]["/properties/timestamp"], "2026-09-23T00:00:00Z")

    def test_measurements_survive_many_metadata_links(self):
        data = {"properties": {
            "links": [{"href": f"https://example.com/station/{i}"} for i in range(24)],
            "timestamp": "2026-09-23T00:00:00Z", "temperature": {"value": 21.1, "unitCode": "wmoUnit:degC"},
        }}
        result = {"status": 200, "content_type": "application/json", "text": json.dumps(data)}
        output = json.loads(compact_tool_result(result, 500))
        self.assertEqual(output["data"]["/properties/temperature/value"], 21.1)
        self.assertEqual(output["data"]["/properties/temperature/unitCode"], "wmoUnit:degC")
        self.assertEqual(output["data"]["/properties/timestamp"], "2026-09-23T00:00:00Z")

    def test_tool_repeated_compaction_preserves_json_and_html(self):
        result = {"status": 200, "url": "https://example.com/api", "content_type": "application/json",
                  "text": json.dumps({"temperature": {"value": 21.1, "unitCode": "wmoUnit:degC"},
                                      "next": "https://example.com/next"}), "note": "Previous response reused."}
        html = {"status": 200, "url": "https://example.com", "title": "Example", "text": "Page text " * 1000,
                "links": [{"url": "https://example.com/details", "text": "Details"}]}
        for original in (result, html):
            compact = compact_tool_result(original, 1000)
            self.assertEqual(compact_tool_result(json.loads(compact), 1000), compact)

    def test_tool_html_balances_text_and_three_full_links(self):
        links = [{"url": f"https://example.com/data/{i}", "text": f"Observation {i}"} for i in range(10)]
        result = {"url": "https://example.com", "status": 200, "title": "Weather",
                  "text": "Current conditions are unavailable. " * 300, "links": links}
        for limit in (1000, 1700):
            text = compact_tool_result(result, limit)
            self.assertLessEqual(len(text), limit)
            output = json.loads(text)
            self.assertEqual([item["url"] for item in output["links"]], [item["url"] for item in links[:3]])
            self.assertIn("Current conditions are unavailable.", output["text"])
            self.assertGreater(len(output["text"]), 200)

    def test_tool_result_all_budgets_remain_valid_and_never_break_urls(self):
        target = "https://example.com/" + "q" * 1000
        result = {"url": target, "status": 200, "text": 'Text " \\ ' * 1000,
                  "links": [{"url": target}], "note": "Previous response reused." * 1000}
        for limit in (0, 1, 2, 25, 60, 120, 1000, 1700):
            text = compact_tool_result(result, limit)
            self.assertLessEqual(len(text), limit)
            self.assertNotIn("https://example.com", text)
            if text:
                json.loads(text)


if __name__ == "__main__":
    unittest.main()
