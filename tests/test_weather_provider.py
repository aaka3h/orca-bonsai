import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_weather as weather


NOW = 1790123400  # 2026-09-23 00:30 UTC; NYC 20:30 on the previous day.
PLACE = {"name": "New York", "admin1": "New York", "country": "United States",
         "country_code": "US", "latitude": 40.71427, "longitude": -74.00597}
CURRENT = {
    "timezone": "America/New_York",
    "current_units": {"time": "unixtime", "temperature_2m": "°C", "apparent_temperature": "°C",
                      "relative_humidity_2m": "%", "weather_code": "wmo code", "wind_speed_10m": "km/h"},
    "current": {"time": NOW - 300, "temperature_2m": 20, "apparent_temperature": 19,
                "relative_humidity_2m": 60, "weather_code": 2, "wind_speed_10m": 10},
}


class Response:
    def __init__(self, data=None, status=200, raw=None):
        self.body = raw if raw is not None else json.dumps(data).encode()
        self.status_code = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_content(self, chunk_size):
        for pos in range(0, len(self.body), chunk_size):
            yield self.body[pos:pos + chunk_size]


class WeatherTests(unittest.TestCase):
    def run_weather(self, location="NYC", country_code=None, places=None, current=None):
        geodata = {"results": [PLACE]} if places is None else places
        forecast = copy.deepcopy(CURRENT if current is None else current)
        with patch.object(weather.requests, "get", side_effect=[Response(geodata), Response(forecast)]) as get:
            with patch.object(weather.time, "time", return_value=NOW):
                result = weather.get_weather(location, country_code)
        return result, get

    def test_nyc_resolves_and_returns_fresh_model_values_in_both_units(self):
        result, get = self.run_weather()
        self.assertNotIn("error", result)
        self.assertEqual(get.call_args_list[0].kwargs["params"]["name"], "New York")
        self.assertEqual(get.call_args_list[0].kwargs["params"]["countryCode"], "US")
        self.assertEqual(result["temperature_f"], 68)
        self.assertEqual(result["feels_like_f"], 66.2)
        self.assertEqual(result["condition"], "Partly cloudy")
        self.assertEqual(result["wind_kph"], 10)
        self.assertTrue(result["fresh"])
        self.assertEqual(result["valid_time"], "2026-09-22T20:25-04:00")
        self.assertIn("modeled estimate", result["source_kind"])
        self.assertTrue(result["source_url"].startswith(weather._WEATHER + "?"))
        self.assertLess(len(json.dumps(result)), 1500)
        for call in get.call_args_list:
            self.assertFalse(call.kwargs["allow_redirects"])
            self.assertEqual(call.kwargs["timeout"], (5, 12))
        self.assertEqual(get.call_count, 2)

    def test_qualified_location_and_country_filter_are_preserved(self):
        for location in ["New York, NY, US", "New York, NY, United States"]:
            with self.subTest(location=location):
                result, get = self.run_weather(location, "us")
                self.assertNotIn("error", result)
                self.assertEqual(get.call_args_list[0].kwargs["params"]["name"], "New York, NY")
                self.assertEqual(get.call_args_list[0].kwargs["params"]["countryCode"], "US")
        _, get = self.run_weather("New York, NY")
        self.assertEqual(get.call_args_list[0].kwargs["params"]["name"], "New York, NY")

    def test_invalid_input_stops_before_network(self):
        for location, country in [(None, None), ("", None), ("x", None), ("x\ny", None),
                                  ("a" * 181, None), ("http://example.org", None),
                                  ("NYC", "ZZ"), ("NYC", "USA"), ("NYC", 3),
                                  ("NYC", "IN"), ("New York, NY, US", "IN"),
                                  ("New York, NY, Nowhere", None), ("New York,", None)]:
            with self.subTest(location=location, country=country):
                with patch.object(weather.requests, "get") as get:
                    result = weather.get_weather(location, country)
                self.assertIn("error", result)
                get.assert_not_called()

    def test_no_results_and_wrong_country_are_errors(self):
        for places in [{}, {"results": []}, {"results": None}, {"results": [None]},
                       {"results": [dict(PLACE, country_code="IN")]}]:
            with self.subTest(places=places):
                result, get = self.run_weather(places=places)
                self.assertIn("error", result)
                self.assertEqual(get.call_count, 1)

    def test_invalid_coordinates_and_missing_location_identity(self):
        for update in [{"latitude": 200}, {"longitude": None}, {"name": None},
                       {"country_code": "ZZ"}, {"latitude": float("nan")}]:
            with self.subTest(update=update):
                result, get = self.run_weather(places={"results": [dict(PLACE, **update)]})
                self.assertIn("error", result)
                self.assertEqual(get.call_count, 1)

    def test_multiple_matches_disclose_resolution(self):
        result, _ = self.run_weather("New York", places={"results": [PLACE, dict(PLACE, name="New York Mills")]})
        self.assertEqual(result["location"]["name"], "New York")
        self.assertIn("First matching location", result["location_note"])

    def test_null_optional_fields_omitted_unknown_condition_explicit(self):
        data = copy.deepcopy(CURRENT)
        for field in ["apparent_temperature", "relative_humidity_2m", "wind_speed_10m", "weather_code"]:
            data["current"][field] = None
        result, _ = self.run_weather(current=data)
        self.assertNotIn("error", result)
        for key in ["feels_like_c", "feels_like_f", "wind_kph", "humidity_percent", "weather_code"]:
            self.assertNotIn(key, result)
        self.assertIn("Unknown", result["condition"])
        data["current"]["weather_code"] = 12345
        result, _ = self.run_weather(current=data)
        self.assertIn("Unknown", result["condition"])

    def test_stale_or_future_data_never_published_as_current(self):
        for age in [10801, -3601]:
            with self.subTest(age=age):
                data = copy.deepcopy(CURRENT)
                data["current"]["time"] = NOW - age
                result, _ = self.run_weather(current=data)
                self.assertIn("error", result)
                self.assertFalse(result["fresh"])
                self.assertNotIn("temperature_c", result)
                self.assertIn("valid_time", result)

    def test_missing_temperature_or_time_fails(self):
        for field in ["temperature_2m", "time"]:
            for invalid in [None, "", float("nan"), True]:
                with self.subTest(field=field, invalid=invalid):
                    data = copy.deepcopy(CURRENT)
                    data["current"][field] = invalid
                    result, _ = self.run_weather(current=data)
                    self.assertIn("error", result)
                    self.assertNotIn("temperature_c", result)

    def test_invalid_timezone_or_units_are_errors(self):
        for tz in [None, "", "No/SuchZone"]:
            with self.subTest(tz=tz):
                data = copy.deepcopy(CURRENT)
                data["timezone"] = tz
                self.assertIn("error", self.run_weather(current=data)[0])
        for field in ["temperature_2m", "time", "wind_speed_10m", "apparent_temperature", "relative_humidity_2m"]:
            with self.subTest(field=field):
                data = copy.deepcopy(CURRENT)
                data["current_units"][field] = "wrong"
                self.assertIn("error", self.run_weather(current=data)[0])

    def test_provider_transport_and_parse_errors(self):
        for response in [Response({}, status=429), Response({}, status=302), Response(raw=b"not JSON"),
                         Response([]), Response({"error": True, "reason": "Unavailable"}),
                         Response(raw=b" " * 262145)]:
            with self.subTest(response=response):
                with patch.object(weather.requests, "get", return_value=response):
                    self.assertIn("error", weather.get_weather("NYC"))
        with patch.object(weather.requests, "get", side_effect=requests.Timeout):
            self.assertIn("Timeout", weather.get_weather("NYC")["error"])

    def test_missing_current_shape_fails(self):
        for data in [{}, {"current": []}, {"current": {"temperature_2m": 20}, "current_units": None}]:
            with self.subTest(data=data):
                self.assertIn("error", self.run_weather(current=data)[0])


if __name__ == "__main__":
    unittest.main()
