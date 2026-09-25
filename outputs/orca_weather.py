"""Current modeled weather from Open-Meteo's public, structured API.

Docs: https://open-meteo.com/en/docs and /en/docs/geocoding-api.
This reports weather model estimates, not weather-station observations.
"""

from __future__ import annotations

import json
import math
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import requests


_GEOCODING = "https://geocoding-api.open-meteo.com/v1/search"
_WEATHER = "https://api.open-meteo.com/v1/forecast"
_COUNTRIES = set("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split())
_COUNTRY_NAMES = {
    "usa": "US", "united states": "US", "united states of america": "US",
    "uk": "GB", "united kingdom": "GB", "great britain": "GB",
    "india": "IN", "canada": "CA", "australia": "AU", "france": "FR",
    "germany": "DE", "japan": "JP", "china": "CN", "pakistan": "PK",
    "bangladesh": "BD", "nepal": "NP", "singapore": "SG",
}
_CONDITIONS = {
    0: "Clear sky", 1: "Mainly clear", 2: "Partly cloudy", 3: "Overcast",
    45: "Fog", 48: "Depositing rime fog", 51: "Light drizzle",
    53: "Moderate drizzle", 55: "Dense drizzle", 56: "Light freezing drizzle",
    57: "Dense freezing drizzle", 61: "Slight rain", 63: "Moderate rain",
    65: "Heavy rain", 66: "Light freezing rain", 67: "Heavy freezing rain",
    71: "Slight snowfall", 73: "Moderate snowfall", 75: "Heavy snowfall",
    77: "Snow grains", 80: "Slight rain showers", 81: "Moderate rain showers",
    82: "Violent rain showers", 85: "Slight snow showers", 86: "Heavy snow showers",
    95: "Slight or moderate thunderstorm", 96: "Thunderstorm with slight hail",
    99: "Thunderstorm with heavy hail",
}


class _WeatherError(Exception):
    pass


def _number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def _query(location, country_code):
    if not isinstance(location, str) or not 2 <= len(location.strip()) <= 180 or any(ord(c) < 32 for c in location):
        raise _WeatherError("Provide a city or postal code, optionally followed by a state or country.")
    location = " ".join(location.split())
    if "://" in location:
        raise _WeatherError("Location must be a city or postal code, not a URL.")
    if country_code is not None:
        if not isinstance(country_code, str) or country_code.strip().upper() not in _COUNTRIES:
            raise _WeatherError("country_code must be an ISO two-letter country code, such as US or IN.")
        country_code = country_code.strip().upper()
    parts = [part.strip() for part in location.split(",")]
    if any(not part for part in parts) or len(parts) > 3:
        raise _WeatherError("Use city, state, country or city with an explicit country_code.")
    if parts[0].casefold() in {"nyc", "new york city"}:
        if country_code and country_code != "US":
            raise _WeatherError("NYC means New York City, US; the supplied country_code conflicts.")
        parts[0], country_code = "New York", "US"
    # The API supports one country/admin1 qualifier. Never drop a third qualifier:
    # turn it into the API's separate, unambiguous countryCode filter.
    if len(parts) == 3:
        last = parts.pop()
        inferred = last.upper() if last.upper() in _COUNTRIES else _COUNTRY_NAMES.get(last.casefold())
        if not inferred:
            raise _WeatherError("For city, state, country, use a two-letter country code as the last part.")
        if country_code and country_code != inferred:
            raise _WeatherError("The country in location conflicts with country_code.")
        country_code = inferred
    return ", ".join(parts), country_code


def _get_json(url, params):
    if url not in {_GEOCODING, _WEATHER}:
        raise _WeatherError("Unsupported weather endpoint.")
    source_url = requests.Request("GET", url, params=params).prepare().url
    try:
        with requests.get(url, params=params, timeout=(5, 12), allow_redirects=False, stream=True,
                          headers={"Accept": "application/json", "User-Agent": "OrcaBonsai/1.0"}) as response:
            if response.status_code != 200:
                raise _WeatherError(f"Open-Meteo returned HTTP {response.status_code}.")
            chunks, size = [], 0
            for chunk in response.iter_content(chunk_size=16_384):
                size += len(chunk)
                if size > 262_144:
                    raise _WeatherError("Open-Meteo response was unexpectedly large.")
                chunks.append(chunk)
            data = json.loads(b"".join(chunks))
    except requests.RequestException as exc:
        raise _WeatherError(f"Open-Meteo request failed ({type(exc).__name__}).") from exc
    except (ValueError, UnicodeError) as exc:
        raise _WeatherError("Open-Meteo returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise _WeatherError("Open-Meteo returned an unexpected response.")
    if data.get("error"):
        raise _WeatherError("Open-Meteo could not provide data: " + str(data.get("reason", "unspecified error"))[:180])
    return data, source_url


def get_weather(location: str, country_code: str | None = None) -> dict:
    """Return fresh current model estimates, or a clear error with no invented values."""
    try:
        query, country_code = _query(location, country_code)
        params = {"name": query, "count": 10, "language": "en", "format": "json"}
        if country_code:
            params["countryCode"] = country_code
        geocoded, _ = _get_json(_GEOCODING, params)
        places = geocoded.get("results", [])
        if not isinstance(places, list):
            raise _WeatherError("Open-Meteo returned invalid location results.")
        places = [p for p in places if isinstance(p, dict) and (not country_code or p.get("country_code") == country_code)]
        if not places:
            raise _WeatherError("No matching location found. Specify the city, state and country_code more precisely.")
        place = places[0]
        latitude, longitude = _number(place.get("latitude")), _number(place.get("longitude"))
        if latitude is None or longitude is None or not -90 <= latitude <= 90 or not -180 <= longitude <= 180:
            raise _WeatherError("Open-Meteo returned invalid location coordinates.")
        if not isinstance(place.get("name"), str) or not place["name"] or place.get("country_code") not in _COUNTRIES:
            raise _WeatherError("Open-Meteo did not identify the resolved city and country.")
        forecast, source_url = _get_json(_WEATHER, {
            "latitude": latitude, "longitude": longitude,
            "current": "temperature_2m,apparent_temperature,relative_humidity_2m,weather_code,wind_speed_10m",
            "temperature_unit": "celsius", "wind_speed_unit": "kmh", "timeformat": "unixtime", "timezone": "auto",
        })
        current, units = forecast.get("current"), forecast.get("current_units")
        if not isinstance(current, dict) or not isinstance(units, dict):
            raise _WeatherError("Open-Meteo did not return current weather values and units.")
        temperature, timestamp = _number(current.get("temperature_2m")), _number(current.get("time"))
        if temperature is None or timestamp is None:
            raise _WeatherError("Current temperature or source time is unavailable; no current weather can be confirmed.")
        if units.get("temperature_2m") != "°C" or units.get("time") != "unixtime":
            raise _WeatherError("Open-Meteo returned unexpected temperature or time units.")
        tz_name = forecast.get("timezone")
        try:
            if not isinstance(tz_name, str) or not tz_name:
                raise ValueError("missing timezone")
            tz = ZoneInfo(tz_name)
            valid_time = datetime.fromtimestamp(timestamp, timezone.utc).astimezone(tz).isoformat(timespec="minutes")
        except (ValueError, OverflowError, OSError, ZoneInfoNotFoundError) as exc:
            raise _WeatherError("Open-Meteo returned an invalid source timestamp or timezone.") from exc
        now = time.time()
        age = now - timestamp
        base = {
            "source": "Open-Meteo", "source_kind": "modeled estimate, not a station observation",
            "source_url": source_url,
            "location": {"name": place["name"], "country_code": place["country_code"],
                         "latitude": latitude, "longitude": longitude},
            "valid_time": valid_time, "timezone": tz_name,
            "retrieved_at": datetime.fromtimestamp(now, timezone.utc).isoformat(timespec="seconds"),
            "fresh": -3600 <= age <= 10800,
        }
        for key, destination in (("admin1", "region"), ("country", "country")):
            if isinstance(place.get(key), str) and place[key]:
                base["location"][destination] = place[key]
        if not base["fresh"]:
            base["error"] = "Source time is more than 3 hours old or over 1 hour in the future; current weather is unverified."
            return base
        base["temperature_c"] = round(temperature, 1)
        base["temperature_f"] = round(temperature * 9 / 5 + 32, 1)
        code = _number(current.get("weather_code"))
        base["condition"] = _CONDITIONS.get(code, "Unknown condition (weather code unavailable or unrecognized)")
        if code is not None:
            base["weather_code"] = code
        for field, expected_unit, output in (("apparent_temperature", "°C", "feels_like_c"),
                                             ("wind_speed_10m", "km/h", "wind_kph"),
                                             ("relative_humidity_2m", "%", "humidity_percent")):
            value = _number(current.get(field))
            if value is not None:
                if units.get(field) != expected_unit:
                    raise _WeatherError(f"Open-Meteo returned unexpected units for {field}.")
                base[output] = round(value, 1)
                if output == "feels_like_c":
                    base["feels_like_f"] = round(value * 9 / 5 + 32, 1)
        if len(places) > 1:
            base["location_note"] = "First matching location selected; use state/country qualifiers if this is not the intended city."
        # Keep answer-bearing facts first when older conversation history is clipped.
        order = ("temperature_c", "temperature_f", "condition", "feels_like_c", "feels_like_f",
                 "wind_kph", "humidity_percent", "weather_code", "valid_time", "timezone",
                 "location", "source", "source_kind", "fresh", "retrieved_at", "location_note", "source_url")
        return {key: base[key] for key in order if key in base}
    except _WeatherError as exc:
        return {"error": str(exc), "source": "Open-Meteo"}
