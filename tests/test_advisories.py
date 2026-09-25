"""No live requests: verify advisory parsing, bounds and failure semantics."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_advisories as advisories


class Response:
    def __init__(self, data=None, status=200, raw=None):
        self.status_code = status
        self.body = raw if raw is not None else json.dumps(data).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def iter_content(self, chunk_size):
        for start in range(0, len(self.body), chunk_size):
            yield self.body[start:start + chunk_size]


def record(identifier="CVE-2021-44228"):
    return {"cve": {"id": identifier, "vulnStatus": "Analyzed", "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2026-08-11T19:33:44.513", "descriptions": [{"lang": "en", "value": "Example product 2.0 has a published flaw."}],
                    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
                        "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                    "references": [{"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]}]}}


def payload(*records):
    return {"totalResults": len(records), "vulnerabilities": list(records)}


class AdvisoryTests(unittest.TestCase):
    def lookup(self, data, query="CVE-2021-44228", **kwargs):
        with patch.object(advisories.requests, "get", return_value=Response(data, **kwargs)) as get:
            result = advisories.lookup_security_advisories(query)
            self.assertEqual(get.call_count, 1)
            self.assertEqual(get.call_args.args[0], advisories._ENDPOINT)
            self.assertFalse(get.call_args.kwargs["allow_redirects"])
            return result

    def test_exact_cve_and_published_fields(self):
        result = self.lookup(payload(record()), "cve-2021-44228")
        item = result["results"][0]
        self.assertEqual(item["classification"], "candidate_advisory")
        self.assertEqual(item["cvss"], {"version": "3.1", "base_score": 9.8, "severity": "CRITICAL", "source": "nvd@nist.gov"})
        self.assertIn("applicability is unverified", result["note"])
        self.assertEqual(item["published"], "2021-12-10T10:15:09.143")
        self.assertEqual(item["vendor_advisories"], ["https://vendor.example/advisory"])

    def test_keyword_parameter(self):
        with patch.object(advisories.requests, "get", return_value=Response(payload(record()))) as get:
            result = advisories.lookup_security_advisories("OpenSSH 9.8p1")
            self.assertEqual(get.call_args.kwargs["params"], {"keywordSearch": "OpenSSH 9.8p1", "resultsPerPage": 5})
            self.assertEqual(result["query"], "OpenSSH 9.8p1")

    def test_empty_or_generic_queries_never_request(self):
        with patch.object(advisories.requests, "get") as get:
            for query in ["", None, [], "all vulnerabilities", "nginx", "CVE-2021-44", "https://example.com/2.0", "2.0", "nginx\n1.2", "x" * 121]:
                with self.subTest(query=query):
                    self.assertIn("error", advisories.lookup_security_advisories(query))
            get.assert_not_called()

    def test_missing_rating_is_not_invented(self):
        item = record()
        item["cve"]["metrics"] = {}
        self.assertIsNone(self.lookup(payload(item))["results"][0]["cvss"])

    def test_v4_preferred_and_source_retained(self):
        item = record()
        item["cve"]["metrics"]["cvssMetricV40"] = [{"source": "security@vendor.example", "type": "Secondary", "cvssData": {
            "version": "4.0", "baseScore": 8.7, "baseSeverity": "HIGH"}}]
        metric = self.lookup(payload(item))["results"][0]["cvss"]
        self.assertEqual(metric["version"], "4.0")
        self.assertEqual(metric["base_score"], 8.7)
        self.assertEqual(metric["source"], "security@vendor.example")

    def test_rejected_record_has_no_rating(self):
        item = record()
        item["cve"]["vulnStatus"] = "Rejected"
        result = self.lookup(payload(item))
        self.assertEqual(result["results"][0]["classification"], "rejected_record")
        self.assertIsNone(result["results"][0]["cvss"])
        self.assertIn("Rejected records must not", result["note"])

    def test_no_matches_is_not_secure_conclusion(self):
        result = self.lookup(payload(), "nginx 1.28.3")
        self.assertEqual(result["results"], [])
        self.assertIn("no matches does not mean secure", result["note"])

    def test_rate_limit_no_retry(self):
        result = self.lookup(None, status=429)
        self.assertIn("rate limit", result["error"])
        self.assertIn("not retried", result["error"])

    def test_network_failure_and_bad_http(self):
        with patch.object(advisories.requests, "get", side_effect=advisories.requests.Timeout()) as get:
            result = advisories.lookup_security_advisories("CVE-2021-44228")
            self.assertIn("Timeout", result["error"])
            self.assertEqual(get.call_count, 1)
        self.assertIn("HTTP 503", self.lookup(None, status=503)["error"])

    def test_malformed_responses(self):
        for data in [[], {}, {"totalResults": "1", "vulnerabilities": []}, {"totalResults": 1, "vulnerabilities": [{}]}, payload(record("CVE-2020-1234"))]:
            with self.subTest(data=data):
                self.assertIn("error", self.lookup(data))
        self.assertIn("invalid JSON", self.lookup(None, raw=b'{invalid')["error"])

    def test_body_limit(self):
        self.assertIn("size or time limit", self.lookup(None, raw=b'x' * (advisories._MAX_BYTES + 1))["error"])

    def test_five_results_output_bound_and_vendor_links_only(self):
        records = []
        for n in range(6):
            item = record(f"CVE-2025-{1000 + n}")
            item["cve"]["descriptions"][0]["value"] = "Example Unicode é and words " * 200
            item["cve"]["references"] = [{"url": "https://vendor.example/" + "x" * 220 + str(n), "tags": ["Vendor Advisory"]} for _ in range(3)]
            item["cve"]["references"] += [{"url": "https://exploit.example/", "tags": ["Exploit"]}, {"url": "javascript:alert(1)", "tags": ["Vendor Advisory"]}]
            records.append(item)
        result = self.lookup(payload(*records), "Example 2.0")
        self.assertEqual(len(result["results"]), 5)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(json.dumps(result)), 4500)
        for item in result["results"]:
            self.assertLessEqual(len(item["description"]), 450)
            self.assertTrue(item["description_excerpt"])
            self.assertLessEqual(len(item["vendor_advisories"]), 2)
            self.assertFalse(any("exploit.example" in url or "javascript" in url for url in item["vendor_advisories"]))


if __name__ == "__main__":
    unittest.main()
