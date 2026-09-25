import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
from orca_security_context import compact_security_result


def advisory(n):
    return {"id": f"CVE-2025-{1000+n}", "status": "Analyzed", "classification": "candidate_advisory",
            "description": "Example issue requiring a specific vulnerable version and configuration. " * 8,
            "cvss": {"version": "3.1", "base_score": 8.8, "severity": "HIGH", "source": "nvd@nist.gov"},
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/CVE-2025-{1000+n}"}


class SecurityContextTests(unittest.TestCase):
    def compact(self, name, result, limit=1000):
        text = compact_security_result(name, result, limit)
        self.assertLessEqual(len(text), limit)
        return json.loads(text)

    def test_candidate_ids_keep_qualification_and_source(self):
        result = {"query": "Example 2.0", "source": "NIST NVD CVE API 2.0", "total_results": 30,
                  "results": [advisory(n) for n in range(10)]}
        output = self.compact("lookup_security_advisories", result, 1700)
        self.assertTrue(output["results"])
        self.assertGreater(output["omitted_results"], 0)
        self.assertIn("target applicability unverified", output["note"])
        for item in output["results"]:
            self.assertEqual(item["classification"], "candidate_advisory")
            self.assertEqual(item["cvss"]["source"], "nvd@nist.gov")
            self.assertTrue(item["nvd_url"].endswith(item["id"]))

    def test_rejected_status_wins_over_candidate_and_removes_stale_rating(self):
        item = advisory(1)
        item["status"] = "Rejected"
        output = self.compact("lookup_security_advisories", {"results": [item]})
        result = output["results"][0]
        self.assertEqual(result["classification"], "rejected_record")
        self.assertNotIn("cvss", result)

    def test_services_keep_product_version_ports_and_partial_status(self):
        result = {"check": "services", "target": "example.org", "check_status": "partial", "error": "Host timeout reached",
                  "evidence": {"tcp_ports_checked": [22, 80, 443], "open_services": [
                      {"port": 22, "state": "open", "name": "ssh", "product": "OpenSSH", "version": "9.8p1"},
                      {"port": 443, "state": "open", "name": "https", "product": "nginx", "version": "1.24.0"}]}, "findings": []}
        output = self.compact("security_check", result)
        self.assertEqual(output["check_status"], "partial")
        self.assertEqual(output["evidence"]["tcp_ports_checked"], [22, 80, 443])
        self.assertEqual(output["evidence"]["open_services"][0]["version"], "9.8p1")
        self.assertEqual(output["omitted_services"], 0)
        self.assertIn("do not prove exploitation", output["note"])

    def test_failed_tls_reason_and_classification_survive(self):
        result = {"check": "tls", "target": "example.org", "check_status": "error",
                  "error": "Certificate validation failed with this machine's trust store.",
                  "evidence": {"port": 443, "certificate_verified": False, "verify_code": 10, "reason": "certificate has expired"},
                  "findings": [{"id": "tls-certificate-validation", "classification": "configuration", "severity": "medium", "evidence": "certificate has expired"}]}
        output = self.compact("security_check", result)
        self.assertFalse(output["evidence"]["certificate_verified"])
        self.assertEqual(output["evidence"]["reason"], "certificate has expired")
        self.assertEqual(output["findings"][0]["classification"], "configuration")
        self.assertEqual(output["check_status"], "error")

    def test_hardening_evidence_stays_with_identifier(self):
        result = {"check": "web", "target": "https://example.org/", "check_status": "complete", "evidence": {
            "http_status": 200, "headers": {"server": "nginx", "content-security-policy": "long policy " * 100}},
            "findings": [{"id": "missing-hsts", "classification": "hardening", "severity": "low", "evidence": "HTTPS response has no Strict-Transport-Security header."}]}
        output = self.compact("security_check", result)
        item = output["findings"][0]
        self.assertEqual(item["classification"], "hardening")
        self.assertEqual(item["id"], "missing-hsts")
        self.assertIn("no Strict-Transport-Security", item["evidence"])
        self.assertEqual(output["evidence"]["http_status"], 200)

    def test_small_budgets_valid_json(self):
        cases = [("lookup_security_advisories", {"results": [advisory(n) for n in range(100)]}),
                 ("security_check", {"check": "web", "target": "https://example.org/", "check_status": "error", "error": "failure" * 1000})]
        for name, result in cases:
            for budget in [1, 2, 20, 40, 80, 150, 250, 500, 1000, 1700]:
                with self.subTest(name=name, budget=budget):
                    self.compact(name, result, budget)

    def test_urls_are_kept_whole_or_omitted(self):
        long_url = "https://example.org/" + "x" * 500
        item = advisory(1)
        item["nvd_url"] = long_url
        item["description"] = "Read " + long_url + " for information"
        output = self.compact("lookup_security_advisories", {"results": [item]})
        encoded = json.dumps(output)
        self.assertNotIn("https://example.org/", encoded)
        output = self.compact("security_check", {"target": long_url, "check": "web", "check_status": "error", "error": "Failed at " + long_url})
        self.assertNotIn("https://example.org/", json.dumps(output))

    def test_repeat_compaction_retains_caveat_and_omission_counts(self):
        original = {"results": [advisory(n) for n in range(10)], "query": "Example 2.0", "total_results": 30}
        output = self.compact("lookup_security_advisories", original, 1700)
        same = self.compact("lookup_security_advisories", output, 1700)
        self.assertEqual(output, same)
        smaller = self.compact("lookup_security_advisories", same, 1000)
        self.assertEqual(smaller["omitted_results"] + len(smaller["results"]), 10)
        for record in smaller["results"]:
            self.assertEqual(record["classification"], "candidate_advisory")
            self.assertIn("description_excerpt", record)
        smallest = self.compact("lookup_security_advisories", smaller, 190)
        self.assertEqual(smallest["omitted_results"], 10)
        self.assertIn("unverified", smallest["note"])
        self.assertEqual(smallest["results"], [])

    def test_repeat_check_compaction_retains_omitted_counts(self):
        original = {"check": "services", "target": "example.org", "check_status": "complete", "evidence": {
            "open_services": [{"port": n, "state": "open", "name": "example", "product": "Example Server", "version": "1.24.0"} for n in range(1, 17)]},
            "findings": [], "omitted_findings": 3}
        output = self.compact("security_check", original, 1700)
        same = self.compact("security_check", output, 1700)
        self.assertEqual(output, same)
        smaller = self.compact("security_check", same, 700)
        self.assertEqual(smaller["omitted_services"] + len(smaller["evidence"]["open_services"]), 16)
        self.assertEqual(smaller["omitted_findings"], 3)

    def test_vendor_link_preserved_whole_and_recompression_stable(self):
        item = advisory(1)
        item["vendor_advisories"] = ["https://vendor.example/security/CVE-2025-1001", "https://other.example/advisory"]
        output = self.compact("lookup_security_advisories", {"results": [item]}, 1700)
        self.assertEqual(output["results"][0]["vendor_advisories"], item["vendor_advisories"][:1])
        self.assertEqual(self.compact("lookup_security_advisories", output, 1700), output)

    def test_vendor_link_never_displaces_qualified_cve_record(self):
        item = advisory(1)
        item["vendor_advisories"] = ["https://vendor.example/" + "x" * 300]
        without_link = dict(item)
        without_link.pop("vendor_advisories")
        expected = self.compact("lookup_security_advisories", {"results": [without_link]}, 1700)
        budget = len(json.dumps(expected, ensure_ascii=False, separators=(",", ":")))
        output = self.compact("lookup_security_advisories", {"results": [item]}, budget)
        self.assertEqual(output["results"][0]["id"], item["id"])
        self.assertEqual(output["results"][0]["classification"], "candidate_advisory")
        self.assertNotIn("vendor_advisories", output["results"][0])

    def test_finding_fix_preserved_when_fit_and_never_displaces_evidence(self):
        finding = {"id": "missing-hsts", "classification": "hardening", "severity": "low",
                   "evidence": "HTTPS response has no Strict-Transport-Security header.",
                   "fix": "Evaluate HSTS after confirming HTTPS works for intended hosts and subdomains."}
        original = {"check": "web", "target": "https://example.org/", "check_status": "complete", "findings": [finding]}
        output = self.compact("security_check", original, 1700)
        self.assertEqual(output["findings"][0]["fix"], finding["fix"])
        self.assertEqual(self.compact("security_check", output, 1700), output)
        no_fix = {**original, "findings": [{key: value for key, value in finding.items() if key != "fix"}]}
        expected = self.compact("security_check", no_fix, 1700)
        budget = len(json.dumps(expected, ensure_ascii=False, separators=(",", ":")))
        smaller = self.compact("security_check", original, budget)
        self.assertNotIn("fix", smaller["findings"][0])
        self.assertEqual(smaller["findings"][0]["evidence"], finding["evidence"])
        self.assertEqual(smaller["findings"][0]["classification"], "hardening")


if __name__ == "__main__":
    unittest.main()
