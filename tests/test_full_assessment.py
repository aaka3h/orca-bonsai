"""Deterministic assessment orchestration tests; every scan/network seam is mocked."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_full_assessment as assessment


def done(tool, **extras):
    return {"status": "complete", "tool": tool, "summary": tool + " completed", "findings": [], **extras}


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.calls = []
        self.mocks = {}
        for name, tool in (("_inventory", "inventory"), ("_run_services", "nmap"), ("_run_web_audit", "web_audit"),
                           ("_run_nikto", "nikto"), ("_run_nuclei", "nuclei")):
            def execute(*args, _tool=tool, **kwargs):
                self.calls.append(_tool)
                return done(_tool)
            self.mocks[name] = self.enterContext(patch.object(assessment, name, side_effect=execute))
        def security(target, check):
            self.calls.append(check)
            return {"check_status": "complete", "tool": check, "findings": [], "evidence": {"url": target}}
        self.security = self.enterContext(patch.object(assessment, "_security_check", side_effect=security))
        self.advisories = self.enterContext(patch.object(assessment, "_lookup_advisories", return_value={"results": [], "total_results": 0}))
        self.sleep = self.enterContext(patch.object(assessment.time, "sleep"))

    def run_assessment(self, **kwargs):
        return assessment.run_full_assessment("https://example.test/", output_root=self.root, **kwargs)

    def manifest(self, result):
        return json.loads(Path(result["manifest_path"]).read_text())

    def test_all_mandatory_stages_persist_in_order_and_scope(self):
        events, snapshots = [], []
        def sink(event):
            events.append(event)
            if event["type"] == "tool_start":
                manifest = json.loads(Path(event["args"]["manifest_path"]).read_text())
                snapshots.append(manifest)
        result = self.run_assessment(event_sink=sink)
        self.assertEqual(self.calls, ["inventory", "web", "tls", "nmap", "web_audit", "nikto", "nuclei"])
        self.assertEqual([stage["stage"] for stage in result["coverage"]], list(assessment._STAGES))
        self.assertEqual(result["assessment_status"], "complete")
        self.assertEqual(result["coverage"][-1]["status"], "not_applicable")
        self.mocks["_run_services"].assert_called_once()
        self.assertEqual(self.mocks["_run_services"].call_args.kwargs, {"ports": "all", "timeout": 1800})
        self.assertEqual(self.mocks["_run_web_audit"].call_args.kwargs, {"timeout": 300, "page_limit": 30})
        self.assertEqual(len(snapshots), 8)
        self.assertEqual(events[0], {"type": "assessment_report", "path": result["report_path"]})
        for index, snapshot in enumerate(snapshots):
            self.assertEqual(snapshot["assessment_status"], "running")
            self.assertEqual(snapshot["stages"][index]["status"], "running")
            for later in snapshot["stages"][index + 1:]:
                self.assertEqual(later["status"], "pending")
        manifest = self.manifest(result)
        self.assertIsNotNone(manifest["finished_at"])
        self.assertEqual(manifest["parameters"]["ports"], "1-65535 (all TCP ports)")
        self.assertEqual(len([event for event in events if event["type"] == "tool_result"]), 8)
        for stage in manifest["stages"]:
            self.assertEqual(json.loads(Path(stage["result_path"]).read_text()), stage["result"])
        self.assertEqual(Path(result["manifest_path"]).stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(result["manifest_path"]).parent.stat().st_mode & 0o777, 0o700)

    def test_failures_missing_tools_and_partial_work_do_not_skip_later_stages(self):
        self.mocks["_inventory"].side_effect = RuntimeError("inventory failed")
        self.mocks["_run_services"].side_effect = None
        self.mocks["_run_services"].return_value = done("nmap", status="partial", error="Timed out", observations=[{"port": 443}])
        self.mocks["_run_nikto"].side_effect = None
        self.mocks["_run_nikto"].return_value = {"status": "blocked", "tool": "nikto", "error": "Not installed"}
        self.mocks["_run_nuclei"].side_effect = None
        self.mocks["_run_nuclei"].return_value = done("nuclei", findings=[{"id": "CVE-2020-12345", "classification": "candidate", "evidence": "template matched"}])
        result = self.run_assessment()
        self.assertEqual(result["assessment_status"], "partial")
        statuses = {stage["stage"]: stage["status"] for stage in result["coverage"]}
        self.assertEqual(statuses["inventory"], "blocked")
        self.assertEqual(statuses["services"], "partial")
        self.assertEqual(statuses["nikto"], "blocked")
        self.assertEqual(statuses["nuclei"], "complete")
        self.assertEqual(statuses["advisories"], "complete")
        self.advisories.assert_called_once_with("CVE-2020-12345")
        self.assertNotIn("pending", statuses.values())

    def test_invalid_scope_and_ports_rejected_before_work(self):
        for target in ("example.test;id", "https://example.test other.test", "10.0.0.0/24", "https://user:pass@example.test", "*.example.test"):
            with self.subTest(target=target):
                result = assessment.run_full_assessment(target, output_root=self.root)
                self.assertIn("error", result)
                self.assertIsNone(result["manifest_path"])
        for ports in ("0", "443-80", "65536", "80,443;id", "-p-", "22,,80", 123):
            with self.subTest(ports=ports):
                result = self.run_assessment(ports=ports)
                self.assertIn("error", result)
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.root.iterdir()), [])
        self.advisories.assert_not_called()

    def test_valid_selected_ports_and_http_tls_not_applicable(self):
        result = assessment.run_full_assessment("http://example.test:8080/start", ports="022,443,8000-8100,443", output_root=self.root)
        self.assertEqual(self.mocks["_run_services"].call_args.kwargs["ports"], "22,443,8000-8100")
        self.assertEqual(self.mocks["_run_services"].call_args.args[0], "http://example.test:8080/start")
        self.assertNotIn("tls", self.calls)
        self.assertEqual(next(stage for stage in result["coverage"] if stage["stage"] == "tls")["status"], "not_applicable")
        self.assertEqual(self.manifest(result)["parameters"]["ports"], "22,443,8000-8100")

    def test_correlates_cves_keeps_all_evidence_and_all_unique_findings(self):
        findings = [{"id": "CVE-2020-12345", "title": "First scanner", "classification": "candidate", "severity": "medium", "location": "/a", "evidence": "First proof", "references": ["https://vendor.example/advisory"]}]
        findings += [{"id": f"unique-{index}", "classification": "hardening", "evidence": f"Evidence {index}"} for index in range(12)]
        self.mocks["_run_nikto"].side_effect = None
        self.mocks["_run_nikto"].return_value = done("nikto", findings=findings)
        self.mocks["_run_nuclei"].side_effect = None
        self.mocks["_run_nuclei"].return_value = done("nuclei", findings=[{"id": "cve-2020-12345", "title": "Second scanner", "classification": "candidate", "severity": "high", "location": "/b", "evidence": {"request": "Second proof"}}])
        result = self.run_assessment()
        self.assertEqual(result["counts"]["total"], 13)
        self.assertEqual(result["counts"]["confirmed_exploits"], 0)
        self.assertEqual(len(result["findings"]), 8)
        manifest = self.manifest(result)
        correlated = next(f for f in manifest["findings"] if f["id"] == "CVE-2020-12345")
        self.assertEqual(correlated["sources"], ["nikto", "nuclei"])
        self.assertEqual(correlated["locations"], ["/a", "/b"])
        self.assertEqual(correlated["evidence"], ["First proof", {"request": "Second proof"}])
        self.assertEqual(len(correlated["source_findings"]), 2)
        self.assertEqual(correlated["severity"], "high")
        report = Path(result["report_path"]).read_text()
        self.assertIn("unique-11", report)
        self.assertIn("First proof", report)
        self.assertIn("Second proof", report)
        self.assertIn("Complete stage records", report)
        self.assertIn("No exploit or exploitability validation", report)

    def test_complete_artifacts_expand_bounded_previews_for_correlation(self):
        def scanner(target, output_dir, **kwargs):
            findings = [{"id": f"finding-{i}", "classification": "hardening", "evidence": str(i)} for i in range(125)]
            path = output_dir / "all-findings.json"
            path.write_text(json.dumps(findings))
            return done("nikto", findings=findings[:1], findings_artifact=str(path))
        def services(target, output_dir, **kwargs):
            observations = {"open_services": [{"product": "nginx", "version": "1.22.1", "port": 443}]}
            path = output_dir / "observations.json"
            path.write_text(json.dumps(observations))
            return done("nmap", observations={}, observations_artifact=str(path))
        self.mocks["_run_nikto"].side_effect = scanner
        self.mocks["_run_services"].side_effect = services
        result = self.run_assessment()
        self.assertEqual(result["counts"]["total"], 125)
        self.assertEqual(len(self.manifest(result)["findings"]), 125)
        self.assertIn("finding-124", Path(result["report_path"]).read_text())
        self.advisories.assert_called_once_with("nginx 1.22.1")

    def test_artifact_outside_stage_is_not_read_and_marks_partial(self):
        outside = self.root / "outside.json"
        outside.write_text('[{"id": "must-not-read"}]')
        self.mocks["_run_nikto"].side_effect = None
        self.mocks["_run_nikto"].return_value = done("nikto", findings_artifact=str(outside))
        result = self.run_assessment()
        self.assertEqual(result["assessment_status"], "partial")
        self.assertEqual(result["counts"]["total"], 0)
        self.assertNotIn("must-not-read", Path(result["report_path"]).read_text())

    def test_same_id_different_locations_are_retained_without_cve(self):
        stages = [{"stage": "web_audit", "result": done("zap", findings=[
            {"id": "missing-header", "location": "/a", "classification": "hardening", "evidence": "one"},
            {"id": "missing-header", "location": "/b", "classification": "hardening", "evidence": "two"}])}]
        self.assertEqual(len(assessment._correlate(stages, "https://example.test")), 2)

    def test_advisory_exact_ids_prioritized_capped_paced_and_errors_recorded(self):
        self.mocks["_run_services"].side_effect = None
        self.mocks["_run_services"].return_value = done("nmap", observations=[{"product": "nginx", "version": "1.22.1"}])
        self.mocks["_run_nuclei"].side_effect = None
        self.mocks["_run_nuclei"].return_value = done("nuclei", findings=[{"id": f"CVE-2020-{10000 + i}", "classification": "candidate"} for i in range(6)])
        self.advisories.side_effect = [{"error": "NVD rate limit reached (HTTP 429)."}] + [{"results": [], "total_results": 0}] * 4
        result = self.run_assessment()
        self.assertEqual([call.args[0] for call in self.advisories.call_args_list], [f"CVE-2020-{10000 + i}" for i in range(5)])
        self.assertEqual(self.sleep.call_count, 4)
        for call in self.sleep.call_args_list:
            self.assertLessEqual(call.args[0], 6.1)
            self.assertGreater(call.args[0], 0)
        self.assertEqual(result["assessment_status"], "partial")
        stage = self.manifest(result)["stages"][-1]
        self.assertEqual(stage["status"], "partial")
        self.assertIn("HTTP 429", json.dumps(stage))
        self.assertIn("2 additional", json.dumps(stage))

    def test_product_version_lookup_preserves_vendor_refs_and_rejected_classification(self):
        self.mocks["_run_services"].side_effect = None
        self.mocks["_run_services"].return_value = done("nmap", evidence={"open_services": [{"port": 443, "product": "nginx", "version": "1.22.1"}, {"port": 80, "product": "Golang net/http"}]})
        self.mocks["_run_nuclei"].side_effect = None
        self.mocks["_run_nuclei"].return_value = done("nuclei", findings=[{"id": "CVE-2020-22222", "classification": "candidate", "evidence": "Scanner match"}])
        vendor_refs = ["https://vendor.example/advisory"]
        self.advisories.return_value = {"results": [
            {"id": "CVE-2020-11111", "classification": "candidate_advisory", "vendor_advisories": vendor_refs, "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-11111", "cvss": {"severity": "HIGH"}},
            {"id": "CVE-2020-22222", "classification": "rejected_record", "status": "Rejected"}]}
        result = self.run_assessment()
        self.assertEqual([call.args[0] for call in self.advisories.call_args_list], ["CVE-2020-22222", "nginx 1.22.1"])
        self.assertEqual(vendor_refs, ["https://vendor.example/advisory"])
        findings = {f["id"]: f for f in self.manifest(result)["findings"]}
        self.assertEqual(findings["CVE-2020-11111"]["classification"], "candidate")
        self.assertIn("https://vendor.example/advisory", findings["CVE-2020-11111"]["references"])
        self.assertEqual(findings["CVE-2020-22222"]["classification"], "observation")

    def test_interrupt_preserves_pending_running_manifest_and_incremental_report(self):
        self.mocks["_run_services"].side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.run_assessment()
        manifest_path = next(self.root.glob("*/manifest.json"))
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["assessment_status"], "running")
        self.assertIsNone(manifest["finished_at"])
        self.assertEqual(manifest["stages"][3]["status"], "running")
        self.assertEqual(manifest["stages"][4]["status"], "pending")
        self.assertEqual(manifest["stages"][2]["status"], "complete")
        self.assertTrue((manifest_path.parent / "REPORT.md").is_file())
        self.assertIn("Not finished", (manifest_path.parent / "REPORT.md").read_text())

    def test_fresh_report_directory_each_run_and_event_failure_does_not_lose_results(self):
        def failed_sink(event):
            raise BrokenPipeError("GUI closed")
        first, second = self.run_assessment(event_sink=failed_sink), self.run_assessment()
        self.assertNotEqual(first["manifest_path"], second["manifest_path"])
        self.assertEqual(len(list(self.root.iterdir())), 2)
        self.assertEqual(first["assessment_status"], "complete")
        self.assertTrue(Path(second["report_path"]).is_file())

    def test_observation_labels_and_unrecognized_tool_state_never_imply_success(self):
        self.mocks["_run_nikto"].side_effect = None
        self.mocks["_run_nikto"].return_value = {"tool": "nikto", "status": "made_up", "findings": [
            {"id": "server-banner", "classification": "candidate", "evidence": "nginx"},
            {"id": "http-to-https-redirect", "classification": "candidate", "evidence": "301 HTTPS"}]}
        result = self.run_assessment()
        self.assertEqual(result["assessment_status"], "partial")
        self.assertEqual(result["counts"]["candidate"], 0)
        self.assertEqual(result["counts"]["observation"], 2)
        self.assertEqual(next(stage for stage in result["coverage"] if stage["stage"] == "nikto")["status"], "partial")


if __name__ == "__main__":
    unittest.main()
