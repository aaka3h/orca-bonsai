"""Generic command failure evidence without running network or device commands."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
from orca_task_evidence import TaskEvidence, result_failed


class CommandDiagnosticsTests(unittest.TestCase):
    @staticmethod
    def record(result):
        evidence = TaskEvidence()
        evidence.add("run_command", {"command": "local-fixture"}, result)
        return evidence

    def test_generic_cli_failures_are_recognized_even_after_successful_filter(self):
        for line in (
            "command failed: Operation not permitted (-1)",
            "ioctl(EXAMPLE) failed: Device or resource busy",
            "sample-tool: invalid argument",
            "Error: Operation not supported",
            "sample-tool: Permission denied",
            "curl: (7) Failed to connect to example.test",
        ):
            for field in ("stdout", "stderr"):
                with self.subTest(line=line, field=field):
                    evidence = self.record({"exit_code": 0, field: line})
                    self.assertTrue(result_failed({"exit_code": 0, field: line}))
                    self.assertIn(line, evidence.render())
                    self.assertIn("partial failure (exit 0)", evidence.render())

    def test_terminal_controls_are_removed_before_detection_and_summary(self):
        line = "\x1b[31msample-tool: Permission denied\x1b[0m"
        evidence = self.record({"exit_code": 0, "stdout": line})
        self.assertTrue(evidence._records[0]["failed"])
        self.assertIn("sample-tool: Permission denied", evidence.render())
        self.assertNotIn("[31m", evidence.render())

    def test_explicit_flags_override_nominal_success(self):
        for flag in ("timed_out", "diagnostic_failure"):
            with self.subTest(flag=flag):
                evidence = self.record({"exit_code": 0, "success": True, flag: True})
                self.assertTrue(result_failed({flag: True}))
                self.assertTrue(evidence._records[0]["failed"])
                self.assertIn("timed out" if flag == "timed_out" else "failed", evidence.render())
        self.assertFalse(result_failed({"exit_code": 0, "timed_out": False, "diagnostic_failure": False}))

    def test_diagnostics_string_and_list_recognize_cli_errors(self):
        diagnostic = "sample-tool: Permission denied"
        for value in (diagnostic, ["Read-only diagnostic report", diagnostic]):
            with self.subTest(value=value):
                result = {"exit_code": 0, "diagnostics": value}
                self.assertTrue(result_failed(result))
                self.assertIn(diagnostic, self.record(result).progress())

    def test_tagged_diagnostics_preserve_failure_detail(self):
        for value in (
            {"severity": "error", "message": "Configuration is unavailable"},
            {"level": "FATAL", "detail": "Configuration is unavailable"},
            {"status": "failed", "reason": "Configuration is unavailable"},
            {"error": "Configuration is unavailable"},
            {"success": False, "text": "Configuration is unavailable"},
            [{"status": "ok"}, {"failed": True, "message": "Configuration is unavailable"}],
            {"diagnostics": [{"severity": "error", "message": "Configuration is unavailable"}]},
        ):
            with self.subTest(value=value):
                result = {"exit_code": 0, "diagnostics": value}
                self.assertTrue(result_failed(result))
                self.assertIn("Configuration is unavailable", self.record(result).progress())

    def test_tags_without_messages_still_report_failure(self):
        result = {"exit_code": 0, "diagnostics": {"status": "timed_out"}}
        self.assertTrue(result_failed(result))
        self.assertIn("Diagnostic reported failure", self.record(result).render())

    def test_ordinary_diagnostics_are_not_failures(self):
        for value in (
            "No errors detected", [], {},
            {"severity": "warning", "message": "Optional feature is not installed"},
            [{"level": "info", "message": "No errors detected"}],
            {"status": "ok", "message": "Read the error documentation"},
        ):
            with self.subTest(value=value):
                self.assertFalse(result_failed({"exit_code": 0, "diagnostics": value}))

    def test_quoted_or_html_examples_do_not_turn_success_into_failure(self):
        diagnostic = "sample-tool: Permission denied"
        for value in (
            "<html><pre>\n" + diagnostic + "\n</pre></html>",
            "<p>A command example:</p>\n" + diagnostic,
            "```text\n" + diagnostic + "\n```",
            "> " + diagnostic,
            "Example output:\n" + diagnostic,
            "    " + diagnostic,
        ):
            with self.subTest(value=value):
                self.assertFalse(result_failed({"exit_code": 0, "stdout": value}))
                self.assertFalse(result_failed({"exit_code": 0, "diagnostics": value}))

    def test_explicit_error_survives_html_and_noisy_output(self):
        result = {
            "exit_code": 0,
            "error": "Failed to extract the document",
            "stdout": "<html><p>sample-tool: Permission denied</p></html>" + "noise " * 10000,
        }
        evidence = self.record(result)
        self.assertTrue(result_failed(result))
        self.assertIn("Failed to extract the document", evidence.progress())
        self.assertIn("failed (exit 0)", evidence.progress())

    def test_diagnostic_survives_long_output_and_later_results(self):
        evidence = self.record({
            "exit_code": 0, "stdout": "Unimportant text\n" * 1000,
            "diagnostics": {"severity": "error", "message": "A required file is unavailable"},
        })
        for index in range(40):
            evidence.add("run_command", {"command": f"local-fixture-{index}"}, {"exit_code": 0, "stdout": "ok"})
        self.assertIn("A required file is unavailable", evidence.render())
        self.assertIn("A required file is unavailable", evidence.progress())
        self.assertLessEqual(len(evidence.progress()), 1100)


if __name__ == "__main__":
    unittest.main()
