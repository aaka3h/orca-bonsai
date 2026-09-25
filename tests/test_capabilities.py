import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_capabilities as capabilities


class CapabilitiesTests(unittest.TestCase):
    def test_inventory_does_not_execute_requested_names(self):
        with patch.object(capabilities.shutil, "which", side_effect=lambda name: "/usr/bin/" + name), \
             patch.object(capabilities.subprocess, "Popen") as popen:
            result = capabilities.check_capabilities({"programs": ["a-custom-tool", "a-custom-tool"], "network": False})
        popen.assert_not_called()
        self.assertEqual(len(result["programs"]), 1)
        self.assertTrue(result["programs"][0]["installed"])
        self.assertFalse(result["programs"][0]["tested"])
        self.assertEqual(result["network_checks"], [])

    def test_invalid_options_fail_before_lookup_or_execution(self):
        values = [[], {"programs": "curl"}, {"programs": ["x"] * 13},
                  {"programs": ["/usr/bin/curl"]}, {"programs": ["curl;id"]},
                  {"programs": ["-rf"]}, {"programs": [True]}, {"network": "false"}]
        with patch.object(capabilities.shutil, "which") as which, \
             patch.object(capabilities.subprocess, "Popen") as popen:
            for value in values:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    capabilities.check_capabilities(value)
        which.assert_not_called()
        popen.assert_not_called()

    def test_missing_fixed_commands_are_reported(self):
        with patch.object(capabilities.shutil, "which", return_value=None), \
             patch.object(capabilities.subprocess, "Popen") as popen:
            result = capabilities.check_capabilities()
        self.assertEqual(len(result["programs"]), 12)
        self.assertEqual(len(result["network_checks"]), 4)
        self.assertTrue(all(item["status"] == "unavailable" for item in result["network_checks"]))
        popen.assert_not_called()

    def test_network_queries_use_only_fixed_arguments(self):
        seen = []
        class Process:
            returncode = 0
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def wait(self, timeout=None):
                self.timeout = timeout
                return 0
        def start(argv, **kwargs):
            self.assertFalse(kwargs["shell"])
            self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
            seen.append(argv)
            kwargs["stdout"].write(b"\x1b[31mstate\x1b[0m\n")
            return Process()
        with patch.object(capabilities.shutil, "which", side_effect=lambda name: "/usr/bin/" + name), \
             patch.object(capabilities.subprocess, "Popen", side_effect=start):
            result = capabilities.check_capabilities({"programs": ["never-run-this"]})
        self.assertEqual(seen, [["/usr/bin/" + command[0], *command[1:]] for _, command in capabilities._NETWORK_COMMANDS])
        self.assertTrue(all(item["stdout"] == "state\n" for item in result["network_checks"]))

    def test_timeout_kills_and_preserves_bounded_diagnostics(self):
        class Process:
            returncode = -9
            killed = False
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def wait(self, timeout=None):
                if timeout is not None:
                    raise subprocess.TimeoutExpired("fixed", timeout)
                return -9
            def kill(self): self.killed = True
        process = Process()
        def start(argv, **kwargs):
            kwargs["stderr"].write(b"x" * 10000)
            return process
        with patch.object(capabilities.shutil, "which", return_value="/usr/bin/ip"), \
             patch.object(capabilities.subprocess, "Popen", side_effect=start):
            result = capabilities._query("routes", ("ip", "route", "show", "default"))
        self.assertTrue(process.killed)
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(len(result["stderr"]), 4096)
        self.assertTrue(result["truncated"])
        self.assertIn("3 seconds", result["error"])

    def test_execution_error_is_not_reported_as_success(self):
        with patch.object(capabilities.shutil, "which", return_value="/usr/bin/ip"), \
             patch.object(capabilities.subprocess, "Popen", side_effect=PermissionError("blocked")):
            result = capabilities._query("routes", ("ip", "route", "show", "default"))
        self.assertEqual(result["status"], "error")
        self.assertIn("blocked", result["error"])

    def test_environment_values_are_not_disclosed(self):
        with patch.dict(os.environ, {"DISPLAY": "private-display", "WAYLAND_DISPLAY": "private-wayland", "PRIVATE_SECRET": "do-not-disclose"}), \
             patch.object(capabilities.shutil, "which", return_value=None):
            result = capabilities.check_capabilities({"network": False})
        self.assertTrue(result["system"]["display_available"])
        self.assertTrue(result["system"]["wayland_display_available"])
        self.assertNotIn("private-display", repr(result))
        self.assertNotIn("private-wayland", repr(result))
        self.assertNotIn("do-not-disclose", repr(result))

    def test_formatter_is_bounded_and_states_untested_limit(self):
        with patch.object(capabilities.shutil, "which", return_value=None):
            result = capabilities.check_capabilities()
        for item in result["network_checks"]:
            item.update(status="error", stdout="long status " * 1000, stderr="\x1b[31merror\x1b[0m" * 1000)
        text = capabilities.format_capabilities(result)
        self.assertLessEqual(len(text), 3000)
        self.assertIn("not functionally tested", text)
        self.assertNotIn("\x1b", text)
        self.assertIn("monitor-mode support", text)


if __name__ == "__main__":
    unittest.main()
