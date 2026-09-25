"""Regression checks and optional real ZAP/local HTTP fixture verification."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_web_audit as audit


class Fixture(BaseHTTPRequestHandler):
    visited = []

    def do_GET(self):
        self.visited.append(self.path)
        self.send_response(302 if self.path == "/redirect" else 200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Set-Cookie", "session=SECRET_COOKIE_VALUE; Path=/")
        if self.path == "/redirect":
            self.send_header("Location", "http://outside.invalid/forbidden")
        self.end_headers()
        body = b'''<html><head><title>Local audit fixture</title></head><body>
        <a href="/about">About</a><a href="/redirect">Redirect</a>
        <a href="/logout">Logout</a><a href="/delete/1">Delete</a>
        <a href="/search?q=SECRET_QUERY_VALUE">Search</a>
        <a href="http://outside.invalid/">Outside</a>
        <form method="POST" action="/submit"><input name="password" type="password" value="SECRET_FORM_VALUE"></form>
        </body></html>'''
        self.wfile.write(body)

    def do_POST(self):
        self.visited.append("POST " + self.path)
        self.send_error(405)

    def log_message(self, *args):
        pass


class WebAuditTests(unittest.TestCase):
    def test_scope_query_and_state_change_guards(self):
        origin = audit._origin("https://example.test/")
        for href in ["https://other.test/", "http://example.test/", "https://example.test:444/", "/x?a=b", "/logout", "/delete/1", "/delete;id=1", "/%64elete/1", "/%2564elete/1", "https://u:p@example.test/", "javascript:alert(1)"]:
            with self.subTest(href=href):
                candidate, reason = audit._crawl_url("https://example.test/", href, origin)
                self.assertIsNone(candidate)
                self.assertTrue(reason)
        self.assertEqual(audit._crawl_url("https://example.test/", "/about#x", origin), ("https://example.test/about", None))
        self.assertEqual(audit._crawl_url("https://example.test/", "https://EXAMPLE.test:443/about", origin), ("https://example.test/about", None))

    def test_passive_scope_allows_default_port_only(self):
        import re
        pattern = audit._origin_pattern("https://example.test:443/")
        self.assertIsNotNone(re.fullmatch(pattern, "https://example.test/"))
        self.assertIsNotNone(re.fullmatch(pattern, "https://example.test:443/path"))
        self.assertIsNone(re.fullmatch(pattern, "https://example.test:444/path"))
        self.assertIsNone(re.fullmatch(pattern, "https://example.test.evil/path"))

    def test_invalid_target_never_starts(self):
        with patch.object(audit.subprocess, "Popen") as popen:
            for target in ["http://example.test/?secret=foo", "example.test;id", "https://example.test/delete/account", "https://u:p@example.test/"]:
                result = audit.run_web_audit(target, Path("/unused"))
                self.assertEqual(result["status"], "blocked")
            popen.assert_not_called()

    def test_forms_record_no_values(self):
        parser = audit._Page("https://example.test/")
        parser.feed('<form action="/submit?key=SECRET"><input name="csrf" value="SECRET"><input name="password" type="password"></form>')
        self.assertFalse(parser.forms[0]["submitted"])
        self.assertNotIn("SECRET", json.dumps(parser.forms))
        self.assertEqual(parser.forms[0]["fields"][1]["type"], "password")

    def test_alerts_redact_values_filter_scope_and_group(self):
        alert = {"pluginId": "10010", "name": "Cookie missing flag", "risk": "Low", "confidence": "Medium", "url": "https://example.test/?token=SECRET", "param": "session", "evidence": "session=SECRET", "attack": "SECRET", "other": "SECRET", "description": "A cookie lacked a flag.", "solution": "Set cookie flags."}
        out = audit._redacted_alerts([alert, dict(alert, url="https://example.test/about"), dict(alert, url="https://outside.test/")], audit._origin("https://example.test/"))
        self.assertEqual(len(out), 2)
        self.assertNotIn("SECRET", json.dumps(out))
        findings = audit._findings(out)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["classification"], "candidate")
        self.assertEqual(len(findings[0]["evidence"]["urls"]), 2)

    def test_missing_zap_crawl_and_redacted_artifacts(self):
        with patch.object(audit.shutil, "which", return_value=None):
            self._fixture_test(real=False)

    def test_passive_classification_keeps_headers_and_banners_separate(self):
        samples = [("10038", "CSP missing", "Medium", "hardening"),
                   ("10021", "Nosniff missing", "Low", "hardening"),
                   ("10036", "Server version banner", "Low", "observation"),
                   ("10109", "Modern application", "Informational", "observation"),
                   ("100202", "Potential missing CSRF token", "Medium", "candidate")]
        for rule, title, risk, expected in samples:
            with self.subTest(rule=rule):
                alerts = audit._redacted_alerts([{"pluginId": rule, "name": title, "risk": risk,
                                                 "url": "https://example.test/"}], audit._origin("https://example.test/"))
                finding = audit._findings(alerts)[0]
                self.assertEqual(finding["classification"], expected)

    def test_zap_start_failure_keeps_crawl(self):
        with patch.object(audit.shutil, "which", return_value="/mock/zap"), patch.object(audit._Zap, "start", side_effect=RuntimeError("Startup failed")):
            self._fixture_test(real=False)

    def test_page_limit_reports_partial(self):
        server, thread = start_fixture()
        try:
            with tempfile.TemporaryDirectory() as temp, patch.object(audit.shutil, "which", return_value=None):
                result = audit.run_web_audit(f"http://127.0.0.1:{server.server_port}/", Path(temp), page_limit=1)
                self.assertEqual(len(result["observations"]["pages"]), 1)
                self.assertGreater(result["observations"]["crawl"]["pending_urls"], 0)
                self.assertTrue(any("page/time limit" in limit for limit in result["limits"]))
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def _fixture_test(self, real):
        server, thread = start_fixture()
        try:
            with tempfile.TemporaryDirectory() as temp:
                result = audit.run_web_audit(f"http://127.0.0.1:{server.server_port}/", Path(temp), timeout=120)
                self.assertEqual(set(Fixture.visited), {"/", "/about", "/redirect"})
                self.assertEqual(len(Fixture.visited), 3)
                self.assertEqual(len(result["observations"]["forms"]), 3)
                self.assertEqual(result["observations"]["crawl"]["pending_urls"], 0)
                if real:
                    print(json.dumps({"status": result["status"], "passive": result["observations"]["passive_analysis"], "findings": len(result["findings"]), "limits": result["limits"]}, indent=2))
                    self.assertEqual(result["observations"]["passive_analysis"]["status"], "complete")
                    self.assertTrue(result["findings"])
                else:
                    self.assertEqual(result["status"], "partial")
                    self.assertEqual(result["observations"]["passive_analysis"]["status"], "blocked")
                for artifact in result["artifacts"]:
                    saved = Path(artifact).read_text()
                    self.assertNotIn("SECRET_COOKIE_VALUE", saved)
                    self.assertNotIn("SECRET_FORM_VALUE", saved)
                    self.assertNotIn("SECRET_QUERY_VALUE", saved)
                    self.assertEqual(os.stat(artifact).st_mode & 0o777, 0o600)
                self.assertFalse(list(Path(temp).glob("*/work")))
        finally:
            server.shutdown(); server.server_close(); thread.join()

    @unittest.skipUnless(os.environ.get("ORCA_TEST_REAL_ZAP") == "1", "Set ORCA_TEST_REAL_ZAP=1 for installed ZAP/local fixture test")
    def test_real_zap_local_fixture(self):
        self._fixture_test(real=True)


def start_fixture():
    Fixture.visited = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


if __name__ == "__main__":
    unittest.main()
