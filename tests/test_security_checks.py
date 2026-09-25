import json
import ssl
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_security_checks as security


class Response:
    def __init__(self, *, status=200, headers=None, body=b"<html><title>Fixture</title></html>", chunks=None):
        self.status_code = status
        self.headers = headers if headers is not None else {"Content-Type": "text/html"}
        self.encoding = "utf-8"
        self.chunks = chunks if chunks is not None else [body]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def iter_content(self, chunk_size):
        yield from self.chunks


def nmap_xml(*, tail=True, timeout=False, name="http", product="nginx", version="1.2.3"):
    body = ('<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host' + (' timedout="true"' if timeout else '') + '>'
            '<status state="up"/><ports><port protocol="tcp" portid="80"><state state="open"/>'
            f'<service name="{name}" product="{product}" version="{version}"/></port>'
            '<port protocol="tcp" portid="443"><state state="closed"/></port></ports></host>')
    return body + ('<runstats><finished exit="success"/></runstats></nmaprun>' if tail else '')


class ScopeTests(unittest.TestCase):
    def test_rejects_multitargets_credentials_networks_and_shell_syntax(self):
        invalid = ["", None, ["example.test"], "a.test b.test", "a.test\nb.test", "192.0.2.0/24",
                   "https://user:password@example.test", "*.example.test", "a.test;id", "a.test|id",
                   "$(id).test", "a.test`id`", "a.test&whoami", "--script", "https://[::1]:0",
                   "https://example.test:65536", "https://example.test:abc", "ftp://example.test",
                   "https://a.test\\b.test", "a.test,b.test", "https://a.test\t", "127.1.2.999",
                   "2001:db8::1%eth0", "https://[::1%eth0]", "https:///a.test", "a.test/path", "a.test:123",
                   "192.0.2.1-5", "1-3.2.3.4", "1-3"]
        with patch.object(security.requests, "get") as get, patch.object(security.subprocess, "run") as run:
            for target in invalid:
                with self.subTest(target=target):
                    self.assertEqual(security.security_check(target)["check_status"], "error")
            get.assert_not_called()
            run.assert_not_called()

    def test_idna_ipv6_and_explicit_port(self):
        self.assertEqual(security._parse_target("https://BÜCHER.example:8443/a").host, "xn--bcher-kva.example")
        self.assertEqual(security._parse_target("2001:db8::1").url, "https://[2001:db8::1]/")
        ipv6 = security._parse_target("https://[::1]:8443/path")
        self.assertTrue(ipv6.ipv6)
        self.assertEqual(security._ports(None, ipv6), [8443])
        self.assertEqual(security._parse_target("EXAMPLE.test.").host, "example.test")

    def test_strict_ports_and_check_enum(self):
        for ports in ["1-65535", "80;id", "80,443,", "0", "65536", "80, 443", "80\n443", 443,
                      ",".join(str(port) for port in range(1, 18))]:
            with self.subTest(ports=ports):
                self.assertEqual(security.security_check("example.test", "services", ports)["check_status"], "error")
        self.assertEqual(security._ports("80,80,443", security._parse_target("example.test")), [80, 443])
        self.assertEqual(security.security_check("example.test", "web", "80")["check_status"], "error")
        self.assertEqual(security.security_check("example.test", "exploit")["check_status"], "error")


class WebTests(unittest.TestCase):
    def test_missing_headers_are_hardening_observations(self):
        with patch.object(security.requests, "get", return_value=Response()) as get:
            result = security.security_check("https://example.test")
        self.assertEqual(result["check_status"], "complete")
        self.assertEqual({item["id"] for item in result["findings"]},
                         {"missing-hsts", "missing-csp", "missing-frame-policy", "missing-nosniff"})
        self.assertTrue(all(item["classification"] == "hardening" for item in result["findings"]))
        self.assertEqual(result["evidence"]["title"], "Fixture")
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        self.assertTrue(get.call_args.kwargs["stream"])

    def test_cookie_values_not_preserved_and_existing_headers_recognized(self):
        headers = {"content-type": "text/html", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                   "Strict-Transport-Security": "max-age=1000", "X-Content-Type-Options": "nosniff",
                   "Set-Cookie": "password=TOPSECRET", "Cookie": "session=TOPSECRET"}
        with patch.object(security.requests, "get", return_value=Response(headers=headers)):
            result = security.security_check("https://example.test")
        self.assertEqual(result["findings"], [])
        self.assertNotIn("TOPSECRET", json.dumps(result))

    def test_http_has_no_hsts_finding_and_json_no_document_findings(self):
        with patch.object(security.requests, "get", return_value=Response(headers={"Content-Type": "application/json"}, body=b"{}")):
            result = security.security_check("http://example.test")
        self.assertEqual(result["findings"], [])

    def test_redirect_outside_exact_host_never_followed(self):
        for location, expected in [("https://other.test/a", False), ("https://sub.example.test", False),
                                   ("/new", True), ("https://EXAMPLE.test/", True)]:
            with self.subTest(location=location):
                response = Response(status=302, headers={"Location": location})
                with patch.object(security.requests, "get", return_value=response) as get:
                    result = security.security_check("https://example.test")
                self.assertEqual(result["evidence"]["redirect"]["same_hostname"], expected)
                self.assertFalse(result["evidence"]["redirect"]["followed"])
                self.assertEqual(get.call_count, 1)

    def test_credential_bearing_redirect_omitted(self):
        with patch.object(security.requests, "get", return_value=Response(status=302, headers={"Location": "https://user:SECRET@example.test"})):
            result = security.security_check("example.test")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertFalse(result["evidence"]["redirect"]["followed"])

    def test_long_redirect_not_silently_cut_and_no_redirect_header_findings(self):
        with patch.object(security.requests, "get", return_value=Response(status=302, headers={
                "Content-Type": "text/html", "Location": "https://example.test/" + "a" * 600})):
            result = security.security_check("example.test")
        self.assertNotIn("url", result["evidence"]["redirect"])
        self.assertIn("omitted", result["evidence"]["redirect"]["note"])
        self.assertEqual(result["findings"], [])

    def test_elapsed_read_limit(self):
        with patch.object(security.requests, "get", return_value=Response()), \
                patch.object(security.time, "monotonic", side_effect=[0, 21]):
            result = security.security_check("example.test")
        self.assertEqual(result["check_status"], "partial")
        self.assertTrue(result["evidence"]["body_truncated"])
        self.assertIn("20-second", result["error"])

    def test_bounded_body_and_http_error_partial(self):
        response = Response(status=403, chunks=[b"x" * security._MAX_BODY, b"OVERLIMIT"])
        with patch.object(security.requests, "get", return_value=response):
            result = security.security_check("http://example.test")
        self.assertTrue(result["evidence"]["body_truncated"])
        self.assertEqual(result["check_status"], "partial")
        self.assertIn("error response only", result["error"])

    def test_tls_fetch_failure_does_not_claim_missing_headers(self):
        with patch.object(security.requests, "get", side_effect=security.requests.exceptions.SSLError("expired")):
            result = security.security_check("example.test")
        self.assertEqual(result["check_status"], "error")
        self.assertEqual(result["findings"], [])


class TlsTests(unittest.TestCase):
    def test_failed_certificate_reports_reason_not_server_configuration_certainty(self):
        exc = ssl.SSLCertVerificationError(1, "certificate verify failed")
        exc.verify_code, exc.verify_message = 10, "certificate has expired"
        context = MagicMock()
        context.wrap_socket.side_effect = exc
        with patch.object(security.ssl, "create_default_context", return_value=context), patch.object(security.socket, "create_connection"):
            result = security.security_check("https://example.test:8443", "tls")
        self.assertEqual(result["check_status"], "complete")
        self.assertNotIn("error", result)
        self.assertIn("trust store", result["validation_result"])
        self.assertEqual(result["evidence"]["verify_code"], 10)
        self.assertIn("expired", result["findings"][0]["evidence"])
        self.assertEqual(result["findings"][0]["classification"], "configuration")
        self.assertFalse(result["evidence"]["certificate_verified"])

    def test_successful_handshake_only_claims_negotiated_version(self):
        context = MagicMock()
        secure = context.wrap_socket.return_value.__enter__.return_value
        secure.version.return_value = "TLSv1.3"
        secure.getpeercert.return_value = {"subject": ((("commonName", "example.test"),),),
                                         "issuer": ((("commonName", "Fixture CA"),),),
                                         "notBefore": "Jan 1 00:00:00 2026 GMT", "notAfter": "Jan 1 00:00:00 2027 GMT"}
        with patch.object(security.ssl, "create_default_context", return_value=context), patch.object(security.socket, "create_connection") as connect:
            result = security.security_check("example.test", "tls")
        self.assertEqual(result["evidence"]["negotiated_version"], "TLSv1.3")
        self.assertEqual(connect.call_args.args[0], ("example.test", 443))
        self.assertIn("not an enumeration", result["limits"])
        self.assertEqual(result["findings"], [])


class ServicesTests(unittest.TestCase):
    def invoke(self, completed=None, target="https://example.test:80", ports=None, error=None):
        with patch.object(security.shutil, "which", return_value="/usr/bin/nmap"), \
                patch.object(security.subprocess, "run", return_value=completed, side_effect=error) as run:
            result = security.security_check(target, "services", ports)
        return result, run

    def test_fixed_command_safe_arguments_and_port_defaults(self):
        result, run = self.invoke(SimpleNamespace(stdout=nmap_xml(), stderr="", returncode=0))
        argv = run.call_args.args[0]
        self.assertEqual(argv[-1], "example.test")
        self.assertEqual(argv[argv.index("-p") + 1], "80")
        self.assertIn("-sT", argv)
        self.assertIn("--version-light", argv)
        self.assertNotIn("--script", argv)
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["timeout"], 60)
        self.assertEqual(result["check_status"], "complete")
        self.assertEqual(result["evidence"]["open_services"], [{"port": 80, "state": "open", "name": "http", "product": "nginx", "version": "1.2.3"}])
        self.assertEqual(result["findings"], [])

    def test_ipv6_flag(self):
        _, run = self.invoke(SimpleNamespace(stdout=nmap_xml(), stderr="", returncode=0), target="::1")
        self.assertIn("-6", run.call_args.args[0])
        self.assertEqual(run.call_args.args[0][-1], "::1")

    def test_timeout_preserves_complete_ports_and_marks_partial(self):
        error = subprocess.TimeoutExpired("nmap", 60, output=nmap_xml(tail=False).encode())
        result, _ = self.invoke(error=error)
        self.assertEqual(result["check_status"], "partial")
        self.assertEqual(result["evidence"]["open_services"][0]["port"], 80)
        self.assertIn("terminated", result["error"])

    def test_host_timeout_not_clean_completion(self):
        result, _ = self.invoke(SimpleNamespace(stdout=nmap_xml(timeout=True), stderr="", returncode=0))
        self.assertEqual(result["check_status"], "partial")
        self.assertIn("host timeout", result["error"])

    def test_malformed_and_failure_output(self):
        for xml in ["garbage", "<html></html>", "", '<!DOCTYPE nmaprun [<!ENTITY x "boom">]><nmaprun/>']:
            with self.subTest(xml=xml):
                result, _ = self.invoke(SimpleNamespace(stdout=xml, stderr="Error: failed to resolve", returncode=1))
                self.assertEqual(result["check_status"], "error")
                self.assertEqual(result["evidence"]["open_services"], [])
                self.assertIn("failed", result["error"])

    def test_missing_tool_no_install(self):
        with patch.object(security.shutil, "which", return_value=None), patch.object(security.subprocess, "run") as run:
            result = security.security_check("example.test", "services")
        self.assertEqual(result["check_status"], "error")
        run.assert_not_called()

    def test_no_root_execution(self):
        with patch.object(security.os, "geteuid", return_value=0), patch.object(security.subprocess, "run") as run:
            result = security.security_check("example.test", "services")
        self.assertEqual(result["check_status"], "error")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
