#!/usr/bin/env python3
"""Focused checks for preserving tool evidence through bounded summaries."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
from orca_task_evidence import TaskEvidence


evidence = TaskEvidence()
assert not evidence
evidence.add("run_command", {"command": "whoami"}, {"exit_code": 0, "stdout": "kali"})
evidence.add("run_command", {"command": "nmap example.test"}, {
    "exit_code": 0,
    "stdout": "Verbose scan setup\n" * 1000 + "22/tcp open ssh\n80/tcp open http\n443/tcp open https\n",
})
evidence.add("run_command", {"command": "whois example.test"}, {
    "exit_code": 0,
    "stdout": "WHOIS boilerplate\n" * 100 + "Domain Name: EXAMPLE.TEST\nRegistrar: Example Registrar\n",
})
evidence.add("run_command", {"command": "dig example.test"}, {"exit_code": 0, "stdout": "192.0.2.15\nns.example.test.\n"})
evidence.add("run_command", {"command": "curl https://example.test"}, {
    "exit_code": 0,
    "stdout": "<!doctype html><html><head><title>Example title</title><style>.bad { hidden: true }</style></head><body><nav>navigation spam</nav><main><h1>Important fact</h1><p>Main text</p><script>hiddenScript()</script></main></body></html>",
})
for i in range(150):
    evidence.add("run_command", {"command": f"curl https://example.test/{i}"}, {"exit_code": 0, "stdout": (f"Unhelpful verbose output {i}\n" * 200)})
evidence.add("run_command", {"command": "openssl s_client -connect example.test:443"}, {"exit_code": 1, "stderr": "TLS late failure: connection refused"})
assert evidence
assert len(evidence._records) == 128
assert all(len(item["output"]) <= 1800 for item in evidence._records)

for render in (evidence.render(), evidence.progress()):
    assert "22/tcp open ssh" in render, render
    assert "80/tcp open http" in render, render
    assert "443/tcp open https" in render, render
    assert "EXAMPLE.TEST" in render, render
    assert "192.0.2.15" in render, render
    assert "TLS late failure" in render, render
    assert "untrusted data" in render, render
    assert "omitted" in render, render
assert len(evidence.progress()) <= 1100
for limit in (0, 1, 7, 30, 100, 180, 500, 1100, 8000):
    assert len(evidence.render(limit)) <= limit
    assert len(evidence.progress(limit)) <= limit

html_evidence = TaskEvidence()
html_result = {"exit_code": 0, "stdout": "<html><title>Title sentinel</title><nav>navigation noise</nav><main><h1>Main sentinel</h1><script>hidden sentinel</script><p>Useful words</p></main></html>"}
html_evidence.add("run_command", {"command": "curl https://example.test"}, html_result)
assert "Title sentinel" in html_evidence.render()
assert "Main sentinel" in html_evidence.render()
assert "navigation noise" not in html_evidence.render()
assert "hidden sentinel" not in html_evidence.render()
before = html_evidence.render()
html_result["stdout"] = "mutated source"
assert html_evidence.render() == before
html_evidence.add("run_command", {}, {"exit_code": 0, "stdout": "cached sentinel"}, cached=True)
assert html_evidence.render() == before

http = TaskEvidence()
http.add("run_command", {"command": "curl -I https://example.test"}, {"exit_code": 0, "stdout": "Verbose text\n" * 200 + "HTTP/1.1 301 Moved Permanently\nServer: nginx\nLocation: https://example.test/\n"})
assert "HTTP/1.1 301" in http.progress()
assert "Server: nginx" in http.progress()
assert "Location: https://example.test/" in http.progress()

# Replay-shaped case: scan metadata precedes port rows and 37 later outputs
# compete for final-summary room. Port findings must appear in a short excerpt.
replay = TaskEvidence()
replay.add("run_command", {"command": "nmap -sV -p- --open -oN /tmp/scan.txt example.test 2>&1 | tail -40", "timeout_seconds": 300}, {
    "exit_code": 0,
    "stdout": "Starting Nmap 7.99 at 2026-09-23\nNmap scan report for example.test (192.0.2.15)\nHost is up (0.039s latency).\nrDNS record for 192.0.2.15: server.example.test\nNot shown: 65532 filtered tcp ports (no-response)\nSome closed ports may be reported as filtered due to --defeat-rst-ratelimit\nPORT STATE SERVICE VERSION\n22/tcp open tcpwrapped\n80/tcp open http nginx 1.28.3 (Ubuntu)\n443/tcp open ssl/http nginx\nService Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n" + "Scan footer information\n" * 20,
})
for i in range(36):
    replay.add("run_command", {"command": f"curl -sk https://example.test/page{i}.html 2>&1 | head -100"}, {"exit_code": 0, "stdout": "Later output\n" * 400})
replay.add("run_command", {"command": "openssl s_client example.test"}, {"exit_code": 1, "stderr": "Late TLS failure"})
summary = replay.render(8000)
for port in ("22/tcp", "80/tcp", "443/tcp"):
    assert port in summary, summary[:700]
assert "Late TLS failure" in summary
assert len(summary) <= 8000
print("TaskEvidence checks passed")
