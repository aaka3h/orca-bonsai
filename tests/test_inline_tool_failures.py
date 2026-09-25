#!/usr/bin/env python3
"""Retain command diagnostics when a shell pipeline still exits successfully."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
from orca_task_evidence import TaskEvidence, result_failed


scan = TaskEvidence()
diagnostic = "|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)"
assert result_failed({"exit_code": 0, "stdout": diagnostic})
assert result_failed({"error": "Failed to run tool"})
assert result_failed({"success": False})
assert result_failed({"exit_code": 1})
assert not result_failed({"exit_code": 0, "stdout": "22/tcp open ssh"})
assert not result_failed({"exit_code": 0, "stdout": "<html><pre>" + diagnostic + "</pre></html>"})
assert not result_failed({"success": True, "stdout": diagnostic})
scan.add("run_command", {"command": "nmap --script ssh-hostkey example.test | tail -40"}, {
    "exit_code": 0,
    "stdout": "Verbose setup line\n" * 500 + "22/tcp open ssh\n" + diagnostic + "\n",
    "stderr": "",
})
for index in range(40):
    scan.add("run_command", {"command": f"curl https://example.test/{index}"}, {
        "exit_code": 0, "stdout": "Later page text\n" * 100,
    })

assert scan._records[0]["failed"]
assert "22/tcp open ssh" in scan._records[0]["output"]
for rendered in (scan.progress(), scan.render()):
    assert "partial failure (exit 0)" in rendered, rendered
    assert "ssh-hostkey: ERROR: Script execution failed" in rendered, rendered
for limit in (0, 1, 50, 180, 500, 1100, 8000):
    assert len(scan.progress(limit)) <= limit
    assert len(scan.render(limit)) <= limit

for text in (
    "curl: (60) SSL peer certificate cannot be authenticated with given CA certificates",
    "NSE: failed to initialize the script engine",
    "zsh: command not found: unknown-tool",
    "/bin/bash: line 1: unknown-tool: command not found",
):
    command = TaskEvidence()
    command.add("run_command", {"command": "diagnostic-producing-command | tail"}, {
        "exit_code": 0, "stdout": "Output\n" * 1000, "stderr": text,
    })
    assert command._records[0]["failed"], text
    assert "partial failure" in command.progress(), command.progress()
    assert text in command.render(), command.render()

for text in (
    "A page about an error in deployment and failed requests.",
    "HTTP/1.1 200 OK\nServer: nginx\nThe error page explains a failed login.",
    "<html><title>Error reference</title><main><pre>\n" + diagnostic + "\n</pre></main></html>",
):
    page = TaskEvidence()
    page.add("run_command", {"command": "curl https://example.test/errors"}, {
        "exit_code": 0, "stdout": text,
    })
    assert not page._records[0]["failed"], text
    assert "partial failure" not in page.render(), page.render()

# A browser or fetch tool may quote CLI output as ordinary page content.
page = TaskEvidence()
page.add("fetch_url", {"url": "https://example.test"}, {"success": True, "stdout": diagnostic})
assert not page._records[0]["failed"]

# A nonzero process result already is a full command failure.
failed = TaskEvidence()
failed.add("run_command", {"command": "curl https://example.test"}, {
    "exit_code": 60, "stderr": "curl: (60) SSL certificate problem",
})
assert failed._records[0]["failed"]
assert "partial failure" not in failed.render()
assert "exit 60" in failed.render()

print("Inline command failure evidence checks passed")
