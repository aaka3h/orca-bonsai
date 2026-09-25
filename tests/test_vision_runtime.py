"""Focused lifecycle, privacy and response-contract checks for local vision."""
from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "outputs"))
from orca_vision_runtime import VisionError, VisionRuntime
from setup_orca_vision import verify_file


class FakeProcess:
    def __init__(self):
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.model = self.directory / "test-model.gguf"
        self.projector = self.directory / "test-projector.gguf"
        self.model.write_bytes(b"GGUF" + b"x" * 2000)
        self.projector.write_bytes(b"GGUF" + b"x" * 2000)
        self.runtime = VisionRuntime(model_path=self.model, projector_path=self.projector,
                                     server_path=sys.executable, runtime_dir=self.directory / "run")

    def tearDown(self):
        self.runtime.close()
        self.temp.cleanup()

    def responses(self, method, path, **kwargs):
        if path == "/health":
            return {"status": "ok"}
        if path == "/v1/models":
            return {"data": [{"id": self.runtime._alias}],
                    "models": [{"name": self.runtime._alias, "capabilities": ["completion", "multimodal"]}]}
        if path == "/props":
            return {"model_alias": self.runtime._alias, "modalities": {"vision": True}}
        if path == "/v1/chat/completions":
            self.assertTrue(kwargs["payload"]["messages"][-1]["content"][0]["image_url"]["url"].startswith("data:image/jpeg;base64,"))
            return {"choices": [{"message": {"content": "A test scene."}, "finish_reason": "length"}]}
        raise AssertionError(path)

    def test_private_cpu_server_is_reused_then_owned_process_is_stopped(self):
        process = FakeProcess()
        with patch("orca_vision_runtime.subprocess.Popen", return_value=process) as spawn, \
             patch.object(self.runtime, "_request_json", side_effect=self.responses), \
             patch.dict(os.environ, {"LLAMA_ARG_HF_REPO": "unexpected/remote", "LLAMA_API_KEY": "inherited-key"}):
            with self.runtime:
                one = self.runtime.describe_image(b"\xff\xd8\xffexample", "What is visible?")
                self.runtime.describe_image(b"\xff\xd8\xffexample", "What is visible?")
                session_dir = self.runtime._session_dir
                self.assertEqual((session_dir / "api-key").stat().st_mode & 0o777, 0o600)
                self.assertEqual(session_dir.stat().st_mode & 0o777, 0o700)
                self.assertEqual(one["finish_reason"], "length")
                self.assertEqual(spawn.call_count, 1)
                command = spawn.call_args.args[0]
                self.assertEqual(command[command.index("--host") + 1], "127.0.0.1")
                self.assertEqual(command[command.index("--n-gpu-layers") + 1], "0")
                self.assertIn("--no-mmproj-offload", command)
                self.assertNotIn(self.runtime._key, command)
                self.assertFalse(spawn.call_args.kwargs["start_new_session"])
                self.assertNotIn("LLAMA_ARG_HF_REPO", spawn.call_args.kwargs["env"])
                self.assertNotIn("LLAMA_API_KEY", spawn.call_args.kwargs["env"])
                self.assertEqual(spawn.call_args.kwargs["env"]["CUDA_VISIBLE_DEVICES"], "")
            self.assertTrue(process.terminated)
            self.assertFalse(session_dir.exists())

    def test_mismatched_service_is_rejected_and_only_owned_process_stopped(self):
        process = FakeProcess()
        def respond(method, path, **kwargs):
            if path == "/v1/models":
                return {"data": [{"id": "unrelated-server"}], "models": []}
            return self.responses(method, path, **kwargs)
        with patch("orca_vision_runtime.subprocess.Popen", return_value=process), \
             patch.object(self.runtime, "_request_json", side_effect=respond):
            with self.assertRaisesRegex(VisionError, "identity"):
                self.runtime.start()
        self.assertTrue(process.terminated)
        self.assertFalse(list((self.directory / "run").glob("session-*")))

    def test_timeout_releases_server(self):
        process = FakeProcess()
        def respond(method, path, **kwargs):
            if method == "POST":
                raise socket.timeout()
            return self.responses(method, path, **kwargs)
        with patch("orca_vision_runtime.subprocess.Popen", return_value=process), \
             patch.object(self.runtime, "_request_json", side_effect=respond):
            with self.assertRaisesRegex(VisionError, "exceeded"):
                self.runtime.describe_image(b"\xff\xd8\xffexample", "Describe the image.")
        self.assertTrue(process.terminated)
        self.assertIsNone(self.runtime._session_dir)

    def test_inputs_are_rejected_before_server_start(self):
        with patch("orca_vision_runtime.subprocess.Popen") as spawn:
            for image, prompt in [(b"not jpeg", "Describe"), (b"\xff\xd8\xff", ""), (b"\xff\xd8\xff", "x" * 12001)]:
                with self.assertRaises(VisionError):
                    self.runtime.describe_image(image, prompt)
            spawn.assert_not_called()

    def test_model_integrity_check_detects_changed_content(self):
        import hashlib
        expected = {"size": self.model.stat().st_size, "sha256": hashlib.sha256(self.model.read_bytes()).hexdigest()}
        self.assertTrue(verify_file(self.model, expected))
        self.model.write_bytes(b"GGUF" + b"z" * 2000)
        self.assertFalse(verify_file(self.model, expected))

    def test_loopback_http_does_not_follow_redirects_or_use_proxy(self):
        received = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(handler):
                received.append((handler.path, handler.headers.get("Authorization")))
                handler.send_response(302)
                handler.send_header("Location", "http://example.invalid/never-contact-this")
                handler.end_headers()
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.runtime._port = server.server_port
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict(os.environ, {"HTTP_PROXY": "http://example.invalid:1234"}):
                with self.assertRaisesRegex(VisionError, "HTTP 302"):
                    self.runtime._request_json("GET", "/health", timeout=2)
            self.assertEqual(received, [("/health", "Bearer " + self.runtime._key)])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
