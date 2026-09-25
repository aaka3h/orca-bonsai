"""Regression: Stop cleans orphaned scanner children and preserves other sessions."""
from pathlib import Path
import json
import os
import select
import signal
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "outputs"))
import orca_gui as gui


class StopTests(unittest.TestCase):
    def test_orphan_ignoring_signals_is_killed_and_other_session_survives(self):
        child = "import os,signal,time;signal.signal(signal.SIGINT,signal.SIG_IGN);signal.signal(signal.SIGTERM,signal.SIG_IGN);print('child '+str(os.getpid()),flush=True);time.sleep(30)"
        parent = "import os,signal,subprocess,sys,time;signal.signal(signal.SIGINT,lambda *args:sys.exit(0));subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);print('parent '+str(os.getpid()),flush=True);time.sleep(30)"
        backend = subprocess.Popen([sys.executable, "-c", parent], stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        detached = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        descriptor = None
        worker = None
        try:
            lines = [backend.stdout.readline().strip(), backend.stdout.readline().strip()]
            child_pid = next(int(line.split()[1]) for line in lines if line.startswith("child "))
            descriptor = os.pidfd_open(child_pid)
            os.killpg(backend.pid, signal.SIGINT)
            backend.wait(timeout=3)
            self.assertEqual(select.select([descriptor], [], [], .05)[0], [])
            # The parent is already gone, precisely the former failure mode.
            worker = gui._schedule_group_cleanup(backend.pid, grace_seconds=.05, kill_seconds=.1)
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertTrue(select.select([descriptor], [], [], 3)[0], "SIGKILL did not stop the stubborn child")
            self.assertIsNone(detached.poll(), "A detached model-like session was incorrectly stopped")
        finally:
            for process in (backend, detached):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
            if backend.stdout:
                backend.stdout.close()
            if descriptor is not None:
                os.close(descriptor)
            if worker:
                worker.join(timeout=3)

    def test_cleanup_rejects_gui_group(self):
        with patch.object(gui.os, "killpg") as killpg:
            self.assertIsNone(gui._schedule_group_cleanup(os.getpgrp(), 0, 0))
            self.assertIsNone(gui._schedule_group_cleanup(1, 0, 0))
            killpg.assert_not_called()

    def test_stop_schedules_captured_group_before_parent_signal(self):
        window = Mock()
        window._busy = True
        window._stopping = False
        window._process = Mock(pid=123456)
        calls = []
        def signal_then_exit(sig):
            calls.append(("signal", sig))
            window._process = None
        window._signal_process.side_effect = signal_then_exit
        with patch.object(gui, "_schedule_group_cleanup", side_effect=lambda pgid: calls.append(("schedule", pgid))):
            gui.OrcaWindow.stop_task(window)
        self.assertEqual(calls, [("schedule", 123456), ("signal", signal.SIGINT)])
        self.assertTrue(window._restart_after_exit)


if __name__ == "__main__":
    unittest.main()
