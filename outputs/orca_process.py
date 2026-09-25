"""Bounded command capture with timeout diagnostics and local child cleanup."""
from __future__ import annotations

import codecs
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

from orca_terminal_text import sanitize_terminal_text, extract_cli_errors


class _Capture:
    def __init__(self, limit=131072):
        self.limit = limit
        self.head = ""
        self.tail = ""
        self.total = 0
        self.decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')

    def add(self, raw, final=False):
        text = self.decoder.decode(raw, final=final)
        self.total += len(text)
        remaining = self.limit // 2 - len(self.head)
        if remaining > 0:
            self.head += text[:remaining]
            text = text[remaining:]
        self.tail = (self.tail + text)[-self.limit // 2:]

    def text(self):
        gap = '\n[Middle output omitted]\n' if self.total > self.limit else ''
        return sanitize_terminal_text(self.head + gap + self.tail)


def _terminate_tree(process):
    """Stop this command's current descendants without signalling our own group.

    Commands keep the agent's group so GUI Stop also reaches them. Linux pidfds
    keep timeout cleanup from accidentally signalling a recycled process ID.
    """
    # Once the leader has exited, reparented children cannot be identified safely
    # from its former PID. In particular never reopen a reaped, reusable PID.
    if process.poll() is not None:
        return False
    pids, pending, handles = [], [process.pid], []
    seen = set()
    try:
        while pending and len(seen) < 1024:
            pid = pending.pop()
            if pid in seen or pid == os.getpid():
                continue
            seen.add(pid)
            try:
                descriptor = os.pidfd_open(pid)
            except OSError:
                continue
            handles.append(descriptor)
            pids.append((pid, descriptor))
            try:
                for task in (Path('/proc') / str(pid) / 'task').iterdir():
                    try:
                        pending.extend(int(value) for value in (task / 'children').read_text().split())
                    except (OSError, ValueError):
                        pass
            except OSError:
                pass
        for sig in (signal.SIGTERM, signal.SIGKILL):
            for _, descriptor in reversed(pids):
                try:
                    signal.pidfd_send_signal(descriptor, sig)
                except (OSError, ProcessLookupError):
                    pass
            if sig == signal.SIGTERM:
                time.sleep(.15)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
    finally:
        for descriptor in handles:
            os.close(descriptor)
    return True


def _excerpt(text, limit):
    if len(text) <= limit:
        return text
    marker = '\n[Output shortened; beginning and end shown]\n'
    budget = limit - len(marker)
    return text[:budget * 2 // 3] + marker + text[-(budget - budget * 2 // 3):]


def run_process(argv, cwd=None, timeout=60, env=None):
    process = None
    output, errors = _Capture(), _Capture()
    streams = {}
    timed_out = False
    cleanup_attempted = False
    timeout = max(1, min(int(timeout), 3600))
    try:
        process = subprocess.Popen(argv, cwd=str(Path(cwd).expanduser().resolve()) if cwd else None,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        deadline = time.monotonic() + timeout
        with selectors.DefaultSelector() as selector:
            for stream, capture in ((process.stdout, output), (process.stderr, errors)):
                os.set_blocking(stream.fileno(), False)
                streams[stream] = capture
                selector.register(stream, selectors.EVENT_READ, capture)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    cleanup_attempted = _terminate_tree(process)
                    # Pipes can remain held by separately detached programs. Only
                    # drain data already available, then return the timeout.
                    for stream, capture in list(streams.items()):
                        for _ in range(32):
                            try:
                                chunk = os.read(stream.fileno(), 16384)
                            except (BlockingIOError, OSError):
                                break
                            if not chunk:
                                break
                            capture.add(chunk)
                    break
                for key, _ in selector.select(min(.1, remaining)):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 16384)
                    except BlockingIOError:
                        continue
                    if chunk:
                        key.data.add(chunk)
                    else:
                        selector.unregister(key.fileobj)
                if not selector.get_map() and process.poll() is None:
                    time.sleep(min(.03, remaining))
        output.add(b'', final=True)
        errors.add(b'', final=True)
        stdout, stderr = output.text(), errors.text()
        # Inspect retained text before narrowing it for the model. This is
        # heuristic and cannot identify every tool's application-level failure.
        diagnostics = list(dict.fromkeys(extract_cli_errors(stdout) + extract_cli_errors(stderr)))[:16]
        result = {
            'exit_code': process.poll(),
            'stdout': _excerpt(stdout, 4500),
            'stderr': _excerpt(stderr, 1600),
        }
        if diagnostics:
            result['diagnostics'] = diagnostics
        if output.total > 4500 or errors.total > 1600:
            result['output_truncated'] = True
        if timed_out:
            result.update(timed_out=True, error=f'Command timed out after {timeout} seconds',
                          cleanup_status='attempted' if cleanup_attempted else 'incomplete',
                          note='Partial output retained; completion is not confirmed. '
                          + ('Cleanup signalled the command and its currently discoverable children.' if cleanup_attempted
                             else 'The command leader already exited; processes holding its output pipes could not be identified safely.'))
        return result
    except BaseException as exc:
        if process is not None:
            _terminate_tree(process)
        if not isinstance(exc, Exception):
            raise
        return {'error': f'{type(exc).__name__}: {exc}'}
    finally:
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream:
                    stream.close()
