"""Opt-in isolated producer smoke for the real remote probe.

This test uses only the private loopback sshd and private tmux server supplied by
Yoohoo's integration fixture.  It never reads or changes the user's SSH files.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import selectors
import shlex
import subprocess
import sys
import time
from typing import Mapping, Sequence
import unittest

from agent_window_resolver.collector import CommandResult, Deadline
from agent_window_resolver.linux import LinuxCollector, _REMOTE_PROBE
from agent_window_resolver.model import (
    Limits,
    ProcessIdentity,
    Request,
    Target,
    TmuxLocation,
)


_FIXTURE_MODULE_DIR = (
    Path(__file__).resolve().parents[3]
    / "yoohoo-hub-work"
    / "tests"
    / "integration"
)
if str(_FIXTURE_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_FIXTURE_MODULE_DIR))

from connection_fixture import (  # noqa: E402
    ConnectionFixture,
    PrivatePaneSnapshot,
    SetupCommand,
    live_test_authorized,
)


_TARGET_MACHINE = "private-fixture-target.invalid"
_LOCAL_MACHINE = "plumbus"


def _request_and_remote(snapshot: PrivatePaneSnapshot) -> tuple[Request, str]:
    request = Request(
        "private-producer-smoke",
        "verify-target",
        None,
        Target(
            ProcessIdentity(
                _TARGET_MACHINE,
                snapshot.pane_pid,
                str(snapshot.pane_start_ticks),
            ),
            "private-fixture-agent",
            TmuxLocation(
                snapshot.session,
                snapshot.window_index,
                snapshot.pane_id,
                None,
            ),
        ),
        _LOCAL_MACHINE,
        (),
        None,
        Limits(deadline_ms=20_000),
    )
    config = {
        "pid": request.target.identity.pid,
        "session": request.target.tmux.session,
        "windowIndex": request.target.tmux.window_index,
        "paneId": request.target.tmux.pane_id,
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(config, separators=(",", ":")).encode()
    ).decode().rstrip("=")
    remote = shlex.join(["python3", "-c", _REMOTE_PROBE, payload])
    return request, remote


class TrackedFixtureProbeIO:
    """Allow exactly one LinuxCollector SSH producer shape into the fixture."""

    def __init__(self, fixture: ConnectionFixture) -> None:
        self.fixture = fixture

    def read_bytes(self, path: str, max_bytes: int) -> bytes:
        raise AssertionError("remote producer smoke attempted local proc read")

    def readlink(self, path: str, max_chars: int) -> str:
        raise AssertionError("remote producer smoke attempted local link read")

    def listdir(self, path: str, max_entries: int) -> tuple[str, ...]:
        raise AssertionError("remote producer smoke attempted local directory read")

    def monotonic(self) -> float:
        return time.monotonic()

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_stdout: int,
        max_stderr: int,
        env: Mapping[str, str],
    ) -> CommandResult:
        expected_prefix = [
            "/usr/bin/ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=5",
            "-o", "ControlMaster=no",
            "-o", "ControlPath=none",
            "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no",
            "-T", "--", _TARGET_MACHINE,
        ]
        values = list(argv)
        if len(values) != len(expected_prefix) + 1:
            raise AssertionError("collector SSH argv had unexpected cardinality")
        if values[:-1] != expected_prefix:
            raise AssertionError("collector SSH prefix escaped the exact allowlist")
        remote = values[-1]
        actual = self.fixture.ssh_argv(remote, interactive=False)
        if timeout <= 0:
            return CommandResult(124, b"", b"", timed_out=True)

        process = subprocess.Popen(
            actual,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=dict(env),
        )
        try:
            identity = self.fixture.track_ssh_client(process, actual)
        except BaseException as error:
            if process.poll() is None:
                try:
                    process.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    raise RuntimeError(
                        "SSH tracking failed while the live process was preserved"
                    ) from error
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
            raise

        assert process.stdout is not None and process.stderr is not None
        streams = {
            process.stdout.fileno(): ("stdout", process.stdout),
            process.stderr.fileno(): ("stderr", process.stderr),
        }
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        limits = {"stdout": max_stdout, "stderr": max_stderr}
        selector = selectors.DefaultSelector()
        deadline = time.monotonic() + timeout
        timed_out = False
        truncated = False
        try:
            for fd, (_, stream) in streams.items():
                os.set_blocking(fd, False)
                selector.register(stream, selectors.EVENT_READ, fd)
            open_fds = set(streams)
            while open_fds:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                events = selector.select(remaining)
                if not events:
                    timed_out = True
                    break
                for key, _ in events:
                    fd = key.data
                    name, stream = streams[fd]
                    try:
                        chunk = os.read(fd, 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        open_fds.discard(fd)
                        continue
                    buffer = buffers[name]
                    room = limits[name] + 1 - len(buffer)
                    if room > 0:
                        buffer.extend(chunk[:room])
                    if len(buffer) > limits[name] or len(chunk) > room:
                        truncated = True
                        open_fds.clear()
                        break
        finally:
            selector.close()
            try:
                status = self.fixture.stop_ssh_client(process, identity)
            finally:
                process.stdout.close()
                process.stderr.close()

        return CommandResult(
            status,
            bytes(buffers["stdout"][:max_stdout]),
            bytes(buffers["stderr"][:max_stderr]),
            timed_out=timed_out,
            truncated=truncated,
        )


@unittest.skipUnless(
    live_test_authorized(),
    "private producer smoke requires the fixture's explicit Plumbus opt-in",
)
class PrivateProducerSmokeTests(unittest.TestCase):
    def test_real_remote_probe_discovers_then_pins_private_tmux_socket(self) -> None:
        prepared: dict[str, object] = {}

        def command_factory(snapshot: PrivatePaneSnapshot) -> tuple[SetupCommand, ...]:
            request, remote = _request_and_remote(snapshot)
            prepared["request"] = request
            prepared["snapshot"] = snapshot
            return (SetupCommand(remote, original_command=remote),)

        fixture = ConnectionFixture(command_factory=command_factory)
        with fixture:
            request = prepared["request"]
            snapshot = prepared["snapshot"]
            assert isinstance(request, Request)
            assert isinstance(snapshot, PrivatePaneSnapshot)
            collector = LinuxCollector(
                TrackedFixtureProbeIO(fixture),
                ssh="/usr/bin/ssh",
                python="python3",
            )
            observation = collector._target_probe(
                request,
                Deadline(request.limits.deadline_ms),
            )

            self.assertEqual(observation.collection_state, "complete")
            self.assertEqual(observation.machine, _TARGET_MACHINE)
            self.assertEqual(observation.actual_socket_path, str(snapshot.socket_path))
            self.assertEqual(observation.socket.kind, "path")
            self.assertEqual(observation.socket.value, str(snapshot.socket_path))
            self.assertEqual(observation.pane.session, snapshot.session)
            self.assertEqual(observation.pane.window_index, snapshot.window_index)
            self.assertEqual(observation.pane.pane_id, snapshot.pane_id)
            self.assertEqual(observation.pane.process.pid, snapshot.pane_pid)
            self.assertTrue(any(
                node.identity == request.target.identity
                for node in observation.processes
            ))


if __name__ == "__main__":
    unittest.main()
