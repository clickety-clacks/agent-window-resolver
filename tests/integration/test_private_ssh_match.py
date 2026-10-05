"""Opt-in private SSH-to-tmux matcher smoke with a synthetic window root.

This proves the real local proc collector, real remote producer, endpoint reversal,
tmux visibility, and resolver cardinality. The SSH client PID is deliberately
used as a synthetic window root; Ghostty/Hyprland ancestry is a later gate.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path, PurePosixPath
import shlex
import sys
import unittest

from agent_window_resolver import Resolver, Window
from agent_window_resolver.linux import DefaultProbeIO, LinuxCollector
from agent_window_resolver.model import Limits, Request


_SUPPORT_PATH = Path(__file__).with_name("test_private_producer.py")
_SUPPORT_SPEC = importlib.util.spec_from_file_location(
    "_private_producer_match_support", _SUPPORT_PATH
)
support = importlib.util.module_from_spec(_SUPPORT_SPEC)
assert _SUPPORT_SPEC.loader is not None
sys.modules[_SUPPORT_SPEC.name] = support
_SUPPORT_SPEC.loader.exec_module(support)

# The producer support imports Yoohoo's fixture module into sys.modules under
# its canonical name. Reuse that exact module so the matcher and Ghostty gate
# share one fixture implementation instead of inventing a duplicate.
import connection_fixture as connection  # noqa: E402

ConnectionFixture = support.ConnectionFixture
PrivatePaneSnapshot = support.PrivatePaneSnapshot
SetupCommand = support.SetupCommand
live_test_authorized = support.live_test_authorized


class RestrictedAttachmentProbeIO(support.TrackedFixtureProbeIO):
    """Permit only the tracked SSH tree's procfs and the exact remote probe."""

    def __init__(self, fixture: ConnectionFixture, root_pid: int) -> None:
        super().__init__(fixture)
        self._real = DefaultProbeIO()
        self._root_pid = root_pid
        self._full_pids = {root_pid}
        self._stat_only_pids: set[int] = set()
        self._task_ids: dict[int, set[int]] = {}

    @staticmethod
    def _proc_parts(path: str) -> tuple[int, tuple[str, ...]]:
        candidate = PurePosixPath(path)
        parts = candidate.parts
        if len(parts) < 3 or parts[:2] != ("/", "proc") or not parts[2].isdigit():
            raise AssertionError("collector path escaped the exact proc allowlist")
        if any(part in {"", ".", ".."} for part in parts[3:]):
            raise AssertionError("collector proc path was not canonical")
        return int(parts[2]), tuple(parts[3:])

    @staticmethod
    def _parent_pid(raw: bytes) -> int:
        try:
            return int(raw.decode("ascii").rsplit(") ", 1)[1].split()[1])
        except (UnicodeError, ValueError, IndexError) as error:
            raise AssertionError("collector observed an invalid proc stat") from error

    def _allow_full_read(self, pid: int, suffix: tuple[str, ...]) -> bool:
        if pid not in self._full_pids:
            return False
        if suffix in {("stat",), ("cmdline",)}:
            return True
        if len(suffix) == 2 and suffix[0] == "net":
            return suffix[1] in {"tcp", "tcp6", "udp", "udp6"}
        if (
            len(suffix) == 3
            and suffix[0] == "task"
            and suffix[1].isdigit()
            and suffix[2] == "children"
        ):
            return int(suffix[1]) in self._task_ids.get(pid, set())
        return False

    def read_bytes(self, path: str, max_bytes: int) -> bytes:
        pid, suffix = self._proc_parts(path)
        if suffix == ("stat",) and pid in self._stat_only_pids:
            return self._real.read_bytes(path, max_bytes)
        if not self._allow_full_read(pid, suffix):
            raise AssertionError("collector proc read escaped the tracked SSH tree")
        raw = self._real.read_bytes(path, max_bytes)
        if suffix == ("stat",):
            parent = self._parent_pid(raw)
            if parent > 1:
                self._stat_only_pids.add(parent)
        elif suffix[-1:] == ("children",):
            for value in raw.split():
                child = int(value)
                if child > 1:
                    self._full_pids.add(child)
        return raw

    def readlink(self, path: str, max_chars: int) -> str:
        pid, suffix = self._proc_parts(path)
        if (
            pid not in self._full_pids
            or len(suffix) != 2
            or suffix[0] != "fd"
            or not suffix[1].isdigit()
        ):
            raise AssertionError("collector proc link escaped the tracked SSH tree")
        return self._real.readlink(path, max_chars)

    def listdir(self, path: str, max_entries: int) -> tuple[str, ...]:
        pid, suffix = self._proc_parts(path)
        if pid not in self._full_pids or suffix not in {("fd",), ("task",)}:
            raise AssertionError("collector proc listing escaped the tracked SSH tree")
        values = self._real.listdir(path, max_entries)
        if suffix == ("task",):
            if not all(value.isdigit() for value in values):
                raise AssertionError("collector task listing was not numeric")
            self._task_ids[pid] = {int(value) for value in values}
        return values


def _request(snapshot: PrivatePaneSnapshot, ssh_pid: int, ssh_ticks: int) -> Request:
    target_request, _remote = support._request_and_remote(snapshot)
    window = Window(
        "synthetic-private-ssh",
        "0xfeed",
        ssh_pid,
        str(ssh_ticks),
        "synthetic-test-root",
    )
    return Request(
        "private-ssh-visible-match",
        "resolve",
        "visible_exact",
        target_request.target,
        support._LOCAL_MACHINE,
        (window,),
        None,
        Limits(deadline_ms=20_000),
    )


@unittest.skipUnless(
    live_test_authorized(),
    "private SSH matcher smoke requires the fixture's explicit Plumbus opt-in",
)
class PrivateSshMatcherSmokeTests(unittest.TestCase):
    def test_real_endpoint_and_tmux_visibility_match_synthetic_ssh_root(self) -> None:
        prepared: dict[str, object] = {}

        def command_factory(
            snapshot: PrivatePaneSnapshot,
        ) -> tuple[SetupCommand, ...]:
            _target_request, remote = support._request_and_remote(snapshot)
            attachment = "exec " + shlex.join(
                ["tmux", "attach-session", "-t", "=" + snapshot.session]
            )
            prepared["snapshot"] = snapshot
            prepared["attachment"] = attachment
            return (
                SetupCommand(remote, original_command=remote),
                SetupCommand(attachment, original_command=attachment),
            )

        fixture = ConnectionFixture(command_factory=command_factory)
        with fixture:
            snapshot = prepared["snapshot"]
            attachment = prepared["attachment"]
            assert isinstance(snapshot, PrivatePaneSnapshot)
            assert isinstance(attachment, str)
            client = fixture.start_ssh_client(attachment)
            try:
                observed_client = fixture.wait_for_tmux_client(client, snapshot)
                request = _request(
                    snapshot, client.identity.pid, client.identity.start_ticks
                )
                collector = LinuxCollector(
                    RestrictedAttachmentProbeIO(fixture, client.identity.pid),
                    ssh="/usr/bin/ssh",
                    python="python3",
                )
                response = Resolver().resolve(request, collector)
                diagnostic = {
                    "status": response.get("status"),
                    "reasons": [
                        {
                            "code": item.get("code"),
                            "source": item.get("source"),
                            "retryable": item.get("retryable"),
                        }
                        for item in response.get("reasons", [])
                        if isinstance(item, dict)
                    ],
                    "evidenceCodes": [
                        item.get("code") for item in response.get("evidence", [])
                        if isinstance(item, dict)
                    ],
                    "candidateCount": len(response.get("candidates", [])),
                }
                self.assertEqual(response["status"], "matched", diagnostic)
                self.assertEqual(len(response["candidates"]), 1)
                candidate = response["candidates"][0]
                self.assertEqual(candidate["window"]["stableId"], "synthetic-private-ssh")
                self.assertEqual(candidate["window"]["pid"], client.identity.pid)
                self.assertEqual(candidate["proof"]["state"], "complete")
                self.assertEqual(candidate["proof"]["relation"], "visible_exact")
                link = candidate["proof"]["evidence"][-1]
                self.assertEqual(link["code"], "tmux_client_visible_exact")
                self.assertEqual(link["details"]["pid"], observed_client.pid)
                self.assertEqual(
                    set(link["details"]),
                    {"pid", "startTimeTicks", "localEndpoint", "targetEndpoint"},
                )
                local_endpoint = link["details"]["localEndpoint"]
                target_endpoint = link["details"]["targetEndpoint"]
                self.assertEqual(local_endpoint["protocol"], "tcp")
                self.assertEqual(target_endpoint["protocol"], "tcp")
                self.assertEqual(local_endpoint["local"], target_endpoint["remote"])
                self.assertEqual(local_endpoint["remote"], target_endpoint["local"])
            finally:
                fixture.stop_started_ssh_client(client)


if __name__ == "__main__":
    unittest.main()
