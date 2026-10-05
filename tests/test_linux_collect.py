"""Full LinuxCollector tests through a scripted ProbeIO; no live probes."""
from __future__ import annotations

import json
import os
from typing import Any

from agent_window_resolver import (
    CommandResult,
    Deadline,
    Limits,
    ProcessIdentity,
    Request,
    Resolver,
    SocketSelector,
    StaticCollector,
    Target,
    TmuxLocation,
    Window,
    WindowObservation,
)
from agent_window_resolver.linux import CollectionFailure, LinuxCollector
from tests.test_linux import endpoint_row, raw_node, stat_row


def make_request() -> Request:
    window = Window("window-1", "0xabc", 100, "20")
    return Request(
        "collect-1", "resolve", "linked_client",
        Target(
            ProcessIdentity("atlas", 42, "99"), "agent",
            TmuxLocation("ask", "1", "%1", SocketSelector("name", "agents")),
        ),
        "lumen", (window,), None, Limits(),
    )


def target_output(protocol: str) -> bytes:
    client_line = "client0\t500\tother\t9\t%9"
    if protocol == "tcp":
        client_processes = [
            raw_node(500, 501, 77),
            raw_node(
                501, 1, 78,
                environment=(
                    b"SSH_CONNECTION=192.0.2.10 52411 198.51.100.7 22"
                ),
            ),
        ]
    else:
        remote = endpoint_row(
            "22", "198.51.100.7", 60002, "192.0.2.10", 52411
        )
        client_processes = [raw_node(
            500, 1, 77, inode="22", net_line=remote, net_kind="udp",
        )]
    return json.dumps({
        "socketPathBefore": "/tmp/tmux/socket",
        "socketPathAfter": "/tmp/tmux/socket",
        "paneLineBefore": "ask\t1\t%1\t600",
        "paneLineAfter": "ask\t1\t%1\t600",
        "clientLinesBefore": [client_line],
        "clientLinesAfter": [client_line],
        "paneProcess": raw_node(600, 1, 10),
        "processes": [raw_node(42, 600, 99), raw_node(600, 1, 10)],
        "clients": [{"line": client_line, "processes": client_processes}],
    }, separators=(",", ":")).encode()


class ScriptedProbeIO:
    def __init__(self, protocol: str, *, changed_child_ticks: bool = False,
                 changed_child_argv: bool = False) -> None:
        port = 22 if protocol == "tcp" else 60002
        local = endpoint_row(
            "11", "192.0.2.10", 52411, "198.51.100.7", port
        )
        command = ("ssh", "atlas") if protocol == "tcp" else ("mosh-client",)
        self.records: dict[int, dict[str, Any]] = {
            100: {"parent": 1, "ticks": 20, "argv": ("terminal",),
                  "children": (200,)},
            200: {"parent": 100, "ticks": 30, "argv": command,
                  "children": (), "inode": "11", "net_kind": protocol,
                  "net_line": local},
        }
        self.changed_child_ticks = changed_child_ticks
        self.changed_child_argv = changed_child_argv
        self.stat_calls: dict[int, int] = {}
        self.cmdline_calls: dict[int, int] = {}
        self.remote = target_output(protocol)
        self.run_calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def monotonic(self) -> float:
        return 0.0

    @staticmethod
    def _parts(path: str) -> tuple[int, tuple[str, ...]]:
        values = path.strip("/").split("/")
        if len(values) < 3 or values[0] != "proc":
            raise AssertionError("unexpected path " + path)
        return int(values[1]), tuple(values[2:])

    def read_bytes(self, path: str, max_bytes: int) -> bytes:
        pid, tail = self._parts(path)
        record = self.records[pid]
        if tail == ("stat",):
            call = self.stat_calls.get(pid, 0)
            self.stat_calls[pid] = call + 1
            ticks = record["ticks"]
            if pid == 200 and self.changed_child_ticks and call >= 1:
                ticks += 1
            value = stat_row(
                pid, record["parent"], ticks, cpu=call,
                state=record.get("state", "S"),
            )
        elif tail == ("cmdline",):
            call = self.cmdline_calls.get(pid, 0)
            self.cmdline_calls[pid] = call + 1
            argv = record["argv"]
            if pid == 200 and self.changed_child_argv and call >= 1:
                argv = ("unrelated",)
            value = b"\0".join(item.encode() for item in argv) + b"\0"
        elif len(tail) == 3 and tail[0] == "task" and tail[2] == "children":
            value = b" ".join(str(item).encode() for item in record["children"])
        elif len(tail) == 2 and tail[0] == "net":
            header = b"header\n"
            if tail[1] == record.get("net_kind") and record.get("net_line"):
                value = header + record["net_line"] + b"\n"
            else:
                value = header
        else:
            raise AssertionError("unexpected read " + path)
        if len(value) > max_bytes:
            raise AssertionError("fixture exceeded requested bound")
        return value

    def listdir(self, path: str, max_entries: int) -> tuple[str, ...]:
        pid, tail = self._parts(path)
        if tail == ("fd",):
            values = ("0", "3") if self.records[pid].get("inode") else ("0",)
        elif tail == ("task",):
            values = (str(pid),)
        else:
            raise AssertionError("unexpected listdir " + path)
        if len(values) > max_entries:
            raise AssertionError("fixture exceeded entry bound")
        return values

    def readlink(self, path: str, max_chars: int) -> str:
        pid, tail = self._parts(path)
        if tail == ("fd", "0"):
            return "/dev/pts/1"
        if tail == ("fd", "3") and self.records[pid].get("inode"):
            return "socket:[" + self.records[pid]["inode"] + "]"
        raise OSError("fixture link absent")

    def run(self, argv, **kwargs) -> CommandResult:
        self.run_calls.append((tuple(argv), dict(kwargs)))
        return CommandResult(0, self.remote)


class NoRemoteProbeIO(ScriptedProbeIO):
    def run(self, argv, **kwargs) -> CommandResult:
        raise AssertionError("remote target probe must not run for match")


class LocalMatchProbeIO:
    def __init__(self) -> None:
        self.run_calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def monotonic(self) -> float:
        return 0.0

    def read_bytes(self, path: str, max_bytes: int) -> bytes:
        if path.endswith("/200/stat"):
            value = stat_row(200, 100, 30)
        elif path.endswith("/201/stat"):
            raise PermissionError(path)
        else:
            raise AssertionError("unexpected local match read " + path)
        if len(value) > max_bytes:
            raise AssertionError("fixture exceeded requested bound")
        return value

    def readlink(self, path: str, max_chars: int) -> str:
        raise AssertionError("local match must not read process links")

    def listdir(self, path: str, max_entries: int) -> tuple[str, ...]:
        raise AssertionError("local match must not scan process directories")

    def run(self, argv, **kwargs) -> CommandResult:
        self.run_calls.append((tuple(argv), dict(kwargs)))
        self.last_env = kwargs["env"]
        if "display-message" in argv:
            return CommandResult(0, b"/tmp/tmux-default\n")
        return CommandResult(
            0,
            b"client0\t200\task\t1\t%1\n"
            b"client1\t201\tother\t9\t%9\n",
        )


import unittest
from dataclasses import replace
from unittest.mock import patch

from agent_window_resolver.collector import ProcessNode


class LinuxCollectTests(unittest.TestCase):
    def test_local_match_collects_narrow_tmux_rows_and_keeps_other_clients(self) -> None:
        request = replace(
            make_request(), operation="match", requested_relation=None,
            target=Target(
                ProcessIdentity("lumen", 42, "99"), "agent",
                TmuxLocation("ask", "1", "%1", SocketSelector("name", "agents")),
            ),
        )
        io = LocalMatchProbeIO()
        collector = LinuxCollector(io)
        window = request.windows[0]
        with patch.dict(os.environ, {"TMUX": "nested", "TMUX_TMPDIR": "/tmp/fixture"}), \
             patch.object(collector, "_window", return_value=WindowObservation(
                 window, (), "partial",
             )):
            snapshot = collector.collect(request, Deadline(1_000, io.monotonic))

        self.assertEqual(len(io.run_calls), 2)
        self.assertTrue(all(argv[0] == "tmux" for argv, _ in io.run_calls))
        self.assertNotIn("TMUX", io.last_env)
        self.assertEqual(io.last_env["TMUX_TMPDIR"], "/tmp/fixture")
        self.assertEqual(snapshot.target.collection_state, "partial")
        self.assertEqual(len(snapshot.target.clients), 1)
        self.assertEqual(snapshot.target.clients[0].process.pid, 200)
        self.assertIn(
            "local_tmux_client_unreadable",
            {error.code for error in snapshot.target.errors},
        )

    def test_remote_match_collect_skips_tmux_and_retains_title_candidate(self) -> None:
        request = replace(
            make_request(), operation="match", requested_relation=None,
            windows=(Window("window-1", "0xabc", 100, "20", title="ask"),),
        )
        io = NoRemoteProbeIO("tcp")
        collector = LinuxCollector(io)
        snapshot = collector.collect(request, Deadline(1_000, io.monotonic))

        self.assertEqual(snapshot.target.collection_state, "partial")
        self.assertEqual(
            tuple(error.code for error in snapshot.target.errors),
            ("remote_target_not_probed",),
        )
        self.assertEqual(snapshot.windows[0].window.title, "ask")
        self.assertTrue(snapshot.windows[0].processes)
        response = Resolver(now=io.monotonic).resolve(
            request, StaticCollector(snapshot)
        )
        self.assertEqual(response["status"], "matched", response)
        self.assertIn(
            "remote_target_not_probed",
            {item["code"] for item in response["candidates"][0]["match"]["uncertainty"]},
        )

    def test_remote_non_tmux_match_skips_target_probe_and_retains_title_candidate(self) -> None:
        request = replace(
            make_request(), operation="match", requested_relation=None,
            target=Target(
                ProcessIdentity("atlas", 42, "99"), "agent", name="agent"
            ),
            windows=(Window("window-1", "0xabc", 100, "20", title="agent"),),
        )
        io = NoRemoteProbeIO("tcp")
        collector = LinuxCollector(io)
        snapshot = collector.collect(request, Deadline(1_000, io.monotonic))

        self.assertEqual(snapshot.target.collection_state, "partial")
        self.assertEqual(snapshot.target.errors[0].code, "remote_target_not_probed")
        self.assertEqual(snapshot.windows[0].window.title, "agent")
        response = Resolver(now=io.monotonic).resolve(
            request, StaticCollector(snapshot)
        )
        self.assertEqual(response["status"], "matched", response)
        self.assertIn(
            "remote_target_not_probed",
            {item["code"] for item in response["candidates"][0]["match"]["uncertainty"]},
        )

    def test_strict_remote_collect_still_delegates_to_target_probe(self) -> None:
        request = make_request()
        io = ScriptedProbeIO("tcp")
        collector = LinuxCollector(io)
        with patch.object(
            collector, "_target_probe", wraps=collector._target_probe
        ) as target_probe:
            collector.collect(request, Deadline(1_000, io.monotonic))
        target_probe.assert_called_once()
        self.assertEqual(len(io.run_calls), 1)

    def test_direct_target_collection_does_not_walk_unrelated_ancestors(self) -> None:
        request = replace(
            make_request(),
            target=Target(ProcessIdentity("lumen", 42, "99"), "agent"),
            local_machine="lumen",
        )
        collector = LinuxCollector(ScriptedProbeIO("tcp"))
        target_node = ProcessNode(ProcessIdentity("lumen", 42, "99"), None)
        with patch.object(collector, "_node", return_value=target_node) as node, \
             patch.object(collector, "_ancestors", side_effect=AssertionError("ancestor walk")):
            observation = collector._target(request, Deadline(1_000))
        self.assertEqual(observation.collection_state, "complete")
        self.assertEqual(observation.processes, (target_node,))
        node.assert_called_once_with(42, "lumen")

    def test_full_ssh_collect_uses_raw_hidden_sshd_endpoint(self) -> None:
        request = make_request()
        io = ScriptedProbeIO("tcp")
        response = Resolver(now=io.monotonic).resolve(
            request, LinuxCollector(io)
        )
        self.assertEqual(response["status"], "matched")
        self.assertEqual(len(io.run_calls), 1)
        argv, options = io.run_calls[0]
        self.assertEqual(argv[0], "ssh")
        self.assertNotIn("TMUX", options["env"])
        self.assertLessEqual(options["max_stdout"], 524_288)

    def test_full_mosh_collect_uses_udp_after_exec(self) -> None:
        request = make_request()
        io = ScriptedProbeIO("udp")
        response = Resolver(now=io.monotonic).resolve(
            request, LinuxCollector(io)
        )
        self.assertEqual(response["status"], "matched")

    def test_unrelated_unreadable_fd_does_not_invalidate_window_scan(self) -> None:
        class UnreadableUnrelatedIO(ScriptedProbeIO):
            def readlink(self, path: str, max_chars: int) -> str:
                if path.endswith("/100/fd/3"):
                    raise PermissionError(path)
                return super().readlink(path, max_chars)

        io = UnreadableUnrelatedIO("tcp")
        io.records[100]["inode"] = "99"
        io.records[100]["net_line"] = endpoint_row(
            "99", "192.0.2.10", 52410, "198.51.100.7", 22
        )
        response = Resolver(now=io.monotonic).resolve(
            make_request(), LinuxCollector(io)
        )
        self.assertEqual(response["status"], "matched", response)

    def test_unreadable_ssh_fd_still_invalidates_window_scan(self) -> None:
        class UnreadableSshIO(ScriptedProbeIO):
            def readlink(self, path: str, max_chars: int) -> str:
                if path.endswith("/200/fd/3"):
                    raise PermissionError(path)
                return super().readlink(path, max_chars)

        io = UnreadableSshIO("tcp")
        response = Resolver(now=io.monotonic).resolve(
            make_request(), LinuxCollector(io)
        )
        self.assertEqual(response["status"], "unresolved", response)
        self.assertEqual(response["reasons"][0]["code"], "local_process_unreadable")

    def test_long_socket_link_still_collects_endpoint(self) -> None:
        long_inode = "1" * 120
        io = ScriptedProbeIO("tcp")
        io.records[200]["inode"] = long_inode
        io.records[200]["net_line"] = endpoint_row(
            long_inode, "192.0.2.10", 52411, "198.51.100.7", 22
        )
        node = LinuxCollector(io)._node(200, "lumen")
        self.assertEqual(len(node.endpoints), 1)

    def test_ineligible_to_ssh_argv_change_fails_closed(self) -> None:
        class IneligibleToSshIO(ScriptedProbeIO):
            def read_bytes(self, path: str, max_bytes: int) -> bytes:
                if path.endswith("/100/cmdline") and self.cmdline_calls.get(100, 0) >= 1:
                    self.records[100]["argv"] = ("ssh", "atlas")
                return super().read_bytes(path, max_bytes)

        io = IneligibleToSshIO("tcp")
        with self.assertRaises(CollectionFailure) as raised:
            LinuxCollector(io)._descendants(
                100, "lumen", Deadline(1_000, io.monotonic)
            )
        self.assertEqual(
            raised.exception.error.code, "process_identity_changed"
        )

    def test_pid_start_change_between_reads_fails_closed(self) -> None:
        request = make_request()
        io = ScriptedProbeIO("tcp", changed_child_ticks=True)
        response = Resolver(now=io.monotonic).resolve(
            request, LinuxCollector(io)
        )
        self.assertEqual(response["status"], "unresolved")
        self.assertEqual(response["candidates"], [])

    def test_exec_between_reads_fails_closed(self) -> None:
        request = make_request()
        io = ScriptedProbeIO("tcp", changed_child_argv=True)
        response = Resolver(now=io.monotonic).resolve(
            request, LinuxCollector(io)
        )
        self.assertEqual(response["status"], "unresolved")
        self.assertEqual(response["candidates"], [])

    def test_zombie_leaf_does_not_invalidate_window_scan(self) -> None:
        io = ScriptedProbeIO("tcp")
        io.records[100]["children"] = (200, 300)
        io.records[300] = {
            "parent": 100, "ticks": 40, "argv": ("xdg-terminal-ex",),
            "children": (), "state": "Z",
        }
        nodes = LinuxCollector(io)._descendants(
            100, "lumen", Deadline(1_000, io.monotonic)
        )
        self.assertEqual(
            tuple(node.identity.pid for node in nodes), (100, 200)
        )

    def test_zombie_window_root_is_not_treated_as_live(self) -> None:
        io = ScriptedProbeIO("tcp")
        io.records[100]["state"] = "Z"
        io.records[100]["children"] = ()
        with self.assertRaises(CollectionFailure) as raised:
            LinuxCollector(io)._descendants(
                100, "lumen", Deadline(1_000, io.monotonic)
            )
        self.assertEqual(raised.exception.error.code, "process_not_live")

    def test_zombie_with_children_is_not_silently_omitted(self) -> None:
        io = ScriptedProbeIO("tcp")
        io.records[100]["state"] = "Z"
        with self.assertRaises(CollectionFailure) as raised:
            LinuxCollector(io)._descendants(
                100, "lumen", Deadline(1_000, io.monotonic)
            )
        self.assertEqual(
            raised.exception.error.code, "zombie_process_has_children"
        )

    def test_zombie_identity_change_during_confirmation_fails_closed(self) -> None:
        class PidReuseZombieIO(ScriptedProbeIO):
            def read_bytes(self, path: str, max_bytes: int) -> bytes:
                if path.endswith("/100/stat") and self.stat_calls.get(100, 0) >= 2:
                    self.records[100]["state"] = "S"
                    self.records[100]["ticks"] = 999
                return super().read_bytes(path, max_bytes)

        io = PidReuseZombieIO("tcp")
        io.records[100]["state"] = "Z"
        io.records[100]["children"] = ()
        with self.assertRaises(CollectionFailure) as raised:
            LinuxCollector(io)._descendants(
                100, "lumen", Deadline(1_000, io.monotonic)
            )
        self.assertEqual(
            raised.exception.error.code, "process_identity_changed"
        )

    def test_nonroot_after_zombie_with_pid_reuse_fails_closed(self) -> None:
        class AfterZombieReuseIO(ScriptedProbeIO):
            def read_bytes(self, path: str, max_bytes: int) -> bytes:
                if path.endswith("/200/stat") and self.stat_calls.get(200, 0) >= 1:
                    self.records[200]["state"] = "Z"
                    self.records[200]["ticks"] = 999
                return super().read_bytes(path, max_bytes)

        io = AfterZombieReuseIO("tcp")
        with self.assertRaises(CollectionFailure) as raised:
            LinuxCollector(io)._descendants(
                100, "lumen", Deadline(1_000, io.monotonic)
            )
        self.assertEqual(
            raised.exception.error.code, "process_identity_changed"
        )

    def test_nonroot_final_zombie_with_pid_reuse_fails_closed(self) -> None:
        class FinalZombieReuseIO(ScriptedProbeIO):
            def read_bytes(self, path: str, max_bytes: int) -> bytes:
                if path.endswith("/200/stat") and self.stat_calls.get(200, 0) >= 2:
                    self.records[200]["state"] = "Z"
                    self.records[200]["ticks"] = 999
                return super().read_bytes(path, max_bytes)

        io = FinalZombieReuseIO("tcp")
        with self.assertRaises(CollectionFailure) as raised:
            LinuxCollector(io)._descendants(
                100, "lumen", Deadline(1_000, io.monotonic)
            )
        self.assertEqual(
            raised.exception.error.code, "process_identity_changed"
        )

    def test_proc_link_bound_allows_normal_desktop_path(self) -> None:
        io = ScriptedProbeIO("tcp")
        bounds: list[int] = []
        original = io.readlink

        def readlink(path: str, max_chars: int) -> str:
            bounds.append(max_chars)
            return original(path, max_chars)

        io.readlink = readlink  # type: ignore[method-assign]
        LinuxCollector(io)._node(200, "lumen")
        self.assertTrue(bounds)
        self.assertEqual(min(bounds), 4096)


if __name__ == "__main__":
    unittest.main()
