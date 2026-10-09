"""Current local session is read from the client, not its launch argv."""
from __future__ import annotations

import ast
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_window_resolver.cli import run
from agent_window_resolver.collector import (
    CommandResult, Deadline, ProcessNode, TmuxClient, WindowObservation,
)
from agent_window_resolver.linux import LinuxCollector, CollectionFailure
from agent_window_resolver.model import ProcessIdentity
from agent_window_resolver.session_probe import REMOTE_SESSION_PROBE
from agent_window_resolver.window_session import (
    WindowSessionReader, parse_window_session_request,
)
from tests.test_window_session_protocol import request


class StaticSessionCollector:
    def __init__(self, observation: WindowObservation, clients=(),
                 remote=None, local_transports=()) -> None:
        self.observation = observation
        self.clients = clients
        self.remote = remote
        self.local_transports = local_transports
        self.calls = []

    def collect_window_session(self, value, deadline):
        self.calls.append("window")
        return self.observation

    def local_session_clients(self, socket, machine, deadline):
        self.calls.append("tmux")
        return self.clients

    def local_transport_clients(self, kind, host, machine, deadline):
        self.calls.append("local-transports")
        return self.local_transports

    def remote_session_read(self, host, socket, need_counts, deadline):
        self.calls.append(("remote", host, need_counts))
        return self.remote


def observation(*nodes: ProcessNode) -> WindowObservation:
    selected = parse_window_session_request(request()).window
    return WindowObservation(selected, nodes)


class WindowSessionReaderTests(unittest.TestCase):
    @staticmethod
    def remote_probe_functions():
        """Execute the shipped fixed program's definitions without its live read."""
        program = ast.parse(REMOTE_SESSION_PROBE)
        definitions = [node for node in program.body
                       if isinstance(node, (ast.Import, ast.FunctionDef)) or
                       (isinstance(node, ast.Assign) and
                        all(isinstance(target, ast.Name) and
                            (target.id.startswith("MAX_") or target.id == "END_NAMES")
                            for target in node.targets))]
        namespace = {}
        exec(compile(ast.Module(body=definitions, type_ignores=[]),
                     "<fixed-remote-session-probe>", "exec"), namespace)
        return namespace

    def test_fixed_probe_accepts_spaced_attach_if_present_launch(self) -> None:
        parse = self.remote_probe_functions()["launch_target"]
        self.assertEqual(parse(["tmux", "new-session", "-A", "-s", "build"]),
                         "build")
        observed, _ = self.remote_window(
            ("et", "example-host", "-c", "tmux new-session -A -s build")
        )
        collector = StaticSessionCollector(observed, remote={
            "host": "example-host", "incomplete": False,
            "clients": [{"session": "deploy", "kind": "et",
                         "remoteEndPid": 900,
                         "launchTarget": parse(["tmux", "new-session", "-A", "-s", "build"])}],
            "terminalEnds": None,
        })
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["session"]["name"], "deploy")
        self.assertEqual(result["session"]["basis"], "current")

    def test_fixed_probe_keeps_named_client_when_default_server_absent(self) -> None:
        namespace = self.remote_probe_functions()
        namespace["cfg"] = {"socket": {"kind": "name", "value": "work"}}
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "tmux"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"-L\" ]; then\n"
                "  printf '101\\tdeploy\\n'\n"
                "  exit 0\n"
                "fi\n"
                "printf 'no server running on /tmp/tmux-test/default\\n' >&2\n"
                "exit 1\n"
            )
            executable.chmod(0o700)
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ["PATH"]}):
                rows, incomplete = namespace["client_rows"]()
        self.assertEqual(rows, [(101, "deploy")])
        self.assertFalse(incomplete)

        observed, _ = self.remote_window(
            ("et", "example-host", "-c", "tmux -L work attach -t '=build'")
        )
        collector = StaticSessionCollector(observed, remote={
            "host": "example-host", "incomplete": incomplete,
            "clients": [{"session": rows[0][1], "kind": "et",
                         "remoteEndPid": 900, "launchTarget": "build"}],
            "terminalEnds": None,
        })
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["session"]["name"], "deploy")
        self.assertEqual(result["session"]["basis"], "current")

    def test_fixed_probe_rejects_failed_named_socket_read(self) -> None:
        namespace = self.remote_probe_functions()
        namespace["cfg"] = {"socket": {"kind": "name", "value": "work"}}
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "tmux"
            executable.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"-L\" ]; then\n"
                "  printf 'permission denied\\n' >&2\n"
                "  exit 1\n"
                "fi\n"
                "printf 'no server running on /tmp/tmux-test/default\\n' >&2\n"
                "exit 1\n"
            )
            executable.chmod(0o700)
            with patch.dict(os.environ, {"PATH": directory + os.pathsep + os.environ["PATH"]}):
                with self.assertRaisesRegex(RuntimeError, "tmux list-clients failed"):
                    namespace["client_rows"]()

    def test_local_transport_count_uses_live_pid_and_start_ticks(self) -> None:
        def stat_row(pid, ticks):
            fields = ["S", "1"] + ["0"] * 18
            fields[19] = str(ticks)
            return f"{pid} (ssh) ".encode() + " ".join(fields).encode() + b"\n"

        class ProcIO:
            def listdir(self, path, maximum):
                self_path = path
                if self_path != "/proc":
                    raise AssertionError(path)
                return ("102", "103")

            def read_bytes(self, path, maximum):
                if path.endswith("/stat"):
                    pid = int(path.split("/")[2])
                    return stat_row(pid, pid + 1)
                if path.endswith("/cmdline"):
                    return b"ssh\0example-host\0"
                raise AssertionError(path)

        clients = LinuxCollector(io=ProcIO()).local_transport_clients(
            "ssh", "example-host", "laptop", Deadline(20000)
        )
        self.assertEqual([(item.pid, item.start_time_ticks) for item in clients],
                         [(102, "103"), (103, "104")])

    def test_fixed_remote_program_compiles(self) -> None:
        compile(REMOTE_SESSION_PROBE, "<fixed-remote-session-probe>", "exec")

    def test_remote_read_uses_one_strict_ssh_and_rejects_process_dump(self) -> None:
        class FakeIO:
            def __init__(self, value):
                self.value = value
                self.calls = []

            def run(self, argv, **kwargs):
                self.calls.append((argv, kwargs))
                return CommandResult(0, json.dumps(self.value).encode())

        result = {"host": "example-host", "clients": [],
                  "terminalEnds": None, "terminalEndCounts": None,
                  "incomplete": False}
        io = FakeIO(result)
        read = LinuxCollector(io=io).remote_session_read(
            "example-host", None, False, Deadline(20000)
        )
        self.assertEqual(read, result)
        self.assertEqual(len(io.calls), 1)
        argv = io.calls[0][0]
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ControlMaster=no", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertIn("PermitLocalCommand=no", argv)
        self.assertIn("-T", argv)
        io.value = {**result, "processes": []}
        with self.assertRaises(CollectionFailure):
            LinuxCollector(io=io).remote_session_read(
                "example-host", None, False, Deadline(20000)
            )

    @staticmethod
    def remote_window(command):
        root_id = ProcessIdentity("laptop", 102, "123")
        end_id = ProcessIdentity("laptop", 104, "457")
        root = ProcessNode(root_id, None, ("kitty",))
        end = ProcessNode(end_id, root_id, command)
        return observation(root, end), end_id

    def test_remote_launch_switch_uses_current_session(self) -> None:
        observed, _ = self.remote_window(
            ("et", "example-host", "-c", "tmux attach -t '=build'")
        )
        collector = StaticSessionCollector(observed, remote={
            "host": "example-host.lan", "incomplete": False,
            "clients": [{"session": "deploy", "kind": "et",
                         "remoteEndPid": 900, "launchTarget": "build"}],
            "terminalEnds": None,
        })
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["session"], {
            "name": "deploy", "host": "example-host", "transport": "et",
            "basis": "current", "method": "remote-ancestry",
        })
        self.assertEqual(collector.calls, ["window", ("remote", "example-host", False)])

    def test_remote_launch_ambiguity_falls_back_to_launch(self) -> None:
        observed, _ = self.remote_window(
            ("et", "example-host", "-c", "tmux attach -t '=build'")
        )
        collector = StaticSessionCollector(observed, remote={
            "host": "example-host", "incomplete": False,
            "clients": [
                {"session": "deploy", "kind": "et", "remoteEndPid": 900,
                 "launchTarget": "build"},
                {"session": "build", "kind": "et", "remoteEndPid": 901,
                 "launchTarget": "build"},
            ], "terminalEnds": None,
        })
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["session"]["basis"], "launch")
        self.assertEqual(result["session"]["name"], "build")

    def test_hand_attached_requires_unique_local_and_remote_end(self) -> None:
        observed, end_id = self.remote_window(("et", "example-host"))
        remote = {
            "host": "example-host", "incomplete": False,
            "clients": [{"session": "deploy", "kind": "et",
                         "remoteEndPid": 900, "launchTarget": None}],
            "terminalEnds": {"et": [900], "ssh": [], "mosh": []},
        }
        collector = StaticSessionCollector(
            observed, remote=remote, local_transports=(end_id,)
        )
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["session"]["basis"], "current")
        self.assertEqual(result["session"]["method"], "remote-unique-connection")
        self.assertNotIn("uncertainty", result)
        self.assertEqual(collector.calls, [
            "window", "local-transports", ("remote", "example-host", True),
            "local-transports",
        ])
        collector = StaticSessionCollector(
            observed, remote=remote, local_transports=(end_id, end_id)
        )
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["status"], "none")
        self.assertIsNone(result["session"])
        self.assertEqual(result["uncertainty"], {
            "code": "et_hint_not_exact_proof", "transport": "et",
            "host": "example-host",
            "window": {"stableId": "17", "address": "0x11", "pid": 102,
                       "startTimeTicks": "123"},
        })
        self.assertEqual(collector.calls, ["window", "local-transports"])

        collector = StaticSessionCollector(
            observed, remote={**remote, "clients": []}, local_transports=(end_id,)
        )
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["status"], "none")
        self.assertEqual(result["uncertainty"]["code"], "et_hint_not_exact_proof")
        self.assertEqual(collector.calls, [
            "window", "local-transports", ("remote", "example-host", True),
            "local-transports",
        ])

    def test_remote_failure_preserves_launch_only_and_unknown_without_it(self) -> None:
        class FailingCollector(StaticSessionCollector):
            def remote_session_read(self, host, socket, need_counts, deadline):
                self.calls.append(("remote", host, need_counts))
                raise CollectionFailure("remote_unreachable", "transport",
                                        "remote read failed", True)

        launch, _ = self.remote_window(
            ("et", "example-host", "-c", "tmux attach -t '=build'")
        )
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), FailingCollector(launch)
        )
        self.assertEqual(result["status"], "found")
        self.assertEqual(result["session"]["basis"], "launch")
        self.assertEqual(result["reasons"][0]["code"], "remote_unreachable")

        manual, end_id = self.remote_window(("et", "example-host"))
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()),
            FailingCollector(manual, local_transports=(end_id,))
        )
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["session"])
        self.assertNotIn("uncertainty", result)

    def test_cli_routes_new_schema_without_touching_v1(self) -> None:
        root = ProcessNode(ProcessIdentity("laptop", 102, "123"), None, ("kitty",))
        collector = StaticSessionCollector(observation(root))
        stdout = BytesIO()
        code = run(
            [], stdin=BytesIO(json.dumps(request()).encode()),
            stdout=stdout, stderr=BytesIO(), collector=collector,
        )
        self.assertEqual(code, 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["schema"],
                         "agent-window-resolver.window-session.response.v1")
        self.assertEqual(result["status"], "none")
        self.assertEqual(collector.calls, ["window"])

    def test_local_client_switch_returns_current_session(self) -> None:
        root_id = ProcessIdentity("laptop", 102, "123")
        tmux_id = ProcessIdentity("laptop", 103, "456")
        root = ProcessNode(root_id, None, ("kitty",))
        tmux = ProcessNode(tmux_id, root_id, ("tmux", "attach", "-t", "api"))
        client = TmuxClient("/dev/pts/1", tmux_id, "web", "2", "%4")
        collector = StaticSessionCollector(observation(root, tmux), (client,))
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["status"], "found")
        self.assertEqual(result["session"], {
            "name": "web", "basis": "current", "method": "local-client",
        })
        self.assertEqual(collector.calls, ["window", "tmux"])

    def test_shared_pid_returns_no_session_without_collection(self) -> None:
        value = request()
        value["windows"].append({
            **value["window"], "stableId": "18", "address": "0x12",
        })
        collector = StaticSessionCollector(observation())
        result = WindowSessionReader().resolve(
            parse_window_session_request(value), collector
        )
        self.assertEqual(result["status"], "none")
        self.assertEqual(collector.calls, [])

    def test_pid_reuse_is_unknown(self) -> None:
        root = ProcessNode(ProcessIdentity("laptop", 102, "999"), None, ("kitty",))
        collector = StaticSessionCollector(observation(root))
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reasons"][0]["code"], "window_identity_changed")

    def test_plain_window_has_no_session(self) -> None:
        root = ProcessNode(ProcessIdentity("laptop", 102, "123"), None, ("kitty",))
        collector = StaticSessionCollector(observation(root))
        result = WindowSessionReader().resolve(
            parse_window_session_request(request()), collector
        )
        self.assertEqual(result["status"], "none")
        self.assertEqual(collector.calls, ["window"])


if __name__ == "__main__":
    unittest.main()
