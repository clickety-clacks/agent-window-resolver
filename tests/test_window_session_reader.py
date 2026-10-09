"""Current local session is read from the client, not its launch argv."""
from __future__ import annotations

from io import BytesIO
import json
import unittest

from agent_window_resolver.cli import run
from agent_window_resolver.collector import ProcessNode, TmuxClient, WindowObservation
from agent_window_resolver.model import ProcessIdentity
from agent_window_resolver.window_session import (
    WindowSessionReader, parse_window_session_request,
)
from tests.test_window_session_protocol import request


class StaticSessionCollector:
    def __init__(self, observation: WindowObservation, clients=()) -> None:
        self.observation = observation
        self.clients = clients
        self.calls = []

    def collect_window_session(self, value, deadline):
        self.calls.append("window")
        return self.observation

    def local_session_clients(self, socket, machine, deadline):
        self.calls.append("tmux")
        return self.clients


def observation(*nodes: ProcessNode) -> WindowObservation:
    selected = parse_window_session_request(request()).window
    return WindowObservation(selected, nodes)


class WindowSessionReaderTests(unittest.TestCase):
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
