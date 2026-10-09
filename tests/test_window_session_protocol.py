"""The additive request stays separate from resolver v1 parsing."""
from __future__ import annotations

import unittest

from agent_window_resolver.model import RequestError, parse_request
from agent_window_resolver.window_session import (
    parse_window_session_request, transport_destination,
)


def request() -> dict:
    window = {
        "stableId": "17", "address": "0x11", "pid": 102,
        "startTimeTicks": "123", "class": "kitty", "title": "shell",
    }
    return {
        "schema": "agent-window-resolver.window-session.request.v1",
        "requestId": "example-1", "operation": "window-session",
        "window": window, "windows": [window], "local": {"machine": "Laptop."},
    }


class WindowSessionProtocolTests(unittest.TestCase):
    def test_new_request_parses_without_changing_v1_acceptance(self) -> None:
        parsed = parse_window_session_request(request())
        self.assertEqual(parsed.window.pid, 102)
        self.assertEqual(parsed.local_machine, "laptop")
        with self.assertRaises(RequestError) as raised:
            parse_request(request())
        self.assertEqual(raised.exception.code, "unknown_field")

    def test_selected_window_must_be_in_the_snapshot(self) -> None:
        value = request()
        value["window"] = {**value["window"], "startTimeTicks": "124"}
        with self.assertRaises(RequestError) as raised:
            parse_window_session_request(value)
        self.assertEqual(raised.exception.code, "window_not_in_snapshot")

    def test_reused_pid_does_not_select_old_process(self) -> None:
        value = request()
        value["windows"] = [{**value["window"], "startTimeTicks": "124"}]
        with self.assertRaises(RequestError) as raised:
            parse_window_session_request(value)
        self.assertEqual(raised.exception.code, "window_not_in_snapshot")

    def test_duplicate_identity_fails(self) -> None:
        value = request()
        value["windows"].append(value["window"])
        with self.assertRaises(RequestError) as raised:
            parse_window_session_request(value)
        self.assertEqual(raised.exception.code, "duplicate_window_identity")

    def test_unknown_field_and_v1_target_are_rejected(self) -> None:
        value = request()
        value["target"] = {}
        with self.assertRaises(RequestError) as raised:
            parse_window_session_request(value)
        self.assertEqual(raised.exception.code, "unknown_field")

    def test_transport_launch_and_hand_attached_hosts(self) -> None:
        cases = [
            (("et", "example-host", "-c", "tmux attach -t '=build'"),
             ("et", "example-host", "build")),
            (("et", "example-host"), ("et", "example-host", None)),
            (("ssh", "person@example-host"), ("ssh", "example-host", None)),
            (("mosh", "example-host"), ("mosh", "example-host", None)),
            (("mosh-client", "-# -- example-host |", "192.0.2.1", "60001"),
             ("mosh", "example-host", None)),
        ]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                result = transport_destination(argv)
                self.assertIsNotNone(result)
                assert result is not None
                self.assertEqual((result.kind, result.host, result.launch_session), expected)

    def test_uncertain_transport_grammar_does_not_produce_a_host(self) -> None:
        for argv in (("ssh", "-o"), ("et", "--unknown", "host"),
                     ("mosh-client", "-# -- |"), ("ssh", "-Z", "host")):
            with self.subTest(argv=argv):
                self.assertIsNone(transport_destination(argv))


if __name__ == "__main__":
    unittest.main()
