"""Protocol fixture parity tests with injected topology only."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from agent_window_resolver import (
    ProcessIdentity,
    ProcessNode,
    Resolver,
    StaticCollector,
    TargetObservation,
    TopologySnapshot,
    WindowObservation,
    parse_request,
)


FIXTURE = Path(__file__).parents[1] / "fixtures" / "protocol-v1.json"


class DenyCollector:
    def collect(self, request, deadline):
        raise AssertionError("early protocol validation attempted collection")


class ProtocolFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.values = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_valid_direct_response_matches_frozen_fixture(self) -> None:
        case = self.values["valid"][0]
        request = parse_request(case["request"])
        window = request.windows[0]
        root = ProcessNode(
            ProcessIdentity(request.local_machine, window.pid,
                            window.start_time_ticks),
            None,
        )
        target = ProcessNode(request.target.identity, root.identity)
        snapshot = TopologySnapshot(
            (WindowObservation(window, (root, target)),),
            TargetObservation(
                request.target.identity.machine, None, None,
                (ProcessNode(request.target.identity, None),), None, (),
            ),
        )
        response = Resolver().resolve(request, StaticCollector(snapshot))
        self.assertEqual(response, case["response"])

    def test_early_negative_protocol_fixtures(self) -> None:
        for case in self.values["negative"]:
            if case["name"] == "output-limit-does-not-truncate-ambiguity":
                continue
            with self.subTest(case=case["name"]):
                response = Resolver().resolve(case["request"], DenyCollector())
                expected = case["expected"]
                self.assertEqual(response["status"], expected["status"])
                self.assertEqual(len(response["candidates"]),
                                 expected["candidateCount"])
                self.assertTrue(any(
                    reason["code"] == expected["reasonCode"]
                    for reason in response["reasons"]
                ))


if __name__ == "__main__":
    unittest.main()
