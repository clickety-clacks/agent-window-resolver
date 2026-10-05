"""Execute the frozen normalization fixture against core endpoint semantics."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from agent_window_resolver import Endpoint
from agent_window_resolver.resolver import endpoint_linked


FIXTURE = Path(__file__).parents[1] / "fixtures" / "normalization-v1.json"


def endpoint(value: dict) -> Endpoint:
    return Endpoint(
        value["protocol"],
        value["addressFamily"],
        value["local"]["address"],
        value["local"]["port"],
        value["remote"]["address"],
        value["remote"]["port"],
    )


class NormalizationFixtureTests(unittest.TestCase):
    def test_endpoint_link_fixtures(self) -> None:
        values = json.loads(FIXTURE.read_text(encoding="utf-8"))
        for case in values["endpointLinks"]:
            with self.subTest(case=case["name"]):
                self.assertEqual(
                    endpoint_linked(endpoint(case["left"]), endpoint(case["right"])),
                    case["linked"],
                )


if __name__ == "__main__":
    unittest.main()
