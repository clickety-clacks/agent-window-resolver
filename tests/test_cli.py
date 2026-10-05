"""Pure CLI framing tests with injected streams and resolver."""
from __future__ import annotations

from io import BytesIO
import json
import unittest
from unittest import mock

from agent_window_resolver.cli import run


class DenyCollector:
    def collect(self, request, deadline):
        raise AssertionError("CLI parser test attempted collection")

class FalseyDenyCollector(DenyCollector):
    def __bool__(self) -> bool:
        return False


class FixedResolver:
    def __init__(self, response: dict) -> None:
        self.response = response
        self.collector = None

    def resolve(self, request, collector):
        self.collector = collector
        return self.response


def valid_request(*, max_stdout_bytes: int | None = None) -> dict:
    value = {
        "schema": "agent-window-resolver.request.v1",
        "requestId": "r", "operation": "verify-target",
        "target": {"identity": {
            "machine": "lumen", "instanceId": "agent",
            "pid": 2, "startTimeTicks": "1",
        }},
        "local": {"machine": "lumen"}, "windows": [],
    }
    if max_stdout_bytes is not None:
        value["limits"] = {"maxStdoutBytes": max_stdout_bytes}
    return value


class CliTests(unittest.TestCase):
    def invoke(self, value: bytes, *, collector=None,
               resolver=None) -> tuple[int, dict]:
        output = BytesIO()
        error = BytesIO()
        code = run(
            [], stdin=BytesIO(value), stdout=output, stderr=error,
            collector=DenyCollector() if collector is None else collector,
            resolver=resolver,
        )
        return code, json.loads(output.getvalue())

    def test_unhashable_operation_is_structured_invalid(self) -> None:
        code, response = self.invoke(
            json.dumps({"operation": []}).encode()
        )
        self.assertEqual(code, 2)
        self.assertEqual(response["status"], "invalid")
        self.assertIsNone(response["operation"])

    def test_explicit_null_limits_is_invalid(self) -> None:
        request = {
            "schema": "agent-window-resolver.request.v1",
            "requestId": "r",
            "operation": "verify-target",
            "target": {
                "identity": {
                    "machine": "lumen", "instanceId": "agent",
                    "pid": 2, "startTimeTicks": "1",
                }
            },
            "local": {"machine": "lumen"},
            "windows": [],
            "limits": None,
        }
        code, response = self.invoke(json.dumps(request).encode())
        self.assertEqual(code, 2)
        self.assertEqual(response["status"], "invalid")

    def test_oversized_input_is_rejected_without_collector(self) -> None:
        code, response = self.invoke(b"{" + b"x" * 262_144)
        self.assertEqual(code, 2)
        self.assertEqual(response["reasons"][0]["code"], "request_too_large")

    def test_lone_surrogate_request_id_is_not_echoed(self) -> None:
        code, response = self.invoke(
            b'{"schema":"bad","requestId":"\\ud800","operation":[]}'
        )
        self.assertEqual(code, 2)
        self.assertIsNone(response["requestId"])

    def test_lone_surrogate_in_valid_shape_is_invalid(self) -> None:
        request = {
            "schema": "agent-window-resolver.request.v1",
            "requestId": "r",
            "operation": "verify-target",
            "target": {
                "identity": {
                    "machine": "lumen", "instanceId": "agent\ud800",
                    "pid": 2, "startTimeTicks": "1",
                }
            },
            "local": {"machine": "lumen"},
            "windows": [],
        }
        code, response = self.invoke(json.dumps(request).encode())
        self.assertEqual(code, 2)
        self.assertEqual(response["status"], "invalid")

    def test_deeply_nested_json_is_structured_invalid(self) -> None:
        value = b"[" * 2000 + b"]" * 2000
        code, response = self.invoke(value)
        self.assertEqual(code, 2)
        self.assertEqual(response["status"], "invalid")

    def test_json_recursion_error_is_structured_invalid(self) -> None:
        output = BytesIO()
        with mock.patch(
            "agent_window_resolver.cli.json.loads",
            side_effect=RecursionError("nesting limit"),
        ):
            code = run([], stdin=BytesIO(b"[]"), stdout=output,
                       stderr=BytesIO(), collector=DenyCollector())
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "invalid")

    def test_framing_timeout_is_unreachable_exit_five(self) -> None:
        with mock.patch(
            "agent_window_resolver.cli._read_bounded",
            side_effect=TimeoutError("stdin framing deadline expired"),
        ):
            code, response = self.invoke(b"")
        self.assertEqual(code, 5)
        self.assertEqual(response["status"], "unreachable")

    def test_output_overflow_never_truncates_ambiguity_to_match(self) -> None:
        resolver = FixedResolver({
            "schema": "agent-window-resolver.response.v1", "requestId": "r",
            "operation": "verify-target", "status": "ambiguous",
            "candidates": [{"padding": "x" * 5000}],
            "evidence": [], "reasons": [],
        })
        code, response = self.invoke(
            json.dumps(valid_request(max_stdout_bytes=4096)).encode(),
            resolver=resolver,
        )
        self.assertEqual(code, 4)
        self.assertEqual(response["status"], "invalid")
        self.assertEqual(response["candidates"], [])
        self.assertEqual(response["reasons"][0]["code"], "output_limit_exceeded")

    def test_falsey_injected_collector_is_preserved(self) -> None:
        collector = FalseyDenyCollector()
        resolver = FixedResolver({
            "schema": "agent-window-resolver.response.v1", "requestId": "r",
            "operation": "verify-target", "status": "verified",
            "candidates": [], "evidence": [], "reasons": [],
        })
        code, _ = self.invoke(json.dumps(valid_request()).encode(),
                              collector=collector, resolver=resolver)
        self.assertEqual(code, 0)
        self.assertIs(resolver.collector, collector)


if __name__ == "__main__":
    unittest.main()
