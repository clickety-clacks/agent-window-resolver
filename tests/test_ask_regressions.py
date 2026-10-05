"""Ask resolver regressions driven by raw topology fixture data."""
from __future__ import annotations

import json
import copy
from pathlib import Path
from typing import Any

from agent_window_resolver.collector import ObservationError, ProcessNode, StaticCollector, TargetObservation, TmuxClient, TmuxPane, TopologySnapshot, WindowObservation
from agent_window_resolver.model import ProcessIdentity, SocketSelector, Window, parse_request
from agent_window_resolver.linux import LinuxCollector
from agent_window_resolver.resolver import Resolver

FIXTURE = Path(__file__).parents[1] / "fixtures" / "ask-regressions-v1.json"


def _fixture() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _identity(fixture: dict[str, Any], value: str | dict[str, Any] | None) -> ProcessIdentity | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = fixture["identities"][value]
    return ProcessIdentity(value["machine"], value["pid"], value["startTimeTicks"])


def _process(fixture: dict[str, Any], value: str | dict[str, Any]) -> ProcessNode:
    record = fixture["processes"][value] if isinstance(value, str) else value
    return ProcessNode(_identity(fixture, record["identity"]), _identity(fixture, record.get("parent")), tuple(record.get("argv", ())))  # type: ignore[arg-type]


def _socket(value: dict[str, str] | None) -> SocketSelector | None:
    return None if value is None else SocketSelector(value["kind"], value["value"])


def _window(value: dict[str, Any]) -> Window:
    return Window(value["stableId"], value["address"], value["pid"], value["startTimeTicks"], value.get("class"))


def _pane(fixture: dict[str, Any], value: dict[str, Any] | None) -> TmuxPane | None:
    if value is None:
        return None
    return TmuxPane(value["session"], value["windowIndex"], value["paneId"], _identity(fixture, value["process"]))  # type: ignore[arg-type]


def _client(fixture: dict[str, Any], value: dict[str, Any]) -> TmuxClient:
    return TmuxClient(value["name"], _identity(fixture, value["process"]), value["currentSession"], value["currentWindowIndex"], value["currentPaneId"], tuple(_process(fixture, item) for item in value.get("processes", ())))  # type: ignore[arg-type]


def _snapshot(fixture: dict[str, Any], value: dict[str, Any]) -> TopologySnapshot:
    windows = tuple(WindowObservation(_window(item["window"]), tuple(_process(fixture, node) for node in item.get("processes", ())), item.get("collectionState", "complete"), tuple(ObservationError(error["code"], error["source"], error["message"], error.get("retryable", False)) for error in item.get("errors", ()))) for item in value["windows"])
    target = value["target"]
    return TopologySnapshot(windows, TargetObservation(target["machine"], _socket(target.get("socket")), target.get("actualSocketPath"), tuple(_process(fixture, node) for node in target.get("processes", ())), _pane(fixture, target.get("pane")), tuple(_client(fixture, client) for client in target.get("clients", ())), target.get("collectionState", "complete"), tuple(ObservationError(error["code"], error["source"], error["message"], error.get("retryable", False)) for error in target.get("errors", ()))))


class _NoProbeIO:
    """Guard parser tests against accidentally crossing into live IO."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"parser unexpectedly used ProbeIO.{name}")


def _raw_collector() -> LinuxCollector:
    return LinuxCollector(io=_NoProbeIO())


def _target_output(raw: dict[str, Any], client_name: str) -> dict[str, Any]:
    output = copy.deepcopy(raw["targetOutputTemplate"])
    client = copy.deepcopy(raw[client_name])
    output["clientLinesBefore"] = [client["line"]]
    output["clientLinesAfter"] = [client["line"]]
    output["clients"] = [client]
    return output


def test_ask_graph_regressions_use_real_static_collector_matcher() -> None:
    fixture = _fixture()
    assert fixture["schema"] == "agent-window-resolver.ask-regressions.v1"
    for case in fixture["graphCases"]:
        result = Resolver().resolve(case["request"], StaticCollector(_snapshot(fixture, case["snapshot"])))
        expected = case["expected"]
        assert result["status"] == expected["status"], case["name"]
        assert len(result["candidates"]) == expected["candidateCount"], case["name"]
        if "reasonCode" in expected:
            assert any(reason["code"] == expected["reasonCode"] for reason in result["reasons"]), case["name"]


def test_raw_io_vectors_are_unparsed_and_not_preverified() -> None:
    fixture = _fixture()
    assert {case["name"] for case in fixture["rawIoCases"]} == {"mosh-session-only", "ssh-full-tuple-with-environment-fallback"}
    for case in fixture["rawIoCases"]:
        assert "probe" in case and "expected" in case
        assert case["layer"] == "documentation_only"
        assert case["expected"] == {"status": "not_executed"}


def test_remote_json_consumer_and_true_parser_are_separate_layers() -> None:
    fixture = _fixture()
    assert fixture["remoteJsonCases"][0]["layer"] == "remote_json_consumer"
    payload = fixture["remoteJsonCases"][0]["payload"]
    assert payload["socketPath"].startswith("/")
    assert fixture["trueRemoteParser"]["status"] == "not_covered_by_reserved_tests"


def test_mosh_raw_process_parser_reaches_matcher_with_client_udp_correlation() -> None:
    fixture = _fixture()
    raw = fixture["rawParserCases"]
    collector = _raw_collector()
    nodes = collector.parse_process_bundle("lumen", raw["moshProcessBundle"], require_chain=True)
    assert {node.identity.pid for node in nodes} == {700, 701, 703}
    mosh_client = next(node for node in nodes if node.identity.pid == 701)
    shell = next(node for node in nodes if node.identity.pid == 703)
    terminal = next(node for node in nodes if node.identity.pid == 700)
    assert mosh_client.parent == shell.identity
    assert shell.parent == terminal.identity
    assert terminal.parent is None
    assert mosh_client.argv[0] == "/usr/bin/mosh-client"
    assert mosh_client.endpoints[0].protocol == "udp"
    assert mosh_client.endpoints[0].local_port == 60000
    assert mosh_client.endpoints[0].remote_port == 60001

    request_value = copy.deepcopy(raw["targetRequest"])
    request_value["requestId"] = "ask-raw-mosh"
    request_value["windows"] = [{"stableId": "raw-mosh-window", "address": "0x202", "pid": 700, "startTimeTicks": "7000"}]
    request = parse_request(request_value)
    target = collector.parse_target_output(
        request, json.dumps(_target_output(raw, "moshRemoteClient")).encode()
    )
    remote_client = target.clients[0]
    assert remote_client.process.pid == 800
    remote_mosh_server = next(
        node for node in remote_client.processes if node.identity.pid == 801
    )
    assert next(
        node for node in remote_client.processes if node.identity.pid == 800
    ).parent == remote_mosh_server.identity
    assert remote_mosh_server.argv[0] == "/usr/bin/mosh-server"
    assert len(remote_mosh_server.endpoints) == 1
    assert remote_mosh_server.endpoints[0].protocol == "udp"
    assert remote_mosh_server.endpoints[0].local_port == 60001
    assert remote_mosh_server.endpoints[0].remote_port == 60000

    snapshot = TopologySnapshot(
        (WindowObservation(request.windows[0], nodes),), target
    )
    result = Resolver().resolve(request, StaticCollector(snapshot))
    assert result["status"] == "matched"
    assert len(result["candidates"]) == 1
    assert result["candidates"][0]["proof"]["relation"] == "visible_exact"
    link = result["candidates"][0]["proof"]["evidence"][-1]
    assert link["source"] == "socket"
    assert link["details"]["localEndpoint"]["protocol"] == "udp"
    assert link["details"]["targetEndpoint"]["protocol"] == "udp"


def test_ssh_local_socket_links_to_remote_environment_only_endpoint() -> None:
    fixture = _fixture()
    raw = fixture["rawParserCases"]
    collector = _raw_collector()
    nodes = collector.parse_process_bundle("lumen", raw["sshProcessBundle"], require_chain=True)
    ssh = nodes[0]
    assert ssh.identity.pid == 702
    assert len(ssh.endpoints) == 1
    assert ssh.ssh_endpoints == ()
    assert ssh.endpoints[0].local_address == "192.0.2.10"
    assert ssh.endpoints[0].local_port == 52411
    assert ssh.endpoints[0].remote_address == "198.51.100.7"
    assert ssh.endpoints[0].remote_port == 22
    request = parse_request(raw["targetRequest"])
    target = collector.parse_target_output(
        request, json.dumps(_target_output(raw, "sshRemoteClient")).encode()
    )
    remote_client = target.clients[0]
    remote_process = remote_client.processes[0]
    assert remote_process.endpoints == ()
    assert len(remote_process.ssh_endpoints) == 1
    assert remote_process.ssh_endpoints[0].local_address == "198.51.100.7"
    assert remote_process.ssh_endpoints[0].local_port == 22
    assert remote_process.ssh_endpoints[0].remote_address == "192.0.2.10"
    assert remote_process.ssh_endpoints[0].remote_port == 52411

    snapshot = TopologySnapshot(
        (WindowObservation(request.windows[0], nodes),), target
    )
    result = Resolver().resolve(request, StaticCollector(snapshot))
    assert result["status"] == "matched"
    assert result["candidates"][0]["proof"]["relation"] == "visible_exact"
    link = result["candidates"][0]["proof"]["evidence"][-1]
    assert link["source"] == "socket"
    assert link["details"]["localEndpoint"]["local"]["address"] == "192.0.2.10"
    assert link["details"]["targetEndpoint"]["local"]["address"] == "198.51.100.7"


def test_raw_parser_rejects_identity_change_and_wrong_endpoint_stays_unresolved() -> None:
    fixture = _fixture()
    raw = fixture["rawParserCases"]
    collector = _raw_collector()
    changed = copy.deepcopy(raw["sshProcessBundle"])
    changed[0]["statAfter"] = raw["negative"]["identityChangedStatAfter"]
    try:
        collector.parse_process_bundle("lumen", changed, require_chain=True)
    except ValueError:
        pass
    else:
        raise AssertionError("changed process ticks must be rejected")

    request = parse_request(raw["targetRequest"])
    wrong_bundle = copy.deepcopy(raw["sshProcessBundle"])
    wrong_lines = {
        "tcp": [raw["wrongLocalEndpointNetLine"]],
        "tcp6": [],
        "udp": [],
        "udp6": [],
    }
    wrong_bundle[0]["netLinesBefore"] = copy.deepcopy(wrong_lines)
    wrong_bundle[0]["netLinesAfter"] = copy.deepcopy(wrong_lines)
    nodes = collector.parse_process_bundle(
        "lumen", wrong_bundle, require_chain=True
    )
    assert nodes[0].endpoints[0].local_address == "192.0.2.11"
    assert nodes[0].ssh_endpoints == ()

    wrong_output = _target_output(raw, "sshRemoteClient")
    wrong_process = wrong_output["clients"][0]["processes"][0]
    wrong_process["environmentBefore"] = ""
    wrong_process["environmentAfter"] = ""
    target = collector.parse_target_output(
        request, json.dumps(wrong_output).encode()
    )
    assert target.clients[0].processes[0].endpoints == ()
    assert target.clients[0].processes[0].ssh_endpoints == ()
    snapshot = TopologySnapshot(
        (WindowObservation(request.windows[0], nodes),), target
    )
    result = Resolver().resolve(request, StaticCollector(snapshot))
    assert result["status"] == "unresolved"
    assert len(result["candidates"]) == 0
    assert any(reason["code"] == raw["negative"]["wrongEndpoint"] for reason in result["reasons"])
