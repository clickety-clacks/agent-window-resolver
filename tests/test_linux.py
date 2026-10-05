"""Pure raw collector parser tests; no live probes."""
from __future__ import annotations

import base64
import ipaddress
import json
import os
from pathlib import PurePath
import unittest
from unittest.mock import patch

from agent_window_resolver.collector import CommandResult, Deadline
from agent_window_resolver import (
    parse_request,
    Resolver,
    ProcessNode,
    StaticCollector,
    TopologySnapshot,
    Window,
    WindowObservation,
)
from agent_window_resolver.linux import CollectionFailure, DefaultProbeIO, LinuxCollector
import agent_window_resolver.linux as linux_module
from agent_window_resolver.model import (
    Limits,
    ProcessIdentity,
    Request,
    SocketSelector,
    Target,
    TmuxLocation,
)
from agent_window_resolver.resolver import _transport_hint
from agent_window_resolver.collector import transport_socket_eligible


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def stat_row(
    pid: int, parent: int, ticks: int, *, cpu: int = 0, state: str = "S"
) -> bytes:
    fields = [state, str(parent)] + ["0"] * 18
    fields[11] = str(cpu)
    fields[19] = str(ticks)
    return f"{pid} (fixture) ".encode() + " ".join(fields).encode() + b"\n"


def raw_node(
    pid: int,
    parent: int,
    ticks: int,
    *,
    after_cpu: int = 1,
    argv: tuple[str, ...] = (),
    environment: bytes = b"",
    inode: str | None = None,
    net_line: bytes | None = None,
    net_kind: str = "tcp",
) -> dict:
    net = {"tcp": [], "tcp6": [], "udp": [], "udp6": []}
    if net_kind not in net:
        raise ValueError("invalid fixture network kind")
    inodes: list[str] = []
    if inode is not None and net_line is not None:
        inodes.append(inode)
        net[net_kind].append(b64(net_line))
    return {
        "pid": pid,
        "parentPid": parent,
        "statBefore": b64(stat_row(pid, parent, ticks, cpu=0)),
        "statAfter": b64(stat_row(pid, parent, ticks, cpu=after_cpu)),
        "cmdlineBefore": b64(b"\0".join(item.encode() for item in argv) + (
            b"\0" if argv else b""
        )),
        "cmdlineAfter": b64(b"\0".join(item.encode() for item in argv) + (
            b"\0" if argv else b""
        )),
        "environmentBefore": b64(environment), "environmentAfter": b64(environment),
        "fdInodesBefore": inodes, "fdInodesAfter": list(inodes),
        "netLinesBefore": net,
        "netLinesAfter": {name: list(lines) for name, lines in net.items()},
        "tty": "",
    }


def tcp_row(inode: str) -> bytes:
    return (
        b"0: 0A0200C0:0016 0A0200C0:CCBB 01 "
        b"00000000:00000000 00:00000000 00000000 1000 0 "
        + inode.encode() + b" 1"
    )
def endpoint_row(inode: str, local_address: str, local_port: int,
                 remote_address: str, remote_port: int) -> bytes:
    local = ipaddress.IPv4Address(local_address).packed[::-1].hex().upper()
    remote = ipaddress.IPv4Address(remote_address).packed[::-1].hex().upper()
    return (
        f"0: {local}:{local_port:04X} {remote}:{remote_port:04X} 01 ".encode()
        + b"00000000:00000000 00:00000000 00000000 1000 0 "
        + inode.encode() + b" 1"
    )

class RunOnlyIO:
    def __init__(self) -> None:
        self.argv: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return False

    def read_bytes(self, path, max_bytes):
        raise AssertionError("unexpected proc read")

    def readlink(self, path, max_chars):
        raise AssertionError("unexpected link read")

    def listdir(self, path, max_entries):
        raise AssertionError("unexpected directory read")

    def run(self, argv, **kwargs):
        self.argv = tuple(argv)
        return CommandResult(1, b"")

    def monotonic(self) -> float:
        return 0.0


def tmux_request(machine: str, local: str) -> Request:
    return Request(
        "r", "verify-target", None,
        Target(
            ProcessIdentity(machine, 42, "99"), "agent",
            TmuxLocation("ask", "1", "%1", SocketSelector("name", "agents")),
        ),
        local, (), None, Limits(),
    )
def empty_target_output() -> dict:
    return {
        "socketPathBefore": "/tmp/tmux/socket",
        "socketPathAfter": "/tmp/tmux/socket",
        "paneLineBefore": "ask\t1\t%1\t600",
        "paneLineAfter": "ask\t1\t%1\t600",
        "clientLinesBefore": [],
        "clientLinesAfter": [],
        "paneProcess": raw_node(600, 1, 10),
        "processes": [
            raw_node(42, 600, 99), raw_node(600, 1, 10),
        ],
        "clients": [],
    }

def parse_boundary_client(
    processes: list[dict], boundary: str | None = None,
):
    output = empty_target_output()
    line = "client0\t500\tother\t9\t%9"
    output["clientLinesBefore"] = [line]
    output["clientLinesAfter"] = [line]
    client = {"line": line, "processes": processes}
    if boundary is not None:
        client["transportBoundary"] = boundary
    output["clients"] = [client]
    return LinuxCollector().parse_target_output(
        tmux_request("gibson", "osanwe"), json.dumps(output).encode(),
    )


def resolve_raw_transport(
    protocol: str, argv: tuple[str, ...], *, extra_pair: bool = False,
) -> dict:
    window = Window("window-1", "0xabc", 100, "20")
    request = Request(
        "r", "resolve", "linked_client",
        Target(
            ProcessIdentity("gibson", 42, "99"), "agent",
            TmuxLocation("ask", "1", "%1", SocketSelector("name", "agents")),
        ),
        "osanwe", (window,), None, Limits(),
    )
    server_port = 22 if protocol == "tcp" else 60002
    local_line = endpoint_row(
        "11", "192.0.2.10", 52411, "198.51.100.7", server_port
    )
    remote_line = endpoint_row(
        "22", "198.51.100.7", server_port, "192.0.2.10", 52411
    )
    collector = LinuxCollector()
    local_raw = [
        raw_node(100, 1, 20),
        raw_node(
            200, 100, 30, argv=argv, inode="11", net_line=local_line,
            net_kind=protocol,
        ),
    ]
    if extra_pair:
        local_raw.append(raw_node(
            201, 100, 31, argv=argv, inode="12",
            net_line=endpoint_row(
                "12", "192.0.2.10", 52412, "198.51.100.7", server_port,
            ),
            net_kind=protocol,
        ))
    local_nodes = collector.parse_process_bundle(
        "osanwe", local_raw, require_chain=False,
    )
    client_line = "client0\t500\tother\t9\t%9"
    if protocol == "tcp":
        client_processes = [
            raw_node(500, 501, 77),
            raw_node(
                501, 502 if extra_pair else 1, 78,
                environment=(
                    b"SSH_CONNECTION=192.0.2.10 52411 198.51.100.7 22"
                ),
            ),
        ]
        if extra_pair:
            client_processes.append(raw_node(
                502, 1, 79,
                environment=(
                    b"SSH_CONNECTION=192.0.2.10 52412 198.51.100.7 22"
                ),
            ))
    else:
        client_processes = [raw_node(
            500, 1, 77, inode="22", net_line=remote_line,
            net_kind="udp",
        )]
    target_output = {
        "socketPathBefore": "/tmp/tmux/socket",
        "socketPathAfter": "/tmp/tmux/socket",
        "paneLineBefore": "ask\t1\t%1\t600",
        "paneLineAfter": "ask\t1\t%1\t600",
        "clientLinesBefore": [client_line],
        "clientLinesAfter": [client_line],
        "paneProcess": raw_node(600, 1, 10),
        "processes": [
            raw_node(42, 600, 99),
            raw_node(600, 1, 10),
        ],
        "clients": [{
            "line": client_line,
            "processes": client_processes,
        }],
    }
    target_observation = collector.parse_target_output(
        request, json.dumps(target_output).encode()
    )
    snapshot = TopologySnapshot(
        (WindowObservation(window, local_nodes),), target_observation
    )

    return Resolver().resolve(request, StaticCollector(snapshot))

class LinuxParserTests(unittest.TestCase):
    def test_transport_socket_eligibility_matches_matcher_domain(self) -> None:
        cases = {
            ("ssh", "gibson"): True,
            ("mosh-client",): True,
            ("env", "-e", "ssh", "gibson", "tmux", "attach", "-t", "agent"): True,
            ("env", "-e", "mosh", "gibson", "tmux", "attach", "-t", "agent"): False,
            ("mosh", "gibson", "tmux", "attach", "-t", "agent"): False,
            ("1Password-Brows",): False,
        }
        for argv, expected in cases.items():
            with self.subTest(argv=argv):
                node = ProcessNode(
                    ProcessIdentity("osanwe", 10, "42"), None, argv
                )
                hint = _transport_hint(node)
                matcher_domain = (
                    (PurePath(argv[0]).name == "ssh")
                    or (hint is not None and hint.kind == "ssh")
                    or PurePath(argv[0]).name == "mosh-client"
                )
                self.assertEqual(transport_socket_eligible(argv), expected)
                self.assertEqual(transport_socket_eligible(argv), matcher_domain)

    def test_stat_counter_changes_do_not_change_identity(self) -> None:
        node = raw_node(10, 1, 42, after_cpu=99)
        parsed = LinuxCollector().parse_process_bundle("osanwe", [node])
        self.assertEqual(parsed[0].identity, ProcessIdentity("osanwe", 10, "42"))

    def test_allowlisted_ssh_environment_builds_full_endpoint(self) -> None:
        node = raw_node(
            10, 1, 42,
            environment=(
                b"SECRET=never-retained\0"
                b"SSH_CONNECTION=192.0.2.10 52411 198.51.100.7 22"
            ),
        )
        parsed = LinuxCollector().parse_process_bundle("gibson", [node])
        endpoint = parsed[0].ssh_endpoints[0]
        self.assertEqual(
            (endpoint.local_address, endpoint.local_port,
             endpoint.remote_address, endpoint.remote_port),
            ("198.51.100.7", 22, "192.0.2.10", 52411),
        )

    def test_raw_proc_net_parser_decodes_complete_tuple(self) -> None:
        node = raw_node(10, 1, 42, inode="123", net_line=tcp_row("123"))
        parsed = LinuxCollector().parse_process_bundle("osanwe", [node])
        endpoint = parsed[0].endpoints[0]
        self.assertEqual(endpoint.protocol, "tcp")
        self.assertEqual(endpoint.address_family, "ipv4")
        self.assertEqual((endpoint.local_port, endpoint.remote_port),
                         (22, 52411))

    def test_socket_counters_can_change_when_tuple_is_stable(self) -> None:
        node = raw_node(10, 1, 42, inode="123", net_line=tcp_row("123"))
        after = tcp_row("123").replace(b"00000000:00000000",
                                       b"00000001:00000000", 1)
        node["netLinesAfter"]["tcp"] = [b64(after)]
        parsed = LinuxCollector().parse_process_bundle("osanwe", [node])
        self.assertEqual(len(parsed[0].endpoints), 1)
    def test_target_parser_rejects_truncated_ancestry(self) -> None:
        request = Request(
            "r", "verify-target", None,
            Target(
                ProcessIdentity("gibson", 42, "99"), "agent",
                TmuxLocation("ask", "1", "%1",
                             SocketSelector("name", "agents")),
            ),
            "osanwe", (), None, Limits(),
        )
        output = {
            "socketPathBefore": "/tmp/tmux/socket",
            "socketPathAfter": "/tmp/tmux/socket",
            "paneLineBefore": "ask\t1\t%1\t600",
            "paneLineAfter": "ask\t1\t%1\t600",
            "clientLinesBefore": [],
            "clientLinesAfter": [],
            "paneProcess": raw_node(600, 1, 10),
            "processes": [raw_node(42, 500, 99)],
            "clients": [],
        }
        with self.assertRaises(Exception):
            LinuxCollector().parse_target_output(
                request, json.dumps(output).encode()
            )

    def test_target_parser_accepts_only_verified_explicit_pane_boundary(self) -> None:
        output = empty_target_output()
        output["paneProcess"] = raw_node(600, 999, 10)
        output["processes"] = [
            raw_node(42, 600, 99), raw_node(600, 999, 10),
        ]
        output["targetBoundary"] = {
            "kind": "pane", "pid": 600, "startTimeTicks": "10",
        }
        observed = LinuxCollector().parse_target_output(
            tmux_request("gibson", "osanwe"), json.dumps(output).encode()
        )
        self.assertEqual(observed.processes[-1].identity,
                         ProcessIdentity("gibson", 600, "10"))

        cases = {
            "wrong-boundary-pid": {
                **output, "targetBoundary": {
                    "kind": "pane", "pid": 601, "startTimeTicks": "10",
                },
            },
            "wrong-boundary-ticks": {
                **output, "targetBoundary": {
                    "kind": "pane", "pid": 600, "startTimeTicks": "11",
                },
            },
            "nonterminal-boundary": {
                **output,
                "processes": [
                    raw_node(42, 600, 99), raw_node(600, 700, 10),
                    raw_node(700, 1, 11),
                ],
            },
        }
        for name, invalid in cases.items():
            with self.subTest(name=name), self.assertRaises(CollectionFailure):
                LinuxCollector().parse_target_output(
                    tmux_request("gibson", "osanwe"),
                    json.dumps(invalid).encode(),
                )

    def test_client_ssh_boundary_accepts_complete_final_node(self) -> None:
        environment = (
            b"SSH_CONNECTION=192.0.2.10 52411 198.51.100.7 22"
        )
        observed = parse_boundary_client(
            [raw_node(500, 999, 77, environment=environment)],
            "ssh_environment",
        )
        self.assertEqual(observed.clients[0].process.pid, 500)
        self.assertEqual(len(observed.clients[0].processes), 1)

    def test_client_without_boundary_rejects_truncated_ancestry(self) -> None:
        with self.assertRaises(CollectionFailure):
            parse_boundary_client([raw_node(500, 999, 77)])

    def test_client_boundary_rejects_unknown_or_mismatched_marker(self) -> None:
        udp = endpoint_row(
            "22", "198.51.100.7", 60002, "192.0.2.10", 52411,
        )
        node = raw_node(
            500, 999, 77, argv=("ssh",), inode="22",
            net_line=udp, net_kind="udp",
        )
        for marker in ("unknown", "ssh_environment", "mosh_udp"):
            with self.subTest(marker=marker):
                with self.assertRaises(CollectionFailure):
                    parse_boundary_client([node], marker)

    def test_client_ssh_boundary_requires_one_complete_connection(self) -> None:
        connection = b"SSH_CONNECTION=192.0.2.10 52411 198.51.100.7 22"
        invalid = (
            b"SSH_CLIENT=192.0.2.10 52411 22",
            b"SSH_CONNECTION=192.0.2.10 52411 0.0.0.0 22",
            connection + b"\0" + connection,
        )
        for environment in invalid:
            with self.subTest(environment=environment):
                with self.assertRaises(CollectionFailure):
                    parse_boundary_client(
                        [raw_node(500, 999, 77, environment=environment)],
                        "ssh_environment",
                    )

    def test_client_boundary_must_describe_final_node(self) -> None:
        connection = b"SSH_CONNECTION=192.0.2.10 52411 198.51.100.7 22"
        with self.assertRaises(CollectionFailure):
            parse_boundary_client(
                [
                    raw_node(500, 501, 77, environment=connection),
                    raw_node(501, 999, 78),
                ],
                "ssh_environment",
            )

    def test_client_mosh_boundary_accepts_one_complete_udp_tuple(self) -> None:
        udp = endpoint_row(
            "22", "198.51.100.7", 60002, "192.0.2.10", 52411,
        )
        observed = parse_boundary_client(
            [
                raw_node(
                    500, 999, 77, argv=("mosh-server",), inode="22",
                    net_line=udp, net_kind="udp",
                ),
            ],
            "mosh_udp",
        )
        self.assertEqual(observed.clients[0].process.pid, 500)

    def test_client_mosh_boundary_rejects_multiple_udp_tuples(self) -> None:
        node = raw_node(
            500, 999, 77, argv=("mosh-server",), inode="22",
            net_line=endpoint_row(
                "22", "198.51.100.7", 60002, "192.0.2.10", 52411,
            ),
            net_kind="udp",
        )
        second = b64(endpoint_row(
            "23", "198.51.100.7", 60003, "192.0.2.10", 52412,
        ))
        node["fdInodesBefore"].append("23")
        node["fdInodesAfter"].append("23")
        node["netLinesBefore"]["udp"].append(second)
        node["netLinesAfter"]["udp"].append(second)
        with self.assertRaises(CollectionFailure):
            parse_boundary_client([node], "mosh_udp")

    def test_client_mosh_boundary_rejects_duplicate_raw_row(self) -> None:
        node = raw_node(
            500, 999, 77, argv=("mosh-server",), inode="22",
            net_line=endpoint_row(
                "22", "198.51.100.7", 60002, "192.0.2.10", 52411,
            ),
            net_kind="udp",
        )
        duplicate = node["netLinesBefore"]["udp"][0]
        node["netLinesBefore"]["udp"].append(duplicate)
        node["netLinesAfter"]["udp"].append(duplicate)
        with self.assertRaises(CollectionFailure):
            parse_boundary_client([node], "mosh_udp")


    def test_client_boundary_rejects_mixed_transport_evidence(self) -> None:
        node = raw_node(
            500, 999, 77, argv=("mosh-server",),
            environment=b"SSH_CONNECTION=192.0.2.10 52411 198.51.100.7 22",
            inode="22",
            net_line=endpoint_row(
                "22", "198.51.100.7", 60002, "192.0.2.10", 52411,
            ),
            net_kind="udp",
        )
        for marker in ("ssh_environment", "mosh_udp"):
            with self.subTest(marker=marker):
                with self.assertRaises(CollectionFailure):
                    parse_boundary_client([node], marker)


    def test_client_boundary_rejects_self_parent_cycle(self) -> None:
        connection = b"SSH_CONNECTION=192.0.2.10 52411 198.51.100.7 22"
        with self.assertRaises(CollectionFailure):
            parse_boundary_client(
                [raw_node(500, 500, 77, environment=connection)],
                "ssh_environment",
            )


    def test_falsey_injected_io_is_preserved(self) -> None:
        io = RunOnlyIO()
        collector = LinuxCollector(io)
        self.assertIs(collector.io, io)

    def test_default_io_omits_only_its_transient_scandir_fd(self) -> None:
        path = f"/proc/{os.getpid()}/fd"
        names = DefaultProbeIO().listdir(path, 1024)
        for name in names:
            self.assertNotEqual(os.path.normpath(os.readlink(f"{path}/{name}")), path)

    def test_default_io_self_fd_filter_does_not_hide_other_vanishing_fd(self) -> None:
        path = f"/proc/{os.getpid()}/fd"

        class Scan:
            def __enter__(self):
                return iter((type("Entry", (), {"name": "3", "path": path + "/3"})(),
                             type("Entry", (), {"name": "9", "path": path + "/9"})()))

            def __exit__(self, *_args):
                return False

        with patch.object(linux_module.os, "scandir", return_value=Scan()), \
             patch.object(linux_module.os, "readlink", side_effect=[path, FileNotFoundError(path + "/9")]):
            with self.assertRaises(FileNotFoundError):
                DefaultProbeIO().listdir(path, 1024)

    def test_default_io_proc_link_bound_handles_long_path_and_rejects_overflow(self) -> None:
        with patch.object(linux_module.os, "readlink", return_value="x" * 129):
            self.assertEqual(
                DefaultProbeIO().readlink("/proc/1/fd/0", 4096), "x" * 129
            )
        with patch.object(linux_module.os, "readlink", return_value="x" * 4097):
            with self.assertRaises(CollectionFailure):
                DefaultProbeIO().readlink("/proc/1/fd/0", 4096)

    def test_short_and_fqdn_alias_uses_local_probe(self) -> None:
        io = RunOnlyIO()
        collector = LinuxCollector(io)
        with self.assertRaises(CollectionFailure):
            collector._target_probe(
                tmux_request("host.example", "host"), Deadline(1000, io.monotonic)
            )
        self.assertEqual(io.argv[0], "python3")

    def test_conflicting_fqdns_use_hardened_ssh_probe(self) -> None:
        io = RunOnlyIO()
        collector = LinuxCollector(io)
        with self.assertRaises(CollectionFailure):
            collector._target_probe(
                tmux_request("host.example", "host.other"), Deadline(1000, io.monotonic)
            )
        self.assertEqual(io.argv[0], "ssh")
        joined = " ".join(io.argv)
        for option in ("ControlMaster=no", "ControlPath=none",
                       "ClearAllForwardings=yes", "PermitLocalCommand=no"):
            self.assertIn(option, joined)
    def test_bare_interactive_ssh_full_tuple_matches(self) -> None:
        response = resolve_raw_transport("tcp", ("ssh", "gibson"))
        self.assertEqual(response["status"], "matched")
        self.assert_endpoint_pair(response, "tcp")

    def test_execed_mosh_client_udp_full_tuple_matches(self) -> None:
        response = resolve_raw_transport("udp", ("mosh-client",))
        self.assertEqual(response["status"], "matched")
        self.assert_endpoint_pair(response, "udp")

    def test_distinct_matching_endpoint_pairs_are_not_unique(self) -> None:
        response = resolve_raw_transport(
            "tcp", ("ssh", "gibson"), extra_pair=True,
        )
        self.assertEqual(response["status"], "unresolved")
        self.assertEqual(response["candidates"], [])

    def assert_endpoint_pair(self, response: dict, protocol: str) -> None:
        evidence = response["candidates"][0]["proof"]["evidence"]
        link = next(item for item in evidence
                    if item["code"] == "tmux_client_linked")
        details = link["details"]
        self.assertEqual(
            set(details),
            {"pid", "startTimeTicks", "localEndpoint", "targetEndpoint"},
        )
        left = details["localEndpoint"]
        right = details["targetEndpoint"]
        for endpoint in (left, right):
            self.assertEqual(
                set(endpoint),
                {"protocol", "addressFamily", "local", "remote"},
            )
            self.assertEqual(set(endpoint["local"]), {"address", "port"})
            self.assertEqual(set(endpoint["remote"]), {"address", "port"})
            self.assertEqual(endpoint["protocol"], protocol)
        self.assertEqual(left["addressFamily"], right["addressFamily"])
        self.assertEqual(left["local"], right["remote"])
        self.assertEqual(left["remote"], right["local"])
        candidate = response["candidates"][0]
        target = candidate["target"]
        parsed = parse_request({
            "schema": "agent-window-resolver.request.v1",
            "requestId": "endpoint-evidence-revalidate",
            "operation": "revalidate",
            "requestedRelation": "linked_client",
            "target": {
                "identity": target["identity"],
                "tmux": target["location"]["tmux"],
            },
            "local": {"machine": "osanwe"},
            "windows": [candidate["window"]],
            "prior": candidate,
        })
        self.assertEqual(parsed.prior.relation, "linked_client")

    def test_raw_bundle_rejects_command_exec_race(self) -> None:
        node = raw_node(10, 1, 42, argv=("ssh", "gibson"))
        node["cmdlineAfter"] = b64(b"unrelated\0")
        with self.assertRaises(Exception):
            LinuxCollector().parse_process_bundle("osanwe", [node])

    def test_target_parser_rejects_changed_tmux_metadata(self) -> None:
        output = empty_target_output()
        output["paneLineAfter"] = "ask\t2\t%2\t600"
        with self.assertRaises(CollectionFailure):
            LinuxCollector().parse_target_output(
                tmux_request("gibson", "osanwe"), json.dumps(output).encode()
            )

    def test_target_parser_rejects_duplicate_client_identity(self) -> None:
        output = empty_target_output()
        first = "client0\t500\task\t1\t%1"
        second = "client1\t500\task\t1\t%1"
        output["clientLinesBefore"] = [first, second]
        output["clientLinesAfter"] = [first, second]
        client = {"line": first, "processes": [raw_node(500, 1, 77)]}
        output["clients"] = [client, {**client, "line": second}]
        with self.assertRaises(CollectionFailure):
            LinuxCollector().parse_target_output(
                tmux_request("gibson", "osanwe"), json.dumps(output).encode()
            )


if __name__ == "__main__":
    unittest.main()
