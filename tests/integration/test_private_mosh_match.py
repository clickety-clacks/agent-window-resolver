"""Opt-in private mosh-to-tmux visible_exact matcher smoke.

This is a separate gate from the private mosh startup smoke.  It proves one
actual tmux attachment, a stable reversed loopback UDP pair, the real remote
producer, and the real resolver.  Importing the module is inert.
"""
from __future__ import annotations

import importlib.util
import math
import os
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

from agent_window_resolver import Resolver, Window
from agent_window_resolver.linux import LinuxCollector
from agent_window_resolver.model import Limits, Request
from agent_window_resolver.resolver import endpoint_linked


MATCH_OPT_IN_ENV = "AGENT_WINDOW_PRIVATE_MOSH_MATCH_LIVE"
ATTACH_TIMEOUT = 3.0
UDP_TIMEOUT = 3.0
POLL_SECONDS = 0.04
MAX_TRANSPORT_DEPTH = 8
MAX_ATTACH_QUERIES = math.ceil(ATTACH_TIMEOUT / POLL_SECONDS) + 2
MAX_QUERY_RETRIES = 16
MAX_UDP_POLLS = math.ceil(UDP_TIMEOUT / POLL_SECONDS) + 2
MAX_CLIENT_LINE_BYTES = 1024
MAX_REPORT_CHARS = 768
LIST_CLIENTS_FORMAT = (
    "#{client_name}\t#{client_pid}\t#{client_session}\t"
    "#{window_index}\t#{pane_id}"
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load integration support: {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).resolve().parent
ssh_match = _load(
    "_private_mosh_match_ssh_support",
    HERE / "test_private_ssh_match.py",
)
YOOHOO_INTEGRATION = (
    HERE.parents[2] / "yoohoo-hub-work" / "tests" / "integration"
)
startup = _load(
    "_private_mosh_match_startup_support",
    YOOHOO_INTEGRATION / "private_mosh_smoke.py",
)

connection = startup.connection
mosh = startup.mosh
private_sshd = mosh.private_sshd
RestrictedProcessRootProbeIO = ssh_match.RestrictedAttachmentProbeIO
producer_support = ssh_match.support


class MoshMatchFailure(RuntimeError):
    """The bounded live topology proof was incomplete or ambiguous."""


def _live_authorized() -> bool:
    return (
        os.environ.get(MATCH_OPT_IN_ENV, "").strip() == "1"
        and os.environ.get(startup.MOSH_OPT_IN_ENV, "").strip() == "1"
        and connection.live_test_authorized()
    )


def _request(
    snapshot: connection.PrivatePaneSnapshot,
    client: private_sshd.ProcessIdentity,
) -> Request:
    target_request, _remote = producer_support._request_and_remote(snapshot)
    return Request(
        "private-mosh-visible-match",
        "resolve",
        "visible_exact",
        target_request.target,
        producer_support._LOCAL_MACHINE,
        (
            Window(
                "synthetic-private-mosh",
                "0xf00d",
                client.pid,
                str(client.start_ticks),
                "synthetic-test-root",
            ),
        ),
        None,
        Limits(deadline_ms=20_000),
    )


def _client_fields(
    raw: bytes,
    snapshot: connection.PrivatePaneSnapshot,
) -> tuple[str, int] | None:
    if not raw:
        return None
    if (
        len(raw) > MAX_CLIENT_LINE_BYTES
        or not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
        or b"\r" in raw
        or b"\0" in raw
    ):
        raise MoshMatchFailure("private tmux client row structure changed")
    try:
        fields = raw[:-1].decode("utf-8", "strict").split("\t")
        pid = int(fields[1])
    except (UnicodeError, ValueError, IndexError) as error:
        raise MoshMatchFailure("private tmux client row was invalid") from error
    if (
        len(fields) != 5
        or not 1 <= len(fields[0].encode()) <= 256
        or any(ord(character) < 32 or ord(character) == 127 for character in fields[0])
        or pid <= 1
        or fields[2:] != [
            snapshot.session,
            snapshot.window_index,
            snapshot.pane_id,
        ]
    ):
        raise MoshMatchFailure("private tmux client did not select the target pane")
    return fields[0], pid


def _query_clients(
    fixture: connection.ConnectionFixture,
    mosh_fixture: mosh.PrivateMoshFixture,
    deadline: float,
) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _attachment_failure(
            fixture,
            mosh_fixture,
            "private tmux attachment proof timed out",
        )
    command = fixture._tmux_command(
        "list-clients", "-F", LIST_CLIENTS_FORMAT
    )
    status, raw = fixture._bounded_tmux_query(
        command, timeout=min(remaining, 0.5)
    )
    if status != 0:
        _attachment_failure(
            fixture,
            mosh_fixture,
            "private tmux client query failed",
        )
    return raw


def _attachment_failure(
    fixture: connection.ConnectionFixture,
    mosh_fixture: mosh.PrivateMoshFixture,
    message: str,
):
    fixture._prove_server()
    mosh_fixture._prove_server()
    raise MoshMatchFailure(message)


def _udp_failure(
    mosh_fixture: mosh.PrivateMoshFixture,
    message: str,
):
    mosh_fixture._prove_server()
    raise MoshMatchFailure(message)


def _transport_chain(
    client_pid: int,
    tmux_executable: Path,
    server: mosh.MoshServerIdentity,
) -> tuple[private_sshd.ProcessIdentity, ...]:
    expected_server = server.process
    current = client_pid
    seen: set[int] = set()
    relations: dict[int, tuple[int, int]] = {}
    result = []
    before = private_sshd._proc_parent_map()
    for depth in range(MAX_TRANSPORT_DEPTH):
        if current <= 1 or current in seen:
            raise MoshMatchFailure("private mosh transport ancestry was invalid")
        seen.add(current)
        proof = private_sshd._process_identity(current)
        state, parent, ticks = private_sshd._proc_fields(current)
        if ticks != proof.start_ticks or state in {"Z", "X", "x"}:
            raise MoshMatchFailure("private mosh transport identity changed")
        relation = (parent, ticks)
        if before.get(current) != relation:
            raise MoshMatchFailure("private mosh transport snapshot changed")
        relations[current] = relation
        result.append(proof)
        if depth == 0 and proof.executable != tmux_executable:
            raise MoshMatchFailure("listed client was not the private tmux executable")
        if proof == expected_server:
            break
        current = parent
    else:
        raise MoshMatchFailure("private mosh transport ancestry exceeded its bound")
    if result[-1] != expected_server:
        raise MoshMatchFailure("private tmux client did not reach owned mosh-server")

    after = private_sshd._proc_parent_map()
    for proof in result:
        state, parent, ticks = private_sshd._proc_fields(proof.pid)
        relation = (parent, ticks)
        if (
            state in {"Z", "X", "x"}
            or ticks != proof.start_ticks
            or relation != relations[proof.pid]
            or after.get(proof.pid) != relations[proof.pid]
        ):
            raise MoshMatchFailure(
                "private mosh transport ancestry changed during proof"
            )
    for proof in result:
        private_sshd._assert_process(proof)
    if mosh._prove_udp_server(expected_server, server.port) != server.socket_inode:
        raise MoshMatchFailure("owned mosh-server UDP identity changed")
    return tuple(result)


def _wait_for_attachment(
    fixture: connection.ConnectionFixture,
    mosh_fixture: mosh.PrivateMoshFixture,
    snapshot: connection.PrivatePaneSnapshot,
    tmux_executable: Path,
    server: mosh.MoshServerIdentity,
) -> tuple[str, tuple[private_sshd.ProcessIdentity, ...]]:
    deadline = time.monotonic() + ATTACH_TIMEOUT
    retries = 0
    queries = 0
    fixture._prove_server()
    mosh_fixture._prove_server()
    while True:
        queries += 1
        if queries > MAX_ATTACH_QUERIES:
            _attachment_failure(
                fixture,
                mosh_fixture,
                "private tmux attachment query count exceeded its bound",
            )
        try:
            first = _query_clients(fixture, mosh_fixture, deadline)
        except connection._TmuxQueryRetry:
            retries += 1
            if retries >= MAX_QUERY_RETRIES:
                _attachment_failure(
                    fixture,
                    mosh_fixture,
                    "private tmux client query repeatedly exited before proof",
                )
            continue
        parsed = _client_fields(first, snapshot)
        if parsed is None:
            if time.monotonic() >= deadline:
                _attachment_failure(
                    fixture,
                    mosh_fixture,
                    "private mosh tmux client did not attach",
                )
            time.sleep(POLL_SECONDS)
            continue
        name, pid = parsed
        chain = _transport_chain(pid, tmux_executable, server)
        queries += 1
        if queries > MAX_ATTACH_QUERIES:
            _attachment_failure(
                fixture,
                mosh_fixture,
                "private tmux attachment query count exceeded its bound",
            )
        try:
            second = _query_clients(fixture, mosh_fixture, deadline)
        except connection._TmuxQueryRetry:
            continue
        fixture._prove_server()
        mosh_fixture._prove_server()
        if second != first:
            raise MoshMatchFailure("private tmux client row changed during proof")
        if _transport_chain(pid, tmux_executable, server) != chain:
            raise MoshMatchFailure("private mosh transport chain changed")
        return name, chain


def _udp_snapshot(
    identity: private_sshd.ProcessIdentity,
) -> tuple[set[int], tuple[object, ...]]:
    private_sshd._assert_process(identity)
    before_inodes = mosh._pid_socket_inodes(identity)
    raw_before = {
        name: mosh._read_bounded(
            Path(f"/proc/{identity.pid}/net/{name}"),
            mosh.MAX_UDP_TABLE_BYTES,
        ).splitlines()[1:]
        for name in ("udp", "udp6")
    }
    before = LinuxCollector._parse_net_lines(
        {str(value) for value in before_inodes}, raw_before
    )
    raw_after = {
        name: mosh._read_bounded(
            Path(f"/proc/{identity.pid}/net/{name}"),
            mosh.MAX_UDP_TABLE_BYTES,
        ).splitlines()[1:]
        for name in ("udp", "udp6")
    }
    after_inodes = mosh._pid_socket_inodes(identity)
    after = LinuxCollector._parse_net_lines(
        {str(value) for value in after_inodes}, raw_after
    )
    private_sshd._assert_process(identity)
    if before_inodes != after_inodes or before != after:
        raise MoshMatchFailure("private mosh UDP observation changed")
    return before_inodes, tuple(before)


def _wait_for_reversed_udp(
    mosh_fixture: mosh.PrivateMoshFixture,
    client: private_sshd.ProcessIdentity,
    server_identity: mosh.MoshServerIdentity,
):
    deadline = time.monotonic() + UDP_TIMEOUT
    polls = 0
    mosh_fixture._prove_server()
    while True:
        polls += 1
        if polls > MAX_UDP_POLLS:
            _udp_failure(
                mosh_fixture,
                "private mosh UDP poll count exceeded its bound",
            )
        client_inodes, client_endpoints = _udp_snapshot(client)
        server_inodes, server_endpoints = _udp_snapshot(server_identity.process)
        if (
            len(client_inodes) == 1
            and server_identity.socket_inode in server_inodes
            and len(client_endpoints) == 1
            and len(server_endpoints) == 1
        ):
            local = client_endpoints[0]
            target = server_endpoints[0]
            if (
                local.protocol == "udp"
                and target.protocol == "udp"
                and local.address_family == "ipv4"
                and target.address_family == "ipv4"
                and {
                    local.local_address,
                    local.remote_address,
                    target.local_address,
                    target.remote_address,
                } == {mosh.LOOPBACK}
                and endpoint_linked(local, target)
            ):
                mosh_fixture._prove_server()
                return local, target
        if time.monotonic() >= deadline:
            _udp_failure(
                mosh_fixture,
                "private mosh UDP tuple did not become reversed",
            )
        time.sleep(POLL_SECONDS)


def _gone(identity: private_sshd.ProcessIdentity) -> None:
    if not private_sshd._process_is_gone(identity):
        raise MoshMatchFailure(f"owned private process remains live: {identity.pid}")


class _ProofRecorder:
    def __init__(self) -> None:
        self.calls = 0

    def _prove_server(self) -> None:
        self.calls += 1


class _QueryFixture(_ProofRecorder):
    def __init__(self, status: int) -> None:
        super().__init__()
        self.status = status
        self.queries = 0

    def _tmux_command(self, *parts: str) -> tuple[str, ...]:
        return parts

    def _bounded_tmux_query(
        self,
        command: tuple[str, ...],
        *,
        timeout: float,
    ) -> tuple[int, bytes]:
        self.queries += 1
        return self.status, b""


class MoshMatcherSafetyTests(unittest.TestCase):
    def test_attachment_failure_reproves_both_servers(self) -> None:
        fixture = _ProofRecorder()
        mosh_fixture = _ProofRecorder()

        with self.assertRaisesRegex(MoshMatchFailure, "bounded failure"):
            _attachment_failure(
                fixture,
                mosh_fixture,
                "bounded failure",
            )

        self.assertEqual(fixture.calls, 1)
        self.assertEqual(mosh_fixture.calls, 1)

    def test_udp_failure_reproves_server(self) -> None:
        mosh_fixture = _ProofRecorder()

        with self.assertRaisesRegex(MoshMatchFailure, "bounded failure"):
            _udp_failure(mosh_fixture, "bounded failure")

        self.assertEqual(mosh_fixture.calls, 1)


    def test_query_deadline_reproves_both_servers(self) -> None:
        fixture = _QueryFixture(0)
        mosh_fixture = _ProofRecorder()

        with self.assertRaisesRegex(MoshMatchFailure, "proof timed out"):
            _query_clients(fixture, mosh_fixture, -1.0)

        self.assertEqual(fixture.calls, 1)
        self.assertEqual(mosh_fixture.calls, 1)
        self.assertEqual(fixture.queries, 0)


    def test_query_status_reproves_both_servers(self) -> None:
        fixture = _QueryFixture(1)
        mosh_fixture = _ProofRecorder()

        with self.assertRaisesRegex(MoshMatchFailure, "client query failed"):
            _query_clients(fixture, mosh_fixture, time.monotonic() + 1.0)

        self.assertEqual(fixture.calls, 1)
        self.assertEqual(mosh_fixture.calls, 1)
        self.assertEqual(fixture.queries, 1)


    def test_attachment_query_cap_reproves_both_servers(self) -> None:
        fixture = _ProofRecorder()
        mosh_fixture = _ProofRecorder()

        with mock.patch.dict(globals(), {"MAX_ATTACH_QUERIES": 0}):
            with self.assertRaisesRegex(MoshMatchFailure, "query count"):
                _wait_for_attachment(fixture, mosh_fixture, None, None, None)

        self.assertEqual(fixture.calls, 2)
        self.assertEqual(mosh_fixture.calls, 2)


    def test_attachment_retry_cap_reproves_both_servers(self) -> None:
        fixture = _ProofRecorder()
        mosh_fixture = _ProofRecorder()
        query = mock.Mock(side_effect=connection._TmuxQueryRetry("retry"))

        with mock.patch.dict(
            globals(), {"_query_clients": query, "MAX_QUERY_RETRIES": 1}
        ):
            with self.assertRaisesRegex(MoshMatchFailure, "repeatedly exited"):
                _wait_for_attachment(fixture, mosh_fixture, None, None, None)

        query.assert_called_once()
        self.assertEqual(fixture.calls, 2)
        self.assertEqual(mosh_fixture.calls, 2)


    def test_empty_row_deadline_reproves_both_servers(self) -> None:
        fixture = _ProofRecorder()
        mosh_fixture = _ProofRecorder()
        query = mock.Mock(return_value=b"")

        with mock.patch.object(
            time,
            "monotonic",
            side_effect=(0.0, ATTACH_TIMEOUT),
        ):
            with mock.patch.dict(globals(), {"_query_clients": query}):
                with self.assertRaisesRegex(MoshMatchFailure, "did not attach"):
                    _wait_for_attachment(fixture, mosh_fixture, None, None, None)

        query.assert_called_once()
        self.assertEqual(fixture.calls, 2)
        self.assertEqual(mosh_fixture.calls, 2)


    def test_udp_poll_cap_reproves_server(self) -> None:
        mosh_fixture = _ProofRecorder()

        with mock.patch.dict(globals(), {"MAX_UDP_POLLS": 0}):
            with self.assertRaisesRegex(MoshMatchFailure, "poll count"):
                _wait_for_reversed_udp(mosh_fixture, None, None)

        self.assertEqual(mosh_fixture.calls, 2)


@unittest.skipUnless(
    _live_authorized(),
    "private mosh matcher requires both explicit Testbed mosh opt-ins",
)
class PrivateMoshMatcherSmokeTests(unittest.TestCase):
    def test_real_mosh_udp_and_tmux_visibility_match(self) -> None:
        prepared: dict[str, object] = {}
        server_executable = startup._system_tool("mosh-server")
        client_executable = startup._system_tool("mosh-client")
        tmux_executable = startup._system_tool("tmux")
        port = startup._random_port()
        session = f"yoohoo-mosh-match-{os.urandom(6).hex()}"

        def command_factory(
            snapshot: connection.PrivatePaneSnapshot,
        ) -> tuple[connection.SetupCommand, ...]:
            bound = prepared.get("fixture")
            if not isinstance(bound, connection.ConnectionFixture):
                raise MoshMatchFailure(
                    "connection fixture was not bound before setup"
                )
            proof = startup._ConnectionSocketProof(bound)
            proof.bind(snapshot)
            command = mosh.bootstrap_command(
                server_executable=server_executable,
                tmux_executable=tmux_executable,
                socket_path=snapshot.socket_path,
                session=snapshot.session,
                port=port,
                prove_socket=proof,
            )
            _request_value, remote = producer_support._request_and_remote(snapshot)
            prepared["snapshot"] = snapshot
            prepared["proof"] = proof
            prepared["command"] = command
            return (
                connection.SetupCommand(command, original_command=command),
                connection.SetupCommand(remote, original_command=remote),
            )

        fixture = connection.ConnectionFixture(
            session=session,
            command_factory=command_factory,
        )
        prepared["fixture"] = fixture
        connection_active = False
        mosh_fixture = None
        mosh_closed = False
        connection_root = None
        private_root = None
        server = None
        client = None
        transport_chain = ()

        try:
            active = fixture.__enter__()
            connection_active = True
            connection_root = active.root
            snapshot = prepared.get("snapshot")
            proof = prepared.get("proof")
            command = prepared.get("command")
            if (
                not isinstance(snapshot, connection.PrivatePaneSnapshot)
                or not isinstance(proof, startup._ConnectionSocketProof)
                or not isinstance(command, str)
                or snapshot is not active._pane_snapshot_proof
            ):
                raise MoshMatchFailure("private setup proof was not retained")
            private_ssh = active._private_sshd
            if not isinstance(private_ssh, private_sshd.PrivateSshdFixture):
                raise MoshMatchFailure("private sshd fixture was not available")
            private_root = private_ssh.root

            mosh_fixture = mosh.PrivateMoshFixture(
                private_ssh,
                server_executable=server_executable,
                client_executable=client_executable,
                tmux_executable=tmux_executable,
                socket_path=snapshot.socket_path,
                session=snapshot.session,
                port=port,
                prove_socket=proof,
            )
            if mosh_fixture.command != command:
                raise MoshMatchFailure("registered mosh bootstrap command changed")

            try:
                mosh_fixture.open_terminal()
                server = mosh_fixture.start_server()
                process, client = mosh_fixture.start_client()
                _name, transport_chain = _wait_for_attachment(
                    active,
                    mosh_fixture,
                    snapshot,
                    tmux_executable,
                    server,
                )
                local_udp, target_udp = _wait_for_reversed_udp(
                    mosh_fixture, client, server
                )
                request = _request(snapshot, client)
                collector = LinuxCollector(
                    RestrictedProcessRootProbeIO(active, client.pid),
                    ssh="/usr/bin/ssh",
                    python="python3",
                )
                response = Resolver().resolve(request, collector)
                diagnostic = {
                    "status": response.get("status"),
                    "reasonCodes": [
                        item.get("code") for item in response.get("reasons", [])
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
                self.assertEqual(
                    candidate["window"]["stableId"], "synthetic-private-mosh"
                )
                self.assertEqual(candidate["window"]["pid"], client.pid)
                self.assertEqual(candidate["proof"]["state"], "complete")
                self.assertEqual(candidate["proof"]["relation"], "visible_exact")
                link = candidate["proof"]["evidence"][-1]
                self.assertEqual(link["code"], "tmux_client_visible_exact")
                self.assertEqual(link["details"]["pid"], transport_chain[0].pid)
                self.assertEqual(
                    link["details"]["startTimeTicks"],
                    str(transport_chain[0].start_ticks),
                )
                self.assertEqual(set(link["details"]), {
                    "pid", "startTimeTicks", "localEndpoint", "targetEndpoint",
                })
                observed_local = link["details"]["localEndpoint"]
                observed_target = link["details"]["targetEndpoint"]
                self.assertEqual(observed_local["protocol"], "udp")
                self.assertEqual(observed_target["protocol"], "udp")
                self.assertEqual(
                    observed_local["local"],
                    {
                        "address": local_udp.local_address,
                        "port": local_udp.local_port,
                    },
                )
                self.assertEqual(
                    observed_local["remote"],
                    {
                        "address": local_udp.remote_address,
                        "port": local_udp.remote_port,
                    },
                )
                self.assertEqual(
                    observed_target["local"],
                    {
                        "address": target_udp.local_address,
                        "port": target_udp.local_port,
                    },
                )
                self.assertEqual(
                    observed_target["remote"],
                    {
                        "address": target_udp.remote_address,
                        "port": target_udp.remote_port,
                    },
                )
            finally:
                mosh_fixture.close()
                mosh_closed = True

            if client is None or server is None or not transport_chain:
                raise MoshMatchFailure("private mosh identities were not retained")
            _gone(client)
            _gone(server.process)
            for identity in transport_chain:
                _gone(identity)

            connection_active = False
            active.__exit__(None, None, None)
            if connection_root.exists() or private_root.exists():
                raise MoshMatchFailure("private fixture root remains after cleanup")
        except BaseException:
            if connection_active and (mosh_fixture is None or mosh_closed):
                exc_type, exc_value, traceback = sys.exc_info()
                connection_active = False
                fixture.__exit__(exc_type, exc_value, traceback)
            raise
        finally:
            preserved = getattr(fixture, "_root", None)
            if preserved is not None:
                server_pid = (
                    server.process.pid if server is not None else "unproven"
                )
                client_pid = client.pid if client is not None else "unproven"
                detail = (
                    "private mosh matcher preserved ambiguous state; "
                    f"connection_root={preserved}; server_pid={server_pid}; "
                    f"client_pid={client_pid}\n"
                )
                sys.stderr.write(detail[:MAX_REPORT_CHARS])


if __name__ == "__main__":
    unittest.main()
