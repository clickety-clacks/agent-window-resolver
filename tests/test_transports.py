"""Transport reachability observation over loopback.

The real remote probe runs under a stand-in ``ssh`` that executes the remote
command locally with a controlled PATH and an ``SSH_CONNECTION`` naming
127.0.0.1, so the UDP echo and TCP connect cross the loopback interface.
No network host, real SSH server, et or mosh installation is used.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from agent_window_resolver import (
    Limits,
    ProcessIdentity,
    ProcessNode,
    Request,
    Resolver,
    StaticCollector,
    Target,
    TargetObservation,
    TopologySnapshot,
    parse_request,
)
from agent_window_resolver.model import VERSION, RequestError
from agent_window_resolver.transports import TransportProber, normalize


FAKE_SSH = """#!/bin/sh
# Drop ssh options up to "--", the host, then run the remote command locally.
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift; shift
[ -n "$FAKE_SSH_FAIL" ] && exit 255
[ -n "$FAKE_NO_PYTHON" ] && FAKE_REMOTE_PATH=/nonexistent
exec /usr/bin/env -i PATH="$FAKE_REMOTE_PATH" \
  SSH_CONNECTION="127.0.0.1 40000 127.0.0.1 22" /bin/sh -c "$1"
"""


class LoopbackHost:
    def __init__(self, *, mosh_server: bool, etterminal: bool) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="awr-transport-")
        root = Path(self.temp.name)
        self.remote_bin = root / "remote-bin"
        self.remote_bin.mkdir()
        (self.remote_bin / "python3").symlink_to(sys.executable)
        for name, wanted in (("mosh-server", mosh_server), ("etterminal", etterminal)):
            if wanted:
                stub = self.remote_bin / name
                stub.write_text("#!/bin/sh\nexit 0\n")
                stub.chmod(0o755)
        self.ssh = root / "ssh"
        self.ssh.write_text(FAKE_SSH)
        self.ssh.chmod(0o755)
        self.root = root
        self.processes: list[subprocess.Popen] = []

    def environment(self, **extra: str) -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "FAKE_REMOTE_PATH": str(self.remote_bin), **extra}

    def etserver(self, port: int) -> None:
        """A stand-in etserver, under a name no real etserver uses."""
        script = self.root / "awr-etserver"
        script.write_text("#!/bin/sh\nwhile :; do sleep 1; done\n")
        script.chmod(0o755)
        process = subprocess.Popen(
            [str(script), "--port", str(port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.processes.append(process)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if Path(f"/proc/{process.pid}/comm").read_text().strip() == "awr-etserver":
                    return
            except OSError:
                pass
            time.sleep(0.02)
        raise AssertionError("stand-in etserver did not start")

    def close(self) -> None:
        for process in self.processes:
            process.kill()
            process.wait()
        self.temp.cleanup()


def listener() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    return sock


class TransportProbeTests(unittest.TestCase):
    def host(self, **kwargs) -> LoopbackHost:
        host = LoopbackHost(**kwargs)
        self.addCleanup(host.close)
        return host

    def prober(self, host: LoopbackHost, **kwargs) -> TransportProber:
        return TransportProber(
            ssh=str(host.ssh), environment=host.environment(**kwargs),
            etserver_name="awr-etserver",
        )

    def test_reachable_et_and_passing_udp_are_available(self) -> None:
        host = self.host(mosh_server=True, etterminal=True)
        server = listener()
        self.addCleanup(server.close)
        host.etserver(server.getsockname()[1])
        result = self.prober(host).probe("loopback", 8.0)
        self.assertEqual(result["state"], "complete", result)
        self.assertEqual(result["ssh"]["state"], "available")
        self.assertEqual(result["et"], {
            "state": "available", "code": "et_reachable",
            "port": server.getsockname()[1],
        })
        self.assertEqual(result["mosh"], {
            "state": "available", "code": "mosh_udp_passing",
        })

    def test_missing_servers_are_unavailable_not_unknown(self) -> None:
        host = self.host(mosh_server=False, etterminal=True)
        result = self.prober(host).probe("loopback", 8.0)
        self.assertEqual(result["state"], "complete", result)
        self.assertIn(result["et"]["code"], {"etserver_not_running", "et_port_unreachable"})
        self.assertEqual(result["mosh"], {
            "state": "unavailable", "code": "mosh_server_missing",
        })

    def test_closed_et_port_and_blocked_udp_are_unavailable(self) -> None:
        host = self.host(mosh_server=True, etterminal=True)
        server = listener()
        port = server.getsockname()[1]
        server.close()
        host.etserver(port)
        prober = self.prober(host)
        prober.udp_echo = lambda *_args: False
        result = prober.probe("loopback", 8.0)
        self.assertEqual(result["et"]["state"], "unavailable")
        self.assertEqual(result["mosh"], {
            "state": "unavailable", "code": "mosh_udp_blocked",
        })

    def test_missing_etterminal_makes_et_unavailable(self) -> None:
        host = self.host(mosh_server=False, etterminal=False)
        server = listener()
        self.addCleanup(server.close)
        host.etserver(server.getsockname()[1])
        result = self.prober(host).probe("loopback", 8.0)
        self.assertEqual(result["et"], {
            "state": "unavailable", "code": "etterminal_missing",
        })

    def test_unreachable_host_reports_unknown_not_unavailable(self) -> None:
        host = self.host(mosh_server=True, etterminal=True)
        result = self.prober(host, FAKE_SSH_FAIL="1").probe("loopback", 8.0)
        self.assertEqual(result["state"], "unreachable")
        for name in ("ssh", "et", "mosh"):
            self.assertEqual(result[name]["state"], "unknown")

    def test_host_without_python_is_partial_not_unreachable(self) -> None:
        host = self.host(mosh_server=True, etterminal=True)
        result = self.prober(host, FAKE_NO_PYTHON="1").probe("loopback", 8.0)
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["mosh"], {"state": "unknown", "code": "probe_failed"})

    def test_dropped_et_connect_cannot_starve_the_mosh_check(self) -> None:
        host = self.host(mosh_server=True, etterminal=True)
        server = listener()
        self.addCleanup(server.close)
        host.etserver(server.getsockname()[1])
        prober = self.prober(host)

        def dropped(_server, _port, wait):
            time.sleep(wait)
            return False
        prober.tcp_open = dropped
        result = prober.probe("loopback", 4.0)
        self.assertEqual(result["mosh"]["state"], "available", result)
        self.assertEqual(result["et"]["code"], "et_port_unreachable")

    def test_too_little_time_is_partial_without_running_ssh(self) -> None:
        prober = TransportProber(popen=lambda *a, **k: self.fail("probe ran"))
        self.assertEqual(prober.probe("atlas", 0.5)["state"], "partial")

    def test_normalize_rejects_malformed_collector_output(self) -> None:
        for value in (None, {"state": "complete"}, {
            "state": "complete",
            "ssh": {"state": "available", "code": "x"},
            "et": {"state": "maybe", "code": "x"},
            "mosh": {"state": "unknown", "code": "x"},
        }):
            with self.subTest(value=value):
                self.assertEqual(normalize(value)["state"], "partial")


def _verify_request(**extra) -> dict:
    return {
        "schema": "agent-window-resolver.request.v1",
        "requestId": "r", "operation": "verify-target",
        "target": {"identity": {
            "machine": "lumen", "instanceId": "agent",
            "pid": 200, "startTimeTicks": "42",
        }},
        "local": {"machine": "lumen"}, "windows": [], **extra,
    }


class TransportProtocolTests(unittest.TestCase):
    def snapshot(self) -> TopologySnapshot:
        identity = ProcessIdentity("lumen", 200, "42")
        return TopologySnapshot((), TargetObservation(
            "lumen", None, None, (ProcessNode(identity, None),), None, (),
        ))

    def test_probe_transports_is_verify_target_only_and_boolean(self) -> None:
        self.assertTrue(parse_request(_verify_request(probeTransports=True)).probe_transports)
        self.assertFalse(parse_request(_verify_request()).probe_transports)
        with self.assertRaises(RequestError) as caught:
            parse_request(_verify_request(probeTransports="yes"))
        self.assertEqual(caught.exception.code, "invalid_probe_transports")
        value = _verify_request(probeTransports=False)
        value.update(operation="match")
        with self.assertRaises(RequestError) as caught:
            parse_request(value)
        self.assertEqual(caught.exception.code, "invalid_probe_transports")

    def test_verified_response_carries_observation_only_when_asked(self) -> None:
        observed = {
            "state": "complete",
            "ssh": {"state": "available", "code": "ssh_probe_succeeded"},
            "et": {"state": "available", "code": "et_reachable", "port": 2022},
            "mosh": {"state": "unavailable", "code": "mosh_udp_blocked"},
        }
        collector = StaticCollector(self.snapshot(), transports=observed)
        plain = Resolver().resolve(_verify_request(), collector)
        self.assertEqual(plain["status"], "verified")
        self.assertNotIn("transports", plain)
        asked = Resolver().resolve(_verify_request(probeTransports=True), collector)
        self.assertEqual(asked["status"], "verified")
        self.assertEqual(asked["transports"], observed)

    def test_collector_without_observation_reports_partial(self) -> None:
        class Plain:
            def collect(inner, request, deadline):
                return self.snapshot()
        response = Resolver().resolve(_verify_request(probeTransports=True), Plain())
        self.assertEqual(response["transports"]["state"], "partial")

    def test_every_response_carries_the_library_version(self) -> None:
        invalid = Resolver().resolve({"operation": "nope"}, StaticCollector(self.snapshot()))
        self.assertEqual(invalid["resolverVersion"], VERSION)
        verified = Resolver().resolve(_verify_request(), StaticCollector(self.snapshot()))
        self.assertEqual(verified["resolverVersion"], VERSION)

    def test_cli_error_envelope_carries_the_library_version(self) -> None:
        from io import BytesIO
        from agent_window_resolver.cli import run
        output = BytesIO()
        run([], stdin=BytesIO(b"not json"), stdout=output, stderr=BytesIO())
        self.assertEqual(json.loads(output.getvalue())["resolverVersion"], VERSION)


if __name__ == "__main__":
    unittest.main()
