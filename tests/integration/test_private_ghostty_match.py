"""Opt-in real Ghostty/Hyprland ancestry gate for the private SSH resolver.

Importing this module is inert.  The test creates one independently-owned
Ghostty process and one private loopback SSH/tmux fixture.  It never focuses,
switches, or attaches an existing tmux client.
"""
from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
import unittest

from agent_window_resolver import Resolver, Window
from agent_window_resolver.linux import LinuxCollector
from agent_window_resolver.model import Limits, Request


OPT_IN_ENV = "AGENT_WINDOW_PRIVATE_GHOSTTY_MATCH_LIVE"
MAX_HYPR_BYTES = 256 * 1024
MAX_HYPR_WINDOWS = 128
MAX_FIELD_BYTES = 256
WINDOW_TIMEOUT = 4.0
HELPER_TIMEOUT = 2.0
MAX_TMUX_QUERIES = 128
MAX_TMUX_QUERY_RETRIES = 4

_HYPR_ADDRESS = re.compile(r"^0x[0-9a-f]{1,32}$")
_HYPR_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def _graphics_preflight() -> None:
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    wayland = os.environ.get("WAYLAND_DISPLAY", "")
    instance = os.environ.get("HYPRLAND_INSTANCE_SIGNATURE", "")
    if not runtime.startswith("/") or not wayland or not _HYPR_NAME.fullmatch(wayland) or not instance or not _HYPR_NAME.fullmatch(instance):
        raise GhosttyGateFailure("Hyprland graphical runtime is incomplete")
    wayland_socket = Path(runtime) / wayland
    hypr_dir = Path(runtime) / "hypr" / instance
    try:
        wayland_info = wayland_socket.lstat()
        hypr_info = (hypr_dir / ".socket.sock").lstat()
    except OSError as error:
        raise GhosttyGateFailure("Hyprland runtime sockets are unavailable") from error
    if (wayland_info.st_uid != os.geteuid() or hypr_info.st_uid != os.geteuid()
            or not stat.S_ISSOCK(wayland_info.st_mode)
            or not stat.S_ISSOCK(hypr_info.st_mode)):
        raise GhosttyGateFailure("Hyprland runtime sockets are unavailable")


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
    "_private_ghostty_ssh_support", HERE / "test_private_ssh_match.py"
)
support = ssh_match.support
connection = ssh_match.connection
private_sshd = connection.private_sshd
RestrictedGhosttyProbeIO = ssh_match.RestrictedAttachmentProbeIO


class GhosttyGateFailure(RuntimeError):
    """The owned terminal or compositor observation became ambiguous."""


class GhosttySpawnUnproven(GhosttyGateFailure):
    def __init__(self, owned_process: subprocess.Popen[bytes], message: str):
        super().__init__(message)
        self.owned_process = owned_process


class HyprctlSpawnUnproven(GhosttyGateFailure):
    def __init__(self, process: subprocess.Popen[bytes], message: str):
        super().__init__(message)
        self.process = process


@dataclass(frozen=True)
class _OwnedProcess:
    process: subprocess.Popen[bytes]
    identity: object
    argv: tuple[str, ...]


def _tool(path: str) -> Path:
    return private_sshd._trusted_executable(Path(path))


def _live_authorized() -> bool:
    return (
        os.environ.get(OPT_IN_ENV, "").strip() == "1"
        and connection.live_test_authorized()
    )


def _start_owned(argv: list[str], executable: Path) -> _OwnedProcess:
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=False,
    )
    try:
        identity = private_sshd._process_identity(process.pid, executable)
        if private_sshd._process_argv(process.pid) != argv:
            raise GhosttyGateFailure("owned process argv changed")
    except BaseException as error:
        status = process.poll()
        if status is not None:
            process.wait(timeout=HELPER_TIMEOUT)
            raise GhosttyGateFailure("owned process exited before proof") from error
        raise GhosttySpawnUnproven(
            process,
            f"unproven owned process remains live: {process.pid}"
        ) from error
    return _OwnedProcess(process, identity, tuple(argv))


def _assert_owned(owned: _OwnedProcess) -> None:
    if owned.process.pid != owned.identity.pid:
        raise GhosttyGateFailure("owned process handle changed")
    private_sshd._assert_process(owned.identity)
    if private_sshd._process_argv(owned.identity.pid) != list(owned.argv):
        raise GhosttyGateFailure("owned process argv changed")


def _stop_owned(owned: _OwnedProcess) -> None:
    if not private_sshd._process_is_gone(owned.identity):
        descendants = private_sshd._descendants(owned.identity)
        private_sshd._terminate_identities(
            descendants + [owned.identity], HELPER_TIMEOUT
        )
    owned.process.wait(timeout=HELPER_TIMEOUT)


def _read_pipe_bounded(
    process: subprocess.Popen[bytes],
    proof,
    *,
    limit: int,
    deadline: float,
) -> tuple[int, bytes]:
    if process.stdout is None:
        raise GhosttyGateFailure("bounded helper stdout was unavailable")
    output = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GhosttyGateFailure("bounded helper timed out")
            readable, _, _ = select.select([process.stdout], [], [], remaining)
            if not readable:
                raise GhosttyGateFailure("bounded helper timed out")
            chunk = os.read(process.stdout.fileno(), limit + 1 - len(output))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > limit:
                raise GhosttyGateFailure("bounded helper output exceeded its limit")
        status = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except BaseException:
        if not private_sshd._process_is_gone(proof):
            descendants = private_sshd._descendants(proof)
            private_sshd._terminate_identities(descendants + [proof], HELPER_TIMEOUT)
        process.wait(timeout=HELPER_TIMEOUT)
        raise
    finally:
        if process.poll() is not None:
            process.stdout.close()
    return status, bytes(output)


def _bounded_hypr_clients(hyprctl: Path) -> list[dict[str, object]]:
    argv = [str(hyprctl), "-j", "clients"]
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=False,
    )
    try:
        # hyprctl may be an exec wrapper on this host; prove the live PID and
        # exact argv below without conflating its final /proc/exe with the
        # command path used to launch it.
        proof = private_sshd._process_identity(process.pid)
        observed_argv = private_sshd._process_argv(process.pid)
        if (
            len(observed_argv) != len(argv)
            or Path(observed_argv[0]).name != Path(argv[0]).name
            or observed_argv[1:] != argv[1:]
        ):
            raise GhosttyGateFailure("hyprctl argv changed")
    except BaseException as error:
        status = process.poll()
        if status is not None:
            process.wait(timeout=HELPER_TIMEOUT)
            if process.stdout is not None:
                process.stdout.close()
            raise GhosttyGateFailure("hyprctl exited before identity proof") from error
        try:
            process.wait(timeout=HELPER_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise HyprctlSpawnUnproven(
                process, f"unproven hyprctl remains live: {process.pid}"
            ) from error
        if process.stdout is not None:
            process.stdout.close()
        raise GhosttyGateFailure("hyprctl identity proof failed") from error
    status, raw = _read_pipe_bounded(
        process, proof, limit=MAX_HYPR_BYTES,
        deadline=time.monotonic() + HELPER_TIMEOUT,
    )
    if status != 0:
        raise GhosttyGateFailure("hyprctl clients query failed")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise GhosttyGateFailure("hyprctl clients response was invalid") from error
    if not isinstance(value, list) or len(value) > MAX_HYPR_WINDOWS:
        raise GhosttyGateFailure("hyprctl clients response exceeded its shape bound")
    if not all(isinstance(item, dict) for item in value):
        raise GhosttyGateFailure("hyprctl client entry was invalid")
    return value


def _plain(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > MAX_FIELD_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise GhosttyGateFailure(f"Hyprland {name} was invalid")
    return value


def _window_for_pid(hyprctl: Path, identity) -> Window | None:
    private_sshd._assert_process(identity)
    matches = []
    for item in _bounded_hypr_clients(hyprctl):
        pid = item.get("pid")
        if isinstance(pid, int) and not isinstance(pid, bool) and pid == identity.pid:
            matches.append(item)
    private_sshd._assert_process(identity)
    state, _parent, ticks = private_sshd._proc_fields(identity.pid)
    if ticks != identity.start_ticks or state in {"Z", "X", "x"}:
        raise GhosttyGateFailure("Ghostty identity changed during Hyprland query")
    if not matches:
        return None
    if len(matches) != 1:
        raise GhosttyGateFailure("Ghostty has an ambiguous Hyprland window set")
    item = matches[0]
    address = _plain(item.get("address"), "address")
    if _HYPR_ADDRESS.fullmatch(address.lower()) is None:
        raise GhosttyGateFailure("Hyprland address was invalid")
    # Hyprland's clients JSON does not provide stableId; the validated
    # address is the compositor identity used by the resolver schema.
    stable_id = "hypr:" + address.lower()
    class_name = item.get("class")
    if class_name is not None:
        class_name = _plain(class_name, "class")
    return Window(
        stable_id,
        address,
        identity.pid,
        str(identity.start_ticks),
        class_name,
    )


def _wait_for_window(hyprctl: Path, identity) -> Window:
    deadline = time.monotonic() + WINDOW_TIMEOUT
    while True:
        window = _window_for_pid(hyprctl, identity)
        if window is not None:
            return window
        if time.monotonic() >= deadline:
            raise GhosttyGateFailure("owned Ghostty window did not appear")
        time.sleep(0.04)


def _wait_for_visible_client(fixture, snapshot, ghostty: _OwnedProcess) -> None:
    command = fixture._tmux_command(
        "list-clients", "-F",
        "#{client_name}\t#{client_pid}\t#{client_session}\t#{window_index}\t#{pane_id}",
    )
    deadline = time.monotonic() + WINDOW_TIMEOUT
    retries = 0
    queries = 0
    max_queries = min(MAX_TMUX_QUERIES, math.ceil(WINDOW_TIMEOUT / 0.04) + 2)
    while True:
        if queries >= max_queries or time.monotonic() >= deadline:
            _assert_owned(ghostty)
            fixture._prove_server()
            raise GhosttyGateFailure("private tmux client query deadline exceeded")
        queries += 1
        _assert_owned(ghostty)
        fixture._prove_server()
        try:
            status, raw = fixture._bounded_tmux_query(
                command, timeout=min(0.5, max(0.01, deadline - time.monotonic()))
            )
        except connection._TmuxQueryRetry:
            retries += 1
            if retries >= MAX_TMUX_QUERY_RETRIES:
                _assert_owned(ghostty)
                fixture._prove_server()
                raise GhosttyGateFailure("tmux query repeatedly exited before proof")
            continue
        _assert_owned(ghostty)
        fixture._prove_server()
        if status != 0:
            raise GhosttyGateFailure("private tmux client query failed")
        if raw and (
            len(raw) > 4096 or not raw.endswith(b"\n")
            or b"\r" in raw or b"\0" in raw
        ):
            raise GhosttyGateFailure("private tmux client row was invalid")
        rows = raw.splitlines()
        if len(rows) > 1:
            raise GhosttyGateFailure("private tmux client proof was ambiguous")
        if len(rows) == 1:
            try:
                fields = rows[0].decode("utf-8", "strict").split("\t")
                if len(fields) != 5:
                    raise ValueError("wrong client field count")
                _plain(fields[0], "tmux client name")
                pid = int(fields[1])
            except (UnicodeError, ValueError, IndexError) as error:
                raise GhosttyGateFailure("private tmux client row was invalid") from error
            if (
                len(fields) == 5 and pid > 1
                and fields[2:] == [
                    snapshot.session, snapshot.window_index, snapshot.pane_id,
                ]
            ):
                proof = connection._process_proof(pid, Path(fixture._tmux))
                _assert_owned(ghostty)
                fixture._prove_server()
                connection._assert_process(proof)
                return
        if time.monotonic() >= deadline:
            raise GhosttyGateFailure("private tmux client did not become visible")
        time.sleep(0.04)


def _request(snapshot, window: Window) -> Request:
    target_request, _remote = support._request_and_remote(snapshot)
    return Request(
        "private-ghostty-visible-match", "resolve", "visible_exact",
        target_request.target, support._LOCAL_MACHINE, (window,), None,
        Limits(deadline_ms=20_000),
    )


@unittest.skipUnless(
    _live_authorized(),
    "private Ghostty matcher requires explicit Plumbus desktop opt-in",
)
class PrivateGhosttyMatcherTests(unittest.TestCase):
    def test_real_hypr_window_ancestry_matches_private_ssh_target(self) -> None:
        ghostty_executable = _tool("/usr/bin/ghostty")
        hyprctl = _tool("/usr/bin/hyprctl")
        prepared: dict[str, object] = {}

        def command_factory(snapshot):
            _target, remote = support._request_and_remote(snapshot)
            attachment = "exec tmux attach-session -t =" + snapshot.session
            prepared.update(
                snapshot=snapshot, remote=remote, attachment=attachment,
            )
            return (
                connection.SetupCommand(remote, original_command=remote),
                connection.SetupCommand(attachment, original_command=attachment),
            )

        fixture = connection.ConnectionFixture(command_factory=command_factory)
        _graphics_preflight()
        active = fixture.__enter__()
        connection_active = True
        ghostty = None
        ghostty_stopped = False
        ghostty_stop_attempted = False
        connection_exit_attempted = False
        hyprctl_unproven = None
        try:
            snapshot = prepared.get("snapshot")
            attachment = prepared.get("attachment")
            if (
                not isinstance(snapshot, connection.PrivatePaneSnapshot)
                or snapshot is not active._pane_snapshot_proof
                or not isinstance(attachment, str)
            ):
                raise GhosttyGateFailure("private setup proof was not retained")
            ssh_argv = active.ssh_argv(attachment, interactive=True)
            argv = [
                str(ghostty_executable),
                "--config-default-files=false",
                "--gtk-single-instance=false",
                "--confirm-close-surface=false",
                "--window-decoration=none",
                "-e",
                *ssh_argv,
            ]
            try:
                ghostty = _start_owned(argv, ghostty_executable)
            except GhosttySpawnUnproven as error:
                ghostty = _OwnedProcess(error.owned_process, object(), tuple(argv))
                ghostty_stop_attempted = True
                raise
            try:
                window = _wait_for_window(hyprctl, ghostty.identity)
            except HyprctlSpawnUnproven as error:
                hyprctl_unproven = error.process
                raise
            _wait_for_visible_client(active, snapshot, ghostty)

            request = _request(snapshot, window)
            collector = LinuxCollector(
                RestrictedGhosttyProbeIO(active, ghostty.identity.pid),
                ssh="/usr/bin/ssh", python="python3",
            )
            response = Resolver().resolve(request, collector)
            diagnostic = {
                "status": response.get("status"),
                "reasonCodes": [
                    item.get("code") for item in response.get("reasons", [])
                    if isinstance(item, dict)
                ],
                "candidateCount": len(response.get("candidates", [])),
            }
            self.assertEqual(response["status"], "matched", diagnostic)
            self.assertEqual(len(response["candidates"]), 1)
            candidate = response["candidates"][0]
            self.assertEqual(candidate["window"]["stableId"], window.stable_id)
            self.assertEqual(candidate["window"]["address"], window.address)
            self.assertEqual(candidate["window"]["pid"], ghostty.identity.pid)
            self.assertEqual(candidate["proof"]["state"], "complete")
            self.assertEqual(candidate["proof"]["relation"], "visible_exact")

            fresh = _window_for_pid(hyprctl, ghostty.identity)
            if fresh is None:
                raise GhosttyGateFailure("owned Ghostty window disappeared")
            self.assertEqual(fresh, window)

            ghostty_stop_attempted = True
            _stop_owned(ghostty)
            ghostty_stopped = True
            connection_exit_attempted = True
            active.__exit__(None, None, None)
            connection_active = False
        except BaseException:
            if ghostty is not None and not ghostty_stopped and not ghostty_stop_attempted:
                ghostty_stop_attempted = True
                _stop_owned(ghostty)
                ghostty_stopped = True
            if connection_active and (ghostty is None or ghostty_stopped) and not connection_exit_attempted:
                exc_type, exc_value, traceback = sys.exc_info()
                connection_exit_attempted = True
                fixture.__exit__(exc_type, exc_value, traceback)
                connection_active = False
            raise
        finally:
            if connection_active or hyprctl_unproven is not None:
                root = getattr(fixture, "_root", None)
                pid = ghostty.process.pid if ghostty is not None else "unproven"
                if hyprctl_unproven is not None:
                    pid = f"{pid};hyprctl={hyprctl_unproven.pid}"
                sys.stderr.write(
                    f"private Ghostty state preserved; root={root}; pid={pid}\n"[:512]
                )


if __name__ == "__main__":
    unittest.main()
