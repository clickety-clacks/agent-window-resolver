"""Additive window-session request type; v1 target requests use their own parser."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath
import shlex
from typing import Any, Mapping

from .collector import (
    Deadline, SocketSelector, WindowObservation,
    _ET_FLAGS, _ET_VALUE_OPTIONS, _et_host,
    transport_command_hint,
)
from .linux import CollectionFailure
from .model import (
    VERSION, Limits, RequestError, Window, _exact_keys, _machine, _mapping,
    _parse_limits, _plain, canonical_machine, parse_socket, parse_window,
)

REQUEST_SCHEMA = "agent-window-resolver.window-session.request.v1"
RESPONSE_SCHEMA = "agent-window-resolver.window-session.response.v1"
OPERATION = "window-session"


@dataclass(frozen=True)
class WindowSessionRequest:
    request_id: str
    window: Window
    windows: tuple[Window, ...]
    local_machine: str
    limits: Limits

    @property
    def operation(self) -> str:
        return OPERATION


@dataclass(frozen=True)
class TransportDestination:
    kind: str
    host: str
    launch_session: str | None
    socket: SocketSelector | None


def _host(value: str) -> str | None:
    host = value.rsplit("@", 1)[-1]
    if not host or host.startswith("-") or len(host) > 255:
        return None
    try:
        _machine(host)
    except RequestError:
        return None
    return host


def transport_destination(argv: tuple[str, ...]) -> TransportDestination | None:
    """Parse only recognized transport argv; return no host on uncertain grammar."""
    launch = transport_command_hint(argv)
    if launch is not None:
        kind, host, command = launch
        target = command.target
        socket = command.socket
        if socket is not None:
            try:
                socket = parse_socket({"kind": socket.kind, "value": socket.value})
            except RequestError:
                return None
        host = _host(host)
        return TransportDestination(
            kind, host, target.session if target.session_kind == "name" else None,
            socket,
        ) if host is not None else None

    if not argv:
        return None
    kind = PurePath(argv[0]).name
    values = list(argv[1:])
    if kind == "mosh-client":
        # mosh-client's display text carries the launch host even when the
        # remote shell was entered without a tmux launch command.
        if not values or not values[0].startswith("-#"):
            return None
        try:
            display = shlex.split(values[0][2:].strip())
        except ValueError:
            return None
        if display[:1] != ["--"] or len(display) < 2:
            return None
        host = _host(display[1])
        return TransportDestination("mosh", host, None, None) if host else None
    if kind == "et":
        hosts: list[str] = []
        while values:
            value = values.pop(0)
            if value == "--":
                hosts.extend(values)
                break
            name, equals, _ = value.partition("=")
            if value.startswith("--") and equals and name in _ET_VALUE_OPTIONS | _ET_FLAGS:
                continue
            if value in _ET_VALUE_OPTIONS:
                if not values:
                    return None
                values.pop(0)
            elif value in _ET_FLAGS or value.startswith("-c") and len(value) > 2:
                continue
            elif value.startswith("-"):
                return None
            else:
                hosts.append(value)
        host = _host(_et_host(hosts[0]) or "") if len(hosts) == 1 else None
        return TransportDestination("et", host, None, None) if host else None
    if kind not in {"ssh", "mosh"}:
        return None
    options = {
        "ssh": {"-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J",
                "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"},
        "mosh": {"-p", "--port", "--ssh"},
    }[kind]
    flags = {"-4", "-6", "-A", "-a", "-C", "-f", "-g", "-K", "-k", "-M",
             "-N", "-n", "-q", "-s", "-T", "-t", "-V", "-v", "-X", "-x", "-Y", "-y"}
    while values and values[0] != "--" and values[0].startswith("-"):
        option = values.pop(0)
        if option in options:
            if not values:
                return None
            values.pop(0)
        elif any(option.startswith(prefix + "=") for prefix in options):
            continue
        elif option in flags or (
            kind == "ssh" and len(option) > 2
            and all("-" + flag in flags for flag in option[1:])
        ):
            continue
        else:
            return None
    if values and values[0] == "--":
        values.pop(0)
    host = _host(values[0]) if values else None
    return TransportDestination(kind, host, None, None) if host else None


def _reason(code: str, source: str, message: str, retryable: bool = False) -> dict[str, Any]:
    return {"code": code, "source": source, "message": message[:512],
            "retryable": retryable}


def _response(request: WindowSessionRequest, status: str,
              session: dict[str, str] | None = None,
              reasons: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "schema": RESPONSE_SCHEMA, "resolverVersion": VERSION,
        "requestId": request.request_id, "operation": OPERATION,
        "status": status, "session": session, "reasons": reasons or [],
    }


def _tmux_socket(argv: tuple[str, ...]) -> tuple[SocketSelector | None, bool]:
    values = list(argv[1:])
    selectors: list[SocketSelector] = []
    for index, value in enumerate(values):
        if value not in {"-L", "-S"}:
            continue
        if index + 1 >= len(values):
            return None, False
        try:
            selectors.append(parse_socket({
                "kind": "name" if value == "-L" else "path",
                "value": values[index + 1],
            }))
        except RequestError:
            return None, False
    return (selectors[0], True) if len(selectors) == 1 else (None, not selectors)


class WindowSessionReader:
    """Read a current session only from sole-owner, live window evidence."""

    def resolve(self, request: WindowSessionRequest, collector: Any) -> dict[str, Any]:
        if sum(item.pid == request.window.pid for item in request.windows) != 1:
            return _response(request, "none")
        deadline = Deadline(request.limits.deadline_ms)
        try:
            observation: WindowObservation = collector.collect_window_session(request, deadline)
        except CollectionFailure as error:
            issue = error.error
            return _response(request, "unknown", reasons=[_reason(
                issue.code, issue.source, issue.message, issue.retryable
            )])
        except (OSError, ValueError):
            return _response(request, "unknown", reasons=[_reason(
                "local_collection_failed", "proc", "window process read failed", True
            )])
        if observation.collection_state != "complete":
            return _response(request, "unknown", reasons=[
                _reason(item.code, item.source, item.message, item.retryable)
                for item in observation.errors
            ] or [_reason("local_collection_incomplete", "proc",
                           "window process read was incomplete", True)])
        root = [node for node in observation.processes
                if node.identity.pid == request.window.pid
                and node.identity.start_time_ticks == request.window.start_time_ticks]
        if len(root) != 1:
            return _response(request, "unknown", reasons=[_reason(
                "window_identity_changed", "proc", "window PID/start ticks changed", True
            )])
        transports = [node for node in observation.processes
                      if node.argv and PurePath(node.argv[0]).name
                      in {"ssh", "et", "mosh", "mosh-client"}]
        tmux = [node for node in observation.processes
                if node.argv and PurePath(node.argv[0]).name == "tmux"]
        if transports:
            if len(transports) != 1:
                return _response(request, "unknown", reasons=[_reason(
                    "transport_ambiguous", "proc", "more than one transport is in the window tree"
                )])
            destination = transport_destination(transports[0].argv)
            if destination is None:
                return _response(request, "unknown", reasons=[_reason(
                    "transport_unparsed", "argv", "transport destination is unknown"
                )])
            return self._remote_session(
                request, collector, deadline, transports[0].identity, destination
            )
        if len(tmux) == 0:
            return _response(request, "none")
        if len(tmux) != 1:
            return _response(request, "unknown", reasons=[_reason(
                "tmux_client_ambiguous", "proc", "more than one tmux process is in the window tree"
            )])
        socket, valid_socket = _tmux_socket(tmux[0].argv)
        if not valid_socket:
            return _response(request, "unknown", reasons=[_reason(
                "tmux_socket_ambiguous", "argv", "tmux socket selector was ambiguous"
            )])
        try:
            clients = collector.local_session_clients(
                socket, request.local_machine, deadline
            )
        except CollectionFailure as error:
            issue = error.error
            return _response(request, "unknown", reasons=[_reason(
                issue.code, issue.source, issue.message, issue.retryable
            )])
        except (OSError, ValueError):
            return _response(request, "unknown", reasons=[_reason(
                "local_tmux_unavailable", "tmux", "local tmux read failed", True
            )])
        matches = [client for client in clients
                   if client.process.pid == tmux[0].identity.pid
                   and client.process.start_time_ticks == tmux[0].identity.start_time_ticks]
        if len(matches) != 1 or not matches[0].current_session:
            return _response(request, "unknown", reasons=[_reason(
                "tmux_client_unattributed", "tmux", "current tmux client was not uniquely found", True
            )])
        return _response(request, "found", {
            "name": matches[0].current_session, "basis": "current",
            "method": "local-client",
        })

    def _remote_session(
        self, request: WindowSessionRequest, collector: Any, deadline: Deadline,
        transport_identity: Any, destination: TransportDestination,
    ) -> dict[str, Any]:
        launch = destination.launch_session

        def fallback(code: str, message: str, retryable: bool = False) -> dict[str, Any]:
            reason = _reason(code, "transport", message, retryable)
            if launch is None:
                return _response(request, "unknown", reasons=[reason])
            return _response(request, "found", {
                "name": launch, "host": destination.host,
                "transport": destination.kind, "basis": "launch", "method": "launch",
            }, [reason])

        if launch is None:
            try:
                local_clients = collector.local_transport_clients(
                    destination.kind, destination.host, request.local_machine, deadline
                )
            except CollectionFailure as error:
                return fallback(error.error.code, error.error.message, error.error.retryable)
            except (OSError, ValueError):
                return fallback("local_transport_scan_incomplete",
                                "local transport count was incomplete", True)
            if (len(local_clients) != 1
                    or local_clients[0].pid != transport_identity.pid
                    or local_clients[0].start_time_ticks != transport_identity.start_time_ticks):
                return _response(request, "none")
        try:
            remote = collector.remote_session_read(
                destination.host, destination.socket, launch is None, deadline
            )
        except CollectionFailure as error:
            return fallback(error.error.code, error.error.message, error.error.retryable)
        except (OSError, ValueError):
            return fallback("remote_unreachable", "remote session read failed", True)
        if not isinstance(remote, dict) or not isinstance(remote.get("host"), str):
            return fallback("remote_output_invalid", "remote session result was invalid", True)
        from .model import machine_matches
        if not machine_matches(destination.host, remote["host"]):
            return fallback("remote_host_mismatch", "remote host did not match transport", True)
        if remote.get("incomplete"):
            return fallback("remote_collection_incomplete",
                            "remote tmux collection was incomplete", True)
        if launch is None:
            try:
                local_clients_after = collector.local_transport_clients(
                    destination.kind, destination.host, request.local_machine, deadline
                )
            except CollectionFailure as error:
                return fallback(error.error.code, error.error.message, error.error.retryable)
            except (OSError, ValueError):
                return fallback("local_transport_scan_incomplete",
                                "local transport count was incomplete", True)
            if local_clients_after != local_clients:
                return fallback("local_transport_changed",
                                "local transport count changed during read", True)
        clients = remote["clients"]
        if launch is not None:
            qualified = [item["session"] for item in clients
                         if item["kind"] == destination.kind
                         and item["launchTarget"] == launch
                         and item["remoteEndPid"] is not None]
            if qualified and len(set(qualified)) == 1:
                return _response(request, "found", {
                    "name": qualified[0], "host": destination.host,
                    "transport": destination.kind, "basis": "current",
                    "method": "remote-ancestry",
                })
            return fallback("current_unattributed",
                            "current session could not be attributed")
        ends = remote.get("terminalEnds")
        pids = ends.get(destination.kind) if isinstance(ends, dict) else None
        if not isinstance(pids, list) or len(pids) != 1:
            return _response(request, "none")
        qualified = [item["session"] for item in clients
                     if item["kind"] == destination.kind
                     and item["remoteEndPid"] == pids[0]]
        if qualified and len(set(qualified)) == 1:
            return _response(request, "found", {
                "name": qualified[0], "host": destination.host,
                "transport": destination.kind, "basis": "current",
                "method": "remote-unique-connection",
            })
        return _response(request, "none")


def _window_key(window: Window) -> tuple[str, str, int, str]:
    return (window.stable_id, window.address, window.pid, window.start_time_ticks)


def parse_window_session_request(value: Any) -> WindowSessionRequest:
    raw = _mapping(value, "request")
    allowed = {"schema", "requestId", "operation", "window", "windows", "local", "limits"}
    required = {"schema", "requestId", "operation", "window", "windows", "local"}
    _exact_keys(raw, allowed, required, "request")
    if raw["schema"] != REQUEST_SCHEMA:
        raise RequestError("unsupported_schema", "request schema is unsupported")
    if raw["operation"] != OPERATION:
        raise RequestError("unsupported_operation", "operation is unsupported")
    request_id = _plain(raw["requestId"], "request_id", maximum=128)
    window = parse_window(raw["window"])
    windows_raw = raw["windows"]
    if not isinstance(windows_raw, list) or not 1 <= len(windows_raw) <= 4096:
        raise RequestError("invalid_windows", "windows must be a bounded nonempty array")
    windows = tuple(parse_window(item) for item in windows_raw)
    keys = [_window_key(item) for item in windows]
    if len(set(keys)) != len(keys):
        raise RequestError("duplicate_window_identity", "window identities must be unique")
    if keys.count(_window_key(window)) != 1:
        raise RequestError("window_not_in_snapshot", "selected window identity is absent")
    local = _mapping(raw["local"], "local")
    _exact_keys(local, {"machine"}, {"machine"}, "local")
    return WindowSessionRequest(
        request_id, window, windows,
        canonical_machine(_machine(local["machine"], "local_machine")),
        _parse_limits(raw["limits"]) if "limits" in raw else Limits(),
    )
