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
    _parse_limits, _plain, canonical_machine, parse_window,
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
        return TransportDestination(
            kind, _host(host) or "", target.session if target.session_kind == "name" else None,
            command.socket,
        ) if _host(host) is not None else None

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


def _tmux_socket(argv: tuple[str, ...]) -> SocketSelector | None:
    values = list(argv[1:])
    selectors: list[SocketSelector] = []
    for index, value in enumerate(values[:-1]):
        if value in {"-L", "-S"} and values[index + 1]:
            selectors.append(SocketSelector(
                "name" if value == "-L" else "path", values[index + 1]
            ))
    return selectors[0] if len(selectors) == 1 else None


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
            # The remote read is a separate collector stage. It must succeed
            # before a current session can be attributed to this window.
            return _response(request, "unknown", reasons=[_reason(
                "remote_read_pending", "transport", "remote session read is unavailable", True
            )])
        if len(tmux) == 0:
            return _response(request, "none")
        if len(tmux) != 1:
            return _response(request, "unknown", reasons=[_reason(
                "tmux_client_ambiguous", "proc", "more than one tmux process is in the window tree"
            )])
        try:
            clients = collector.local_session_clients(
                _tmux_socket(tmux[0].argv), request.local_machine, deadline
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
