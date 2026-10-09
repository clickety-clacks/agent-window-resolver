"""Additive window-session request type; v1 target requests use their own parser."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .model import (
    Limits, RequestError, Window, _exact_keys, _machine, _mapping,
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
