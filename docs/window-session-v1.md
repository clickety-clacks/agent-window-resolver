# Window session reading, additive protocol v1

This operation answers which tmux session one supplied desktop window is showing.
It is read-only. The existing `agent-window-resolver.request.v1` and
`agent-window-resolver.response.v1` protocols retain their exact behavior.

The JSON CLI accepts one `agent-window-resolver.window-session.request.v1`
request and returns one `agent-window-resolver.window-session.response.v1`
response under the same framing, byte, and deadline ceilings as resolver v1.
The caller supplies a complete current desktop window snapshot because a
process tree identifies a window only when its PID owns no other window.
`window` must occur exactly once in `windows` with the same four identity
fields. Windows use the v1 `stableId`, `address`, `pid`, and canonical decimal
`startTimeTicks` form. `local.machine` uses v1 machine comparison.

```json
{"schema":"agent-window-resolver.window-session.request.v1","requestId":"example-1","operation":"window-session","window":{"stableId":"17","address":"0x11","pid":102,"startTimeTicks":"123"},"windows":[{"stableId":"17","address":"0x11","pid":102,"startTimeTicks":"123"}],"local":{"machine":"laptop"}}
```

A `found` response has `session.name` and `session.basis`. A remote session
also has `session.host` (the launch host without `user@`) and
`session.transport` (`ssh`, `mosh`, or `et`). `basis: current` means the current
tmux client was attributed under TS-1, SL-6, or SL-7; it is eligible as
SR-5 attribution, though it is not a resolver v1 `visible_exact` proof.
`basis: launch` is only a parsed launch target and cannot support SR-5.
`method` distinguishes the source of a current attribution.

`none` means collection completed and no terminal session qualifies.
`unknown` means required evidence could not be collected or was ambiguous;
it never asserts absence. If a remote read fails but a launch target exists,
the response is `found` with `basis: launch` and a reason describing the
failed current read. Shared-process windows return `none` without reading
their process tree. No response asks a caller to act on a window or client.

The operation observes local `(pid,startTimeTicks)` identities and bounded
tmux/process data. Its only remote read is SL-5: one strict SSH invocation per
host/request, fixed Python, current tmux clients and their bounded ancestry;
for TS-4 only, counts and PIDs of remote terminal-serving ends. It writes
nothing, changes no tmux state, and returns no raw process dump.

The structural schema is `schema/window-session-v1.json`. The Scottland
Window Names part 3 v3 contract defines TS-1 through TS-5, SL-5 through
SL-7, and SR-5 semantics.
