# Agent Window Resolver protocol v1

## Scope

The resolver is a Python-standard-library, read-only core with a JSON CLI. It
answers four questions: which supplied compositor window has a requested
relation to an Agentd target (`resolve`), whether a previously chosen window
still has that relation (`revalidate`), whether a target identity and
location are live (`verify-target`), and which existing windows are plausible
matches for an Agentd target (`match`).

The core does not focus windows, create or attach tmux clients, launch a
terminal, acknowledge notifications, subscribe to Agentd Hub, or run as a
daemon. Hub/SSE state and compositor commands are adapter responsibilities.
Action policy is also outside the core.

`schema/v1.json` is the normative structural schema. This document defines the
semantic rules that JSON Schema cannot express.

## CLI framing and resource limits

The executable reads exactly one UTF-8 JSON value from standard input and
writes exactly one compact UTF-8 JSON value followed by `\n` to standard
output. It rejects trailing non-whitespace input. Standard error is for a
bounded human diagnostic only; protocol consumers use the response.

Hard ceilings apply before caller limits: 256 KiB stdin, 1 MiB stdout, 16 KiB
stderr, and 20 seconds wall-clock per request. The optional `limits` object may
only reduce those ceilings. A limit above a hard ceiling is invalid rather than
silently widening it. The core terminates owned subprocesses at the deadline
and bounds every process walk, file read, SSH result, and emitted collection.
It constructs a result without truncation, then verifies its encoded size. If
the complete result exceeds the effective stdout limit, it emits a minimal
`invalid` response with reason `output_limit_exceeded` and exits `4`; if
even that response cannot fit, it emits no partial JSON and exits `4`.
Candidate or evidence truncation is forbidden and an ambiguous result is never
reduced to `matched`.

Exit codes are:

| Code | Meaning |
| --- | --- |
| `0` | A valid request produced a schema-valid domain response, including `unresolved`, `ambiguous`, or remote `unreachable`. |
| `2` | Malformed JSON, invalid request, or unsupported schema/operation. Emit `invalid` when a bounded response is possible. |
| `3` | A required local dependency is absent or incompatible. Emit `unreachable` with `dependency_missing` or `dependency_incompatible` when possible. |
| `4` | Internal or output encoding/limit failure prevented normal processing. Emit `invalid` with `internal_error` or `output_limit_exceeded` when possible. |
| `5` | The overall deadline expired. Emit `unreachable` with `deadline_exceeded` when possible. |

An error response uses `requestId: null` or `operation: null` only when that
field cannot be recovered safely. There is one shared implementation. Adapters
fail explicitly when it is absent or incompatible; they do not retain or
invoke a copied private fallback.

## Canonical request

Every request has:

- `schema: "agent-window-resolver.request.v1"` and a caller-unique
  `requestId`;
- an `operation`;
- `target.identity` with `machine`, caller-roster `instanceId`, numeric
  `pid`, and decimal-string `startTimeTicks`;
- optional `target.tmux` location;
- optional `target.name` (the roster/agent display name used for best-effort
  matching);
- `local.machine`; and
- caller-supplied `windows`, each with `stableId`, `address`, `pid`, and
  decimal-string `startTimeTicks` (plus optional `class` and compositor
  `title`).

All agent and window start ticks are canonical unsigned-64-bit decimal
strings: `0` or `[1-9][0-9]{0,19}`, value at most
`18446744073709551615`, without exponent notation or leading zero. Zero is a
valid observed Linux start tick for a process born in the first clock tick; it
is not an unknown-value sentinel. An adapter normalizes upstream integers to
strings before serialization. A JavaScript adapter rejects an unsafe numeric
input, never converts a tick string through `Number`, and compares canonical
ticks with `BigInt` or by digit length then lexical order. PIDs and ports
remain bounded JSON integers and are safely representable in supported
languages.

Machine comparison is ASCII case-insensitive after removing one trailing dot.
Exact names match. A short name and FQDN may match when their first labels
match; two different FQDNs do not. No DNS lookup is performed. A collision
created by short-name matching prevents a complete proof. Output canonicalizes
each request machine by ASCII lowercasing and removing one trailing dot; it
does not expand a short name or replace it with `local.machine`. Candidate and
verified-target identities preserve `instanceId`, PID, and ticks exactly and
equal the request target under this machine canonicalization.

`target.tmux` is absent for a direct local non-tmux target. Its absence does
not mean `no_tmux`, and missing tmux metadata is never reported as that fact.
A non-local target without tmux location cannot be resolved by v1 and is
`unresolved` with explicit evidence. tmux sockets use a tagged value:
`{"kind":"name","value":"..."}` maps only to `tmux -L`, while
`{"kind":"path","value":"/..."}` maps only to `tmux -S`. Neither adapters
nor the core guess the form from string content.

An omitted `tmux.socket` selects the default server, not an unknown server.
The core removes `TMUX`, inherits `TMUX_TMPDIR` unchanged in that probe
context, passes no `-L` or `-S` to the first
`tmux display-message -p '#{socket_path}'`, validates the returned absolute
path, and uses explicit `-S <that-path>` on all remaining commands. Failure to
obtain and consistently reuse that path is partial/unreachable, never a
complete proof. A normalized result replaces an omitted selector with the
proved `{"kind":"path","value":"<socket_path>"}`; explicit name and path
selectors retain their tagged input spelling. Revalidation resolves an omitted
selector again before comparing normalized locations.

Operation-specific fields are:

| Operation | Relation | Windows | Prior candidate |
| --- | --- | --- | --- |
| `resolve` | Required | Caller snapshot | Forbidden |
| `revalidate` | Required | Caller snapshot | Required in `prior` |
| `verify-target` | Forbidden | Must be empty | Forbidden |
| `match` | Forbidden | Caller snapshot | Forbidden |

`verify-target` also accepts `probeTransports: true` (a boolean; any other
operation that carries the field is `invalid_probe_transports`). See
"Transport reachability" below.

The prior candidate is a complete candidate previously returned by this
protocol. It is a claim to re-check, not trusted evidence. For `revalidate`,
its normalized target identity and location must equal the current request
target, its proof relation must equal `requestedRelation`, and its exact
four-field window identity must occur once in `windows`. A changed target or
missing/changed prior window yields zero-candidate `unresolved`; a wrong prior
relation or duplicate identity is `invalid`. Other supplied windows are not
substitutes and are not considered as candidates.

## Evidence and privacy

Evidence is a structured list of stable `code`, allowlisted `source`,
`result`, and optional bounded details. Reasons likewise have a stable code,
source, bounded message, and retryability flag. Programs branch on codes, not
messages. Implementations use specific codes such as
`target_process_mismatch`, `pane_membership_mismatch`,
`connection_unlinked`, `candidate_count`, `remote_unreachable`, and
`window_identity_changed`.

The core may read live process identity, bounded parent/child topology, argv
needed to identify an SSH/mosh/tmux transport, controlling TTY links, socket
endpoint metadata, tmux display/list-client metadata, and only
`SSH_CONNECTION` or `SSH_CLIENT` when endpoint evidence is needed. It does
not collect complete environments, terminal transcripts, shell history, pane
content, unrelated command output, or arbitrary `/proc` data. Raw argv, raw
Linux `/proc/net` byte encoding, and raw SSH environment values are never
emitted.

Network evidence is the full normalized tuple: protocol (`tcp` or `udp`),
`addressFamily` (`ipv4` or `ipv6`), and local/remote textual IP address
plus bounded integer port. Linux bytes are decoded internally. IPv4 is canonical
dotted decimal; IPv6 is lowercase RFC 5952-style compressed text. An
IPv4-mapped IPv6 address remains observed as `addressFamily: "ipv6"`, but an
exact mapped address and its IPv4 address share a derived 32-bit comparison key.
No other cross-family equivalence exists. A zone suffix is valid only on scoped
IPv6 and is preserved after validating a bounded interface name/index. Raw
zone names such as `eth0` are host-local and are never compared across hosts;
scoped endpoint linkage needs separately demonstrated scope mapping, otherwise
it is unresolved. The core never silently strips a zone.

Endpoint linkage requires equal protocol, reversed normalized address keys, and
reversed ports. Both ports must be 1 through 65535. Unspecified addresses
(`0.0.0.0` and `::`, with valid ports) and an unmapped scope may appear in
an endpoint only as informational evidence and never support a complete link.
Port zero is structurally invalid and is not emitted as an endpoint; it may
only cause a reason or evidence code without endpoint details. Ports alone
never prove a link.

`instanceId` is caller roster provenance. `/proc`, SSH, and tmux probes do
not prove it, so evidence does not claim otherwise. Live PID/start ticks and
pane membership are proven separately. An already proven match is not vetoed
solely because the roster is unknown, stale, or temporarily unreachable. A new
attach adapter may apply a stricter source/freshness policy before its separate
mutating action.

## Proof relations

A candidate contains the exact supplied window identity, normalized target
identity and location, and a proof. `complete` is a closed allow decision for
the named relation; `partial` is diagnostic only and always has relation
`partial`.

Common requirements for a complete proof are:

1. Every process used in the proof was re-read as a live
   `(pid, startTimeTicks)` pair during this request. A PID without matching
   start ticks is not identity.
2. The candidate window PID/start pair and stable ID/address agree with the
   caller snapshot. Window `class` is descriptive, never identity.
3. Target PID/start ticks are live on the target machine. For a tmux target,
   the process is a live member of the requested pane, and the pane's session,
   window index, pane ID, PID, and start ticks came from the selected socket.
4. Missing, unreadable, contradictory, or non-unique evidence cannot be
   upgraded to complete evidence.

`visible_exact` is evaluated independently for each candidate: that supplied
compositor window is currently the visible process-tree endpoint for the
target. More than one candidate may independently satisfy that predicate, in
which case response cardinality makes the result `ambiguous`. For a direct
local target, the live target process is the window process or is in its
bounded, cycle-checked process tree. For a tmux target, that window's live
process tree contains the uniquely identified transport/client path and the
linked tmux client is currently displaying the exact requested
session/window/pane. Endpoint linkage is required where multiple paths could
otherwise fit. A merely plausible client is not `visible_exact`.

`linked_client` means the candidate window's live process tree contains one
SSH/mosh transport whose full normalized endpoint tuple uniquely
reverse-matches one live remote tmux client transport on the same verified tmux
server and explicitly selected socket as the target. The target process still
has live PID/start identity and live membership in its requested pane, but the
linked client may currently display a different session, window, or pane. A
server/socket association that cannot be proved is partial, as are argv
host/session hints alone. Complete `linked_client` is deliberately not
interchangeable with `visible_exact`: Ask focus policy accepts only a freshly
revalidated `visible_exact` proof. Yoohoo may choose and switch a linked
client under its own policy, including a cross-session switch on that proven
server/socket, then request revalidation before acting.

Candidates are deduplicated by all four window identity fields, not by class or
PID alone. Output order is deterministic: ascending `stableId`, then
`address`, then PID and numeric start ticks.

## Status and cardinality

- `matched` for `resolve` or `revalidate` contains exactly one candidate with
  a complete proof whose relation equals `requestedRelation`; `matched` for
  `match` contains one or more ranked heuristic candidates.
- `ambiguous` is valid only for `resolve`, and contains more than one
  qualifying complete candidate, each for `requestedRelation`.
- `revalidate` returns `matched` only for the same prior target, relation,
  and four-field window identity. It otherwise returns zero-candidate
  `unresolved`, `unreachable`, or `invalid`; it never returns another
  candidate or `ambiguous`.
- `unresolved` has zero qualifying candidates. Strict-operation partial
  observations belong in top-level `evidence`, never in candidate
  authorization; `match` retains partial hint observations in each
  candidate's `uncertainty`.
- `unreachable` has zero candidates and means a required live probe could not
  complete. It is not evidence that a target, tmux location, or window does not
  exist.
- `invalid` has zero candidates and explicit reasons.
- `verified` is valid only for `verify-target`, has zero window candidates,
  and contains exactly one `verifiedTarget` whose PID/start and optional tmux
  location are completely verified.

`matched` and `verified` have no reasons. Other statuses have at least one
reason. JSON Schema enforces structural cardinality; the implementation
enforces relation equality and the full semantic proof predicates.

Candidate arrays contain qualifying candidates only. A caller that needs
`linked_client` discovery issues a separate request with that relation; a
`visible_exact` request never includes linked-only candidates.

## Best-effort matching

`match` is deliberately not a proof operation. It returns `status: "matched"`
when one or more supplied windows have usable evidence, including when several
windows plausibly represent the same target; it never returns `ambiguous`.
Candidates are ranked by descending `match.score`, then stable window identity
(`stableId`, address, PID, numeric start ticks). Adapters may use active/MRU
window state as their tie-break after this ranking. A match candidate has the
existing `window` and normalized result `target`, plus a `match` object with
`confidence` (`high`, `medium`, or `low`), an integer `score` from 0 through
100, structured `evidence`, and structured `uncertainty` reasons.

Titles, target/agent names, tmux session names, and parsed SSH/mosh transport
argv are useful evidence without claiming endpoint or pane proof. Exact local
PID/start-tick ancestry ranks highest. Parsed host and session hints rank
strongly, while title/name evidence ranks lower. Ordinary mosh argv is useful
matching evidence even when exact UDP correlation is unavailable. Collection
failures do not erase retained title or argv hints; they appear in the
candidate's structured `uncertainty`. Raw argv is never emitted. A transport
hint naming a different host does not itself qualify as a target match, but
does not veto an independently matching current title. Historical launch hints
can be stale; disagreements appear as uncertainty. Host-only hints never
qualify. Multiple windows with matching evidence remain eligible.

For `match`, a Linux collector skips probing a target whose machine does not
`machine_matches` the local machine. This applies to both remote tmux and
remote non-tmux targets, so the operation does not initiate SSH or other
remote target commands merely to rank existing local windows. It returns a
partial target observation with the explicit uncertainty code
`remote_target_not_probed`; retained local window observations and their title
or argv hints remain eligible. This skip is specific to best-effort `match`;
`resolve`, `revalidate`, and `verify-target` retain their strict target probe
behavior.

When no candidate is found and a supplied window was missing or incompletely
inspected, the result is `unresolved` with `local_collection_incomplete`, not
`candidate_count`. Adapters must not treat that as confirmed absence and open
another terminal. Retained useful candidates remain eligible despite incomplete
collection elsewhere.

`match` never emits a `proof` object and never authorizes focus, attachment, or
creation of a new terminal. Adapters must refresh compositor/window and
process identities before acting and should prefer an existing candidate over
starting a new connection.

For local tmux `match`, the collector reads the socket path, current client
session/window/pane rows, and client process identities. A corresponding client
in the supplied window subtree is ranked as heuristic evidence without requiring
target ancestry or transport inspection. Strict operations retain their full
probe. An unreadable client does not erase another usable match; incomplete
collection without a match cannot authorize a new connection.

## Freshness and adapter handoff

`resolve` and `revalidate` obtain fresh process, transport, socket, and
remote tmux topology within their deadline. The compositor list is explicitly
caller-supplied; the core does not invoke Hyprland.

For focus or dispatch, the adapter treats a resolver response as one stage of a
time-of-check/time-of-use defense. After all resolver probes return and
immediately before dispatch, it fetches Hyprland clients again and finds
exactly one entry matching the chosen `stableId`, `address`, and `pid`.
Because Hyprland does not supply start ticks, the adapter then independently
re-reads `/proc/<pid>/stat` and requires its start tick to equal the chosen
window's `startTimeTicks`. A missing, changed, duplicated, or unreadable field
cancels the action. The adapter also requires the relation its product policy allows;
Ask rejects `linked_client` for focus.

No successful response authorizes mutation by itself. Attach, focus,
notification acknowledgement, and other actions remain explicit adapter calls
with their own source and freshness policy.

## Normalization examples

These are contract fixtures, not suggestions. Normalization cases are
machine-readable in `fixtures/normalization-v1.json`; valid protocol examples
and negative revalidation/output cases are in
`fixtures/protocol-v1.json`:

| Input/source form | Public representation or result |
| --- | --- |
| start ticks integer text `00042` | Reject; it is not canonical. |
| JavaScript number `9007199254740993` | Reject as unsafe; do not round. |
| IPv4 bytes decoded as `192.0.2.10` | `{"addressFamily":"ipv4","address":"192.0.2.10"}` |
| IPv6 `2001:0DB8:0:0:0:0:0:1` | `{"addressFamily":"ipv6","address":"2001:db8::1"}` |
| IPv4-mapped `::FFFF:192.0.2.10` | Preserve `{"addressFamily":"ipv6","address":"::ffff:c000:20a"}`; its comparison key equals IPv4 `192.0.2.10`. |
| Link-local `fe80:0:0:0:1::1%eth0` | `{"addressFamily":"ipv6","address":"fe80::1:0:0:1%eth0"}`; scope is retained. |
| tmux socket `{"kind":"name","value":"agents"}` | Invoke with `-L agents`, never `-S`. |
| tmux socket `{"kind":"path","value":"/run/user/1000/tmux.sock"}` | Invoke with `-S /run/user/1000/tmux.sock`, never `-L`. |

An endpoint fixture includes the whole tuple. For example:

```json
{
  "protocol": "tcp",
  "addressFamily": "ipv4",
  "local": {"address": "192.0.2.10", "port": 52411},
  "remote": {"address": "198.51.100.7", "port": 22}
}
```

Its peer matches only if protocol and reversed normalized address keys and
ports match: local `198.51.100.7:22` and remote
`192.0.2.10:52411`.

## Transport reachability

A `verified` response to a `verify-target` request with `probeTransports:
true` carries `transports`: what this machine can reach on the target's
machine, measured, not inferred from installed binaries. The resolver never
chooses a transport; that is caller policy.

```json
"transports": {
  "state": "complete",
  "ssh":  {"state": "available",   "code": "ssh_probe_succeeded"},
  "et":   {"state": "available",   "code": "et_reachable", "port": 2022},
  "mosh": {"state": "unavailable", "code": "mosh_udp_blocked"}
}
```

One extra bounded SSH connection runs a standard-library probe on the target.
et is `available` only when `etserver` is running, `etterminal` is on the
non-interactive PATH, and a TCP connection from here to etserver's port (from
its `--port`, its config file, or 2022) succeeds. mosh is `available` only
when `mosh-server` is on that PATH and a nonce sent from here to a UDP port the
probe holds in 60001-60999 is echoed back. Both use the server address SSH
reached (`SSH_CONNECTION`).

`state` is `complete`, `partial` (some entries `unknown`), `unreachable` (the
probe SSH connection failed: every entry `unknown`; callers must not treat
this as a transport failure), or `not_applicable` (the target is local).
Entry states are `available`, `unavailable` or `unknown`; `code` is a stable
snake_case reason and `port` is present for et when known.

Window identification does not depend on this observation or on any caller
setting: et, mosh and ssh windows are recognized from what is running. et
client argv (`et [options] [--] host -c COMMAND`) is a host/session hint graded
like mosh (`et_hint_not_exact_proof`); there is no exact et proof because the
remote tmux client descends from `etterminal`, while the TCP connection belongs
to the shared `etserver`.

## Versioning

V1 consumers require exact request and response schema tags. Unknown tags,
operations, top-level fields, or enum values are invalid; there is no
best-effort version fallback. Additive fields require a new protocol version
unless an existing bounded extension point permits them.

Every response, including CLI framing errors, carries `resolverVersion`, the
library version (also printed by `--version`). Library 0.2.0 added
`resolverVersion`, `probeTransports` and `transports`. A caller that sends a
newer field to a vendored copy that predates it receives `invalid` without
`resolverVersion`; it should report "resolver too old", not "invalid
request".
