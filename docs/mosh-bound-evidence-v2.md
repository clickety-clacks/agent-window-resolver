# Mosh bound-endpoint evidence proposal

The v1 resolver requires a reversed full UDP tuple. That is truthful for a
connected mosh client, but not for a roaming `mosh-server`: its UDP socket is
normally bound to the server port with a wildcard remote peer.

Do not synthesize a reverse peer or weaken v1's `endpoint_linked` predicate.
For a future schema version, add an explicit transport relation such as
`mosh_bound_client` with these independently verified facts:

1. The local terminal's mosh-client process has one connected UDP endpoint.
2. The remote mosh-server process is the exact target process (PID and start
   ticks), owns one bound UDP socket on the client-declared server port, and
   has the proven tmux client/pane ancestry.
3. The mosh client command/session token and the remote server port correlate
   to the same target; a wildcard remote peer is represented as `remote: null`
   or an explicit `bound` endpoint state, never as a fabricated address.
4. The local Hypr window and both process graphs are revalidated after probes.

The relation may authorize an existing-window action only if all four facts
are complete and unique. Missing UDP ownership, ambiguous ancestry, changed
PID/start ticks, or a changed server port returns unresolved. `linked_client`
and `visible_exact` remain distinct, and v1 callers must continue to reject
this relation as unsupported.

This is a design note only; it is not a v1 schema or implementation change.
