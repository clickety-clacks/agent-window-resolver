# Transport policy v1 (shared by Yoohoo and Omarchy Ask)

The resolver observes; the applications choose. This document is the one
definition of how Yoohoo and Ask turn a user preference and an observation
into a connection, so the two cannot drift apart again. Both apps implement it
in their own language (it is a few lines) and test themselves against
`fixtures/transport-policy-v1.json`, which each app copies verbatim.

## The setting

One key with the same name and values in both apps:

    transport = "auto" | "local" | "et" | "mosh" | "ssh"      default "auto"

Yoohoo reads it from `[agentd_hub]` in `~/.config/window-attention/config.toml`;
Ask reads `agentdHub.transport` in `~/.config/omarchy/ask.json`. Any other value
means `auto`. The apps never write discovered facts into these files.

## Choosing

Inputs: the preference, whether the target is on this machine, which client
executables exist here (`et`, `mosh`, `ssh`), and the recorded capability for
the host (each of et, mosh, ssh `available`, `unavailable` or `unknown`), or
none.

1. A target on this machine attaches locally, whatever the preference.
2. `local` for a remote target is unavailable (`local_requires_local_target`).
3. An explicit `et`, `mosh` or `ssh` is used when its client exists here,
   whatever the capability says; otherwise unavailable (`<name>_client_missing`).
4. `auto` takes the first of:
   - et, if the et client exists and capability says et is `available`;
   - mosh, if the mosh client exists and capability does not say mosh is
     `unavailable` (no record behaves exactly like the old mosh-first ladder);
   - ssh, if the ssh client exists.
   Otherwise unavailable (`no_transport_client`).
5. Any transport other than ssh gets ssh as its runtime fallback when the ssh
   client exists.

et needs positive evidence because it is new: a host without a record keeps
mosh-first behaviour, so discovery can never add a failure mode.

## Launching

The terminal runs the argv in the vectors' `launch` section. Every remote
command is wrapped as `sh -lc '<command>'` (single quotes, `'` written as
`'\''`) wherever a remote login shell parses it, which is ssh's command and
et's `-c` (et types its command into the remote shell). mosh receives
`sh -lc <command>` as argv. ssh always gets `-tt`.

With a fallback, a fixed POSIX script runs the primary transport; on a nonzero
exit it checks the host with `ssh -o BatchMode=yes true`. Only if that succeeds
(the host is reachable, so the transport itself failed) does it delete the
host's capability record. Then it execs `ssh -tt`. et and mosh exit 0 on a
normal detach or end of session and nonzero when they cannot connect, so a
normal exit never reconnects.

## Capability records

Each app keeps one JSON file per host under its state directory
(`$XDG_STATE_HOME/<app>/transport-capabilities/<host>.json`), separate from the
user's settings:

```json
{"schema": "transport-capabilities.v1", "host": "gibson",
 "observedAtUnixMs": 1790000000000, "resolverVersion": "0.2.0",
 "transports": { ...the resolver's transports object... }}
```

- No record, or a record older than 7 days: the next activation's
  `verify-target` request sets `probeTransports: true`.
- `complete` or `partial` observations are written; `unreachable` and
  `not_applicable` are not (a roaming laptop on a hostile network must not
  overwrite what it learned elsewhere).
- If the probe times out or the resolver predates 0.2.0, the app connects with
  no record (rule 4's mosh-first behaviour). Discovery never blocks a launch.
- The fallback script deletes the record after a transport failure on a
  reachable host, so the next activation re-probes.
