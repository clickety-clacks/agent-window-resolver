# Agent Window Resolver

A Python standard-library implementation for relating an agent process to an
existing terminal window through local process ancestry, tmux and remote
transport evidence. The resolver collects observations; the calling application
owns focus, attachment and acknowledgement.
The additive `match` operation also ranks best-effort title, agent/session,
SSH, mosh and et hints when exact transport proof is unavailable.
`verify-target` can also report which of et, mosh and ssh actually reach the
target machine; choosing one stays with the calling application.

## Including the library

Ship the `agent_window_resolver/` Python package inside the consuming application.
Users install Ask or Yoohoo normally; they do not install or configure a resolver
executable. Keep the source copy in each application's version control and update
it deliberately from this canonical source, together with the relevant tests.
Exclude editor backups, `.orig`, `.rej` and `__pycache__` directories when copying.
Each application records the upstream URL, vendored commit and sync date in
`agent_window_resolver/VENDORED.json` beside its copy and re-vendors with its
own sync script; its install test checks the copy against that commit.

Python callers use `Resolver().resolve(request, collector)`. A production collector
is available as `agent_window_resolver.linux.LinuxCollector`; tests can inject a
collector. Requests and responses follow `docs/contract-v1.md` and `schema/v1.json`.
A separate read-only `window-session` request follows
`docs/window-session-v1.md` and `schema/window-session-v1.json`; it reads the
current tmux session of one supplied sole-owner window for Scottland without
changing v1 target requests or their responses.
A Node application can call a bundled Python helper at a fixed package-relative
path. This is an internal implementation detail, not a separately installed
service or configurable resolver command. Each response names the library
version that produced it (`resolverVersion`), so a caller can detect a stale
vendored copy.

Importing the package does not collect observations. Calling the Linux collector
can run bounded process, tmux and SSH probes. The caller must obtain fresh
compositor and process identities after probes before focusing a window. A failed
probe or ambiguous match does not authorize choosing an arbitrary window.

## Verification

Run the pure suite from this directory with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p 'test_*.py'
```

Live integration tests under `tests/integration/` are separate and require an
explicitly selected test machine. Pure tests are not proof of live mosh matching;
the current bound-socket limitation is described in
`docs/mosh-bound-evidence-v2.md`.
