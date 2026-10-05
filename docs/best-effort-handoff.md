# Best-effort source handoff, September 14, 2026

Shared schema: `schema/v1.json`. Semantics: `docs/contract-v1.md`.
Bundle the seven source files unchanged; no separate installation or discovery.
Ask owns its adapter, Yoohoo owns its adapter, and neither keeps a private matcher.

Final SHA256 source snapshot:

```
eb4317c4f98a441006f7dd11e458596c8df32a5487b1ccccba5743ad69ea285b  __init__.py
6d8b7d7846a845059d7a3107143f11131f63c5511d669b44085b15ec5e3d2279  __main__.py
8456de39f7234d2d21d1b8fb1b322de59aa97348498bf5c90dbc2fbf0c45474a  cli.py
c080b3050ef7ca5018bb1bf348acb3334286880ba5b99f8c755b9d64f9e526ce  collector.py
f2911ba1d4cca826542ed8c1a8be571a6688ac7f37443b7cd996775d7663af45  linux.py
c917960688c83989998beb77b8a070ff250df061683a6dd47610d2063b6e172d  model.py
24174377501e53434c8786f75641be5be9e71baa9b0e96274e9e1aca72d40d42  resolver.py
```

The test machine validation: 81 core tests, 80 Yoohoo tests, and the actual two-Ghostty
window production activation test passed. The three captured mosh command forms
match without endpoints in shared regression tests. Follow-up Yoohoo activation
tests also passed with two real mosh connections and with a real local
Ghostty/tmux window, including workspace navigation, acknowledgement, unchanged
window/client sets, and cleanup. The installed desktop popup was not test-clicked.
No automated tests ran on the desktop. Mike subsequently authorized the
Yoohoo fix installation there; only its tracker service was restarted. Ask
deployment remains under its own authorization.

Corrected after Ask's handoff review: remote `match` skips target probing,
including for tmux targets, and reports `remote_target_not_probed` uncertainty.
Strict target verification keeps its existing behavior.
The live two-window check now includes synthetic remote tmux metadata and
fails before executing any SSH/mosh subprocess. This supersedes the earlier
`linux.py` hash `0aefbddc...`, which still probed remote tmux targets.

Local tmux correction: an existing client with generic title/argv is matched
using current tmux session/window/pane and client PID/start identity within its
terminal subtree. Full target/transport probing is no longer required for local
`match`. A live private-tmux unnamed-client regression failed before this change
and passed afterward on the test machine. This supersedes `c83fd9f9...` locally as well.

For `match`, consume ranked candidates, including multiple candidates for one
agent. Distinguish evidence from proof. Prefer an existing match, then refresh
compositor and process identity before focus. A failed/missing window scan with
no candidate returns `local_collection_incomplete`, not `candidate_count`;
do not treat it as permission to create another connection.
