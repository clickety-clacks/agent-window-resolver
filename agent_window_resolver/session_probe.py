"""Fixed, bounded remote read for the additive window-session operation."""

# This program runs through one strict SSH invocation. It emits only the host,
# current tmux session, the associated remote-end PID/kind, launch target, and
# (when requested for TS-4) counts/PIDs of terminal-serving remote ends.
REMOTE_SESSION_PROBE = r'''
import base64, json, os, selectors, subprocess, sys, time

cfg = json.loads(base64.urlsafe_b64decode(sys.argv[1] + "=" * (-len(sys.argv[1]) % 4)))
MAX_CLIENTS = 256
MAX_DEPTH = 64
MAX_PROCESSES = 32768
MAX_STAT = 4096
MAX_CMDLINE = 65536
END_NAMES = {"sshd": "ssh", "etterminal": "et", "mosh-server": "mosh"}

def bounded(path, limit):
    with open(path, "rb", buffering=0) as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise RuntimeError("bounded proc read exceeded")
    return value

def stat(pid):
    raw = bounded("/proc/%d/stat" % pid, MAX_STAT).decode("ascii", "strict")
    head, tail = raw.rsplit(") ", 1)
    name = head.split("(", 1)[1]
    fields = tail.split()
    return (name, int(fields[1]), int(fields[4]), str(int(fields[19])))

def argv(pid):
    return [item.decode("utf-8", "replace") for item in
            bounded("/proc/%d/cmdline" % pid, MAX_CMDLINE).split(b"\0") if item]

def ancestry(pid):
    seen, result = set(), []
    for _ in range(MAX_DEPTH):
        if pid in seen or pid < 1:
            raise RuntimeError("process ancestry cycle")
        seen.add(pid)
        before = stat(pid)
        command = argv(pid)
        after = stat(pid)
        if before != after:
            raise RuntimeError("process identity changed")
        result.append((pid, before[0], command))
        if before[1] <= 1:
            return result
        pid = before[1]
    raise RuntimeError("process ancestry depth exceeded")

def run_tmux(command):
    env = dict(os.environ)
    env.pop("TMUX", None)
    env["LC_ALL"] = "C"
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               close_fds=True, env=env)
    select = selectors.DefaultSelector()
    output, errors = bytearray(), bytearray()
    deadline = time.monotonic() + 5.0
    try:
        select.register(process.stdout, selectors.EVENT_READ, output)
        select.register(process.stderr, selectors.EVENT_READ, errors)
        while select.get_map():
            remaining = deadline - time.monotonic()
            events = select.select(remaining) if remaining > 0 else []
            if not events:
                raise RuntimeError("tmux read timed out")
            for key, _ in events:
                buffer = key.data
                limit = 65536 if buffer is output else 4096
                chunk = os.read(key.fileobj.fileno(), min(8192, limit + 1 - len(buffer)))
                if not chunk:
                    select.unregister(key.fileobj)
                    continue
                buffer.extend(chunk)
                if len(buffer) > limit:
                    raise RuntimeError("tmux output bound exceeded")
        process.wait(timeout=max(.1, deadline - time.monotonic()))
        if process.returncode == 0:
            return output.decode("utf-8", "strict")
        diagnostic = errors.decode("utf-8", "replace").strip()
        if diagnostic == "no clients":
            return ""
        if (diagnostic.startswith("no server running") or
                (diagnostic.startswith("error connecting to ") and
                 "No such file or directory" in diagnostic)):
            return None
        raise RuntimeError("tmux list-clients failed")
    finally:
        select.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()

def client_rows():
    selectors = [None]
    if cfg.get("socket") is not None:
        selectors.append(cfg["socket"])
    result = []
    incomplete = False
    for selector in selectors:
        base = ["tmux"]
        if selector is not None:
            base += ["-L" if selector["kind"] == "name" else "-S", selector["value"]]
        output = run_tmux(base + ["list-clients", "-F", "#{client_pid}\t#{client_session}"])
        if output is None:
            # The named socket is requested evidence. The default is optional
            # when it has no server, but any other tmux failure remains unknown.
            incomplete = incomplete or selector is not None
            continue
        lines = output.splitlines()
        if len(lines) > MAX_CLIENTS:
            raise RuntimeError("tmux client count exceeded")
        for line in lines:
            fields = line.split("\t")
            if len(fields) != 2 or not fields[1] or len(fields[1]) > 256:
                raise RuntimeError("invalid tmux client row")
            result.append((int(fields[0]), fields[1]))
    if len(result) > MAX_CLIENTS:
        raise RuntimeError("tmux client count exceeded")
    return sorted(set(result)), incomplete

def launch_target(command):
    if not command or os.path.basename(command[0]) != "tmux":
        return None
    values = command[1:]
    if len(values) >= 2 and values[0] in ("-L", "-S"):
        values = values[2:]
    if len(values) >= 3 and values[0] in ("attach", "attach-session") and values[1] == "-t":
        target = values[2]
    elif len(values) >= 4 and values[0] in ("new", "new-session") and values[1:3] == ["-A", "-s"]:
        target = values[3]
    elif len(values) >= 3 and values[0] in ("new", "new-session") and values[1] in ("-s", "-As"):
        target = values[2]
    else:
        return None
    target = target.lstrip("=")
    return target if target and len(target) <= 256 and ":" not in target and "." not in target else None

def terminal_ends():
    own_ancestors = set()
    current = os.getpid()
    for _ in range(MAX_DEPTH):
        if current in own_ancestors or current < 1:
            raise RuntimeError("probe ancestry cycle")
        own_ancestors.add(current)
        parent = stat(current)[1]
        if parent <= 1:
            break
        current = parent
    rows = {}
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            if len(rows) >= MAX_PROCESSES:
                raise RuntimeError("process count bound exceeded")
            pid = int(entry.name)
            try:
                before = stat(pid)
                after = stat(pid)
            except (FileNotFoundError, ProcessLookupError):
                continue
            if before != after:
                raise RuntimeError("process identity changed")
            rows[pid] = before
    children_with_tty = {item[1] for item in rows.values() if item[2] != 0}
    result = {kind: [] for kind in END_NAMES.values()}
    for pid, item in rows.items():
        kind = END_NAMES.get(item[0])
        if kind is None and item[0].startswith("sshd:"):
            kind = "ssh"
        if kind and pid not in own_ancestors and pid in children_with_tty:
            result[kind].append(pid)
    return {key: sorted(value) for key, value in result.items()}

host = bounded("/proc/sys/kernel/hostname", 255).decode("utf-8", "strict").strip()
before, incomplete = client_rows()
clients = []
for pid, session in before:
    chain = ancestry(pid)
    ends = [(item_pid, END_NAMES.get(name, "ssh" if name.startswith("sshd:") else None))
            for item_pid, name, _ in chain
            if name in END_NAMES or name.startswith("sshd:")]
    remote_end_pid, kind = ends[0] if len(ends) == 1 else (None, None)
    clients.append({"pid": pid, "session": session,
                    "remoteEndPid": remote_end_pid, "kind": kind,
                    "launchTarget": launch_target(chain[0][2])})
counts = terminal_ends() if cfg.get("needCounts") else None
after, incomplete_after = client_rows()
if before != after:
    raise RuntimeError("tmux clients changed during read")
print(json.dumps({"host": host, "clients": clients,
                  "terminalEnds": counts,
                  "terminalEndCounts": {key: len(value) for key, value in counts.items()}
                  if counts is not None else None,
                  "incomplete": incomplete or incomplete_after},
                 separators=(",", ":")))
'''
