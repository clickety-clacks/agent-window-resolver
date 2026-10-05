"""Pure matcher tests; no Linux, tmux, or network access."""
from __future__ import annotations

from dataclasses import replace
import unittest

from agent_window_resolver import (
    Endpoint,
    ProcessIdentity,
    ProcessNode,
    Resolver,
    SocketSelector,
    StaticCollector,
    Target,
    TargetObservation,
    TmuxClient,
    TmuxLocation,
    TmuxPane,
    TopologySnapshot,
    Window,
    WindowObservation,
)
from agent_window_resolver.model import Limits, Request


LOCAL = "osanwe"


def identity(pid: int, ticks: str) -> ProcessIdentity:
    return ProcessIdentity(LOCAL, pid, ticks)


def direct_request(
    *, relation: str = "visible_exact", windows: tuple[Window, ...] | None = None
) -> Request:
    window = Window("window-1", "0xabc", 100, "20")
    return Request(
        "test-1", "resolve", relation,
        Target(identity(200, "42"), "agent-1"), LOCAL,
        windows if windows is not None else (window,), None, Limits(),
    )


def direct_snapshot(
    request: Request, *, state: str = "complete"
) -> TopologySnapshot:
    root = ProcessNode(identity(100, "20"), None)
    agent = ProcessNode(identity(200, "42"), root.identity)
    observation = WindowObservation(
        request.windows[0], (root, agent), state  # type: ignore[arg-type]
    )
    return TopologySnapshot(
        (observation,),
        TargetObservation(
            LOCAL, None, None, (agent,), None, ()
        ),
    )


class ResolverTests(unittest.TestCase):
    def test_direct_local_visible_exact_matches(self) -> None:
        request = direct_request()
        response = Resolver().resolve(
            request, StaticCollector(direct_snapshot(request))
        )
        self.assertEqual(response["status"], "matched")
        self.assertEqual(response["candidates"][0]["proof"]["relation"],
                         "visible_exact")

    def test_explicit_target_pane_boundary_allows_only_bound_target_graph(self) -> None:
        window = Window("window-1", "0xabc", 100, "20")
        target_identity = identity(42, "99")
        pane_identity = identity(600, "10")
        client_identity = identity(200, "30")
        target = Target(
            target_identity, "agent-1",
            TmuxLocation("ask", "1", "%1", None),
        )
        request = Request(
            "bounded-target", "resolve", "visible_exact", target, LOCAL,
            (window,), None, Limits(),
        )
        snapshot = TopologySnapshot(
            (WindowObservation(
                window,
                (ProcessNode(identity(100, "20"), None),
                 ProcessNode(client_identity, identity(100, "20"))),
            ),),
            TargetObservation(
                LOCAL, SocketSelector("path", "/tmp/tmux/socket"),
                "/tmp/tmux/socket",
                (ProcessNode(target_identity, pane_identity),
                 ProcessNode(pane_identity, None)),
                TmuxPane("ask", "1", "%1", pane_identity),
                (TmuxClient(
                    "client0", client_identity, "ask", "1", "%1",
                    (ProcessNode(client_identity, None),),
                ),),
                target_boundary=pane_identity,
                target_chain_complete=False,
            ),
        )
        response = Resolver().resolve(request, StaticCollector(snapshot))
        self.assertEqual(response["status"], "matched", response)

        unmarked = replace(
            snapshot.target, target_boundary=None, target_chain_complete=False,
        )
        response = Resolver().resolve(
            request, StaticCollector(TopologySnapshot(snapshot.windows, unmarked))
        )
        self.assertEqual(response["status"], "unresolved", response)
        self.assertEqual(response["candidates"], [])

        non_boolean = replace(
            snapshot.target, target_boundary=None, target_chain_complete="false",
        )
        response = Resolver().resolve(
            request, StaticCollector(TopologySnapshot(snapshot.windows, non_boolean))
        )
        self.assertEqual(response["status"], "unresolved", response)
        self.assertEqual(response["candidates"], [])

        corrupt = replace(
            snapshot.target,
            processes=snapshot.target.processes + (
                ProcessNode(identity(700, "11"), identity(700, "11")),
            ),
        )
        response = Resolver().resolve(
            request, StaticCollector(TopologySnapshot(snapshot.windows, corrupt))
        )
        self.assertEqual(response["status"], "unresolved", response)
        self.assertEqual(response["candidates"], [])

    def test_direct_local_never_claims_linked_client(self) -> None:
        request = direct_request(relation="linked_client")
        response = Resolver().resolve(
            request, StaticCollector(direct_snapshot(request))
        )
        self.assertEqual(response["status"], "unresolved")
        self.assertEqual(response["candidates"], [])

    def test_incomplete_window_scan_cannot_collapse_ambiguity(self) -> None:
        windows = (
            Window("window-1", "0xabc", 100, "20"),
            Window("window-2", "0xdef", 101, "21"),
        )
        request = direct_request(windows=windows)
        complete = WindowObservation(
            windows[0],
            (ProcessNode(identity(100, "20"), None),
             ProcessNode(identity(200, "42"), identity(100, "20"))),
        )
        partial = WindowObservation(windows[1], (), "partial")
        snapshot = TopologySnapshot(
            (complete, partial),
            TargetObservation(
                LOCAL, None, None,
                (ProcessNode(identity(200, "42"), None),), None, (),
            ),
        )
        response = Resolver().resolve(request, StaticCollector(snapshot))
        self.assertEqual(response["status"], "unresolved")
        self.assertEqual(response["candidates"], [])

    def test_dangling_parent_does_not_prove_window_relation(self) -> None:
        request = direct_request()
        agent = ProcessNode(identity(200, "42"), identity(100, "20"))
        snapshot = TopologySnapshot(
            (WindowObservation(request.windows[0], (agent,)),),
            TargetObservation(LOCAL, None, None, (agent,), None, ()),
        )
        response = Resolver().resolve(request, StaticCollector(snapshot))
        self.assertEqual(response["status"], "unresolved")

    def test_self_parent_cycle_cannot_prove_window_relation(self) -> None:
        request = direct_request()
        root = ProcessNode(identity(100, "20"), identity(100, "20"))
        agent = ProcessNode(identity(200, "42"), root.identity)
        snapshot = TopologySnapshot(
            (WindowObservation(request.windows[0], (root, agent)),),
            TargetObservation(LOCAL, None, None,
                              (ProcessNode(agent.identity, None),), None, ()),
        )
        response = Resolver().resolve(request, StaticCollector(snapshot))
        self.assertEqual(response["status"], "unresolved")
        self.assertEqual(response["candidates"], [])

    def test_two_node_cycle_cannot_prove_window_relation(self) -> None:
        request = direct_request()
        root = ProcessNode(identity(100, "20"), identity(200, "42"))
        agent = ProcessNode(identity(200, "42"), root.identity)
        snapshot = TopologySnapshot(
            (WindowObservation(request.windows[0], (root, agent)),),
            TargetObservation(LOCAL, None, None,
                              (ProcessNode(agent.identity, None),), None, ()),
        )
        response = Resolver().resolve(request, StaticCollector(snapshot))
        self.assertEqual(response["status"], "unresolved")
        self.assertEqual(response["candidates"], [])


if __name__ == "__main__":
    unittest.main()
