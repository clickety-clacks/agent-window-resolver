"""Tmux visibility and exact-prior semantics with injected live graphs."""
from __future__ import annotations

import unittest

from agent_window_resolver import (
    Limits,
    PriorCandidate,
    ProcessIdentity,
    ProcessNode,
    Request,
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


LOCAL = "osanwe"
SOCKET = SocketSelector("name", "agents")
LOCATION = TmuxLocation("ask", "1", "%1", SOCKET)
TARGET = Target(ProcessIdentity(LOCAL, 42, "99"), "agent", LOCATION)
WINDOW = Window("window-1", "0xabc", 100, "20")


def resolve_case(relation: str, *, current_pane: str,
                 operation: str = "resolve") -> dict:
    client_identity = ProcessIdentity(LOCAL, 200, "30")
    pane_identity = ProcessIdentity(LOCAL, 600, "10")
    root_identity = ProcessIdentity(LOCAL, 100, "20")
    window_nodes = (
        ProcessNode(root_identity, None),
        ProcessNode(client_identity, root_identity),
    )
    target_nodes = (
        ProcessNode(TARGET.identity, pane_identity),
        ProcessNode(pane_identity, None),
    )
    client = TmuxClient(
        "client0", client_identity, "ask", "1", current_pane,
        (ProcessNode(client_identity, None),),
    )
    prior = (
        PriorCandidate(WINDOW, TARGET, relation)
        if operation == "revalidate" else None
    )
    request = Request(
        "tmux-1", operation, relation, TARGET, LOCAL, (WINDOW,), prior, Limits()
    )
    snapshot = TopologySnapshot(
        (WindowObservation(WINDOW, window_nodes),),
        TargetObservation(
            LOCAL, SOCKET, "/tmp/tmux/socket", target_nodes,
            TmuxPane("ask", "1", "%1", pane_identity), (client,),
        ),
    )
    return Resolver().resolve(request, StaticCollector(snapshot))


class TmuxSemanticsTests(unittest.TestCase):
    def test_visible_exact_requires_current_active_pane(self) -> None:
        self.assertEqual(
            resolve_case("visible_exact", current_pane="%1")["status"],
            "matched",
        )
        self.assertEqual(
            resolve_case("visible_exact", current_pane="%2")["status"],
            "unresolved",
        )

    def test_linked_client_allows_different_active_pane(self) -> None:
        response = resolve_case("linked_client", current_pane="%2")
        self.assertEqual(response["status"], "matched")
        self.assertEqual(response["candidates"][0]["proof"]["relation"],
                         "linked_client")

    def test_revalidate_never_substitutes_lost_visible_relation(self) -> None:
        response = resolve_case(
            "visible_exact", current_pane="%2", operation="revalidate"
        )
        self.assertEqual(response["status"], "unresolved")
        self.assertEqual(response["candidates"], [])
        self.assertEqual(response["reasons"][0]["code"],
                         "prior_relation_no_longer_proven")


if __name__ == "__main__":
    unittest.main()
