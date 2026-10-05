"""Pure best-effort match tests; no Linux, tmux, or network access."""
from __future__ import annotations

import unittest
import json
import shlex
from pathlib import Path
from unittest.mock import patch
from agent_window_resolver.linux import LinuxCollector
from agent_window_resolver.collector import Deadline

from agent_window_resolver import (
    ObservationError,
    ProcessIdentity,
    ProcessNode,
    Resolver,
    StaticCollector,
    Target,
    TargetObservation,
    TmuxClient,
    TmuxLocation,
    TopologySnapshot,
    Window,
    WindowObservation,
)
from agent_window_resolver.model import Limits, Request


LOCAL = "osanwe"


def _identity(machine: str, pid: int, ticks: str) -> ProcessIdentity:
    return ProcessIdentity(machine, pid, ticks)


def _request(
    windows: tuple[Window, ...],
    *,
    name: str | None = None,
    tmux: TmuxLocation | None = None,
    machine: str = "gibson",
) -> Request:
    return Request(
        "best-effort", "match", None,
        Target(_identity(machine, 200, "42"), "agent-1", tmux, name),
        LOCAL, windows, None, Limits(),
    )


def _unreachable_target() -> TargetObservation:
    return TargetObservation(
        "gibson", None, None, (), None, (), "unreachable",
        (ObservationError("remote_unreachable", "transport", "offline", True),),
    )


class BestEffortTests(unittest.TestCase):
    def test_partial_collector_retains_stable_argv_hints_without_exact_proof(self) -> None:
        window = Window("window-a", "0xabc", 100, "20", title="mosh")
        request = _request((window,), tmux=TmuxLocation("ask", "0", "%1"))
        node = ProcessNode(_identity(LOCAL, 100, "20"), None,
                           ("mosh", "gibson", "tmux", "attach", "-t", "ask"))
        collector = LinuxCollector()
        with patch.object(collector, "_node", return_value=node), \
                patch.object(collector, "_children", side_effect=PermissionError("child")):
            observation = collector._window(request, window, Deadline(1000))
        self.assertEqual(observation.collection_state, "partial")
        self.assertEqual(observation.processes, (node,))
        response = Resolver().resolve(request, StaticCollector(TopologySnapshot(
            (observation,), _unreachable_target())))
        self.assertEqual(response["status"], "matched")
        self.assertEqual(response["candidates"][0]["match"]["score"], 90)
        self.assertNotIn("proof", response["candidates"][0])

    def test_yoohoo_single_argument_ssh_shell_command(self) -> None:
        window = Window("window-a", "0xabc", 100, "20", title="ssh")
        remote = "exec tmux attach-session -t " + shlex.quote("=ask (review)")
        node = ProcessNode(_identity(LOCAL, 100, "20"), None,
                           ("ghostty", "-e", "ssh", "--", "gibson",
                            "sh -lc " + shlex.quote(remote)))
        request = _request((window,), tmux=TmuxLocation("ask (review)", "0", "%1"))
        response = Resolver().resolve(request, StaticCollector(TopologySnapshot(
            (WindowObservation(window, (node,), "complete"),), _unreachable_target())))
        self.assertEqual(response["status"], "matched")
        self.assertEqual(response["candidates"][0]["match"]["score"], 90)

    def test_multiple_title_matches_are_ranked_and_not_ambiguous(self) -> None:
        windows = (
            Window("window-a", "0xabc", 100, "20", title="0_1_9 (patrol)"),
            Window("window-b", "0xdef", 101, "21", title="0_1_9 (patrol)"),
        )
        request = _request(windows, name="0_1_9 (patrol)")
        snapshot = TopologySnapshot(
            tuple(WindowObservation(window, (), "partial") for window in windows),
            _unreachable_target(),
        )
        response = Resolver().resolve(request, StaticCollector(snapshot))
        self.assertEqual(response["status"], "matched")
        self.assertEqual(len(response["candidates"]), 2)
        self.assertNotIn("proof", response["candidates"][0])

    def test_mosh_display_hint_matches_full_session_without_endpoint_proof(self) -> None:
        window = Window("window-a", "0xabc", 100, "20")
        root = ProcessNode(
            _identity(LOCAL, 100, "20"), None,
            ("mosh-client", "-# -- gibson tmux attach-session -t 0_1_9 (patrol) |", "1", "2"),
        )
        request = _request(
            (window,),
            tmux=TmuxLocation("0_1_9 (patrol)", "1", "%7"),
        )
        snapshot = TopologySnapshot(
            (WindowObservation(window, (root,), "complete"),),
            _unreachable_target(),
        )
        response = Resolver().resolve(request, StaticCollector(snapshot))
        self.assertEqual(response["status"], "matched")
        match = response["candidates"][0]["match"]
        self.assertEqual(match["confidence"], "high")
        self.assertTrue(any(reason["code"] == "mosh_hint_not_exact_proof"
                            for reason in match["uncertainty"]))

    def test_current_title_survives_historical_wrong_host(self) -> None:
        window = Window("window-a", "0xabc", 100, "20", title="0_1_9")
        wrong_transport = ProcessNode(
            _identity(LOCAL, 100, "20"), None,
            ("ssh", "wrong-host", "tmux", "attach-session", "-t", "0_1_9"),
        )
        request = _request(
            (window,),
            name="0_1_9",
            tmux=TmuxLocation("0_1_9", "1", "%7"),
        )
        snapshot = TopologySnapshot(
            (WindowObservation(window, (wrong_transport,), "complete"),),
            _unreachable_target(),
        )
        response = Resolver().resolve(request, StaticCollector(snapshot))
        self.assertEqual(response["status"], "matched")
        self.assertIn("stale_transport_hint", [r["code"] for r in
                      response["candidates"][0]["match"]["uncertainty"]])

    def test_host_only_and_name_prefixes_do_not_match(self) -> None:
        for title in ("mosh", "ask-other", "ask.dev"):
            with self.subTest(title=title):
                window = Window("window-a", "0xabc", 100, "20", title=title)
                node = ProcessNode(_identity(LOCAL, 100, "20"), None,
                                   ("ssh", "gibson"))
                request = _request((window,), name="ask")
                response = Resolver().resolve(request, StaticCollector(TopologySnapshot(
                    (WindowObservation(window, (node,), "complete"),),
                    _unreachable_target())))
                self.assertEqual(response["status"], "unresolved")

    def test_captured_mosh_command_forms_return_all_existing_windows(self) -> None:
        fixture = json.loads((Path(__file__).resolve().parents[1] /
                              "fixtures/mosh-window-hints.json").read_text())
        observations = []
        for index, record in enumerate(fixture["windows"]):
            window = Window(f"window-{index}", hex(100 + index), 100 + index,
                            "20", title=record["title"])
            node = ProcessNode(_identity(LOCAL, window.pid, "20"), None,
                               tuple(record["argv"]))
            observations.append(WindowObservation(window, (node,), "complete"))
        request = _request(tuple(o.window for o in observations),
                           tmux=TmuxLocation(fixture["session"], "0", "%100"))
        response = Resolver().resolve(request, StaticCollector(TopologySnapshot(
            tuple(observations), _unreachable_target())))
        self.assertEqual(response["status"], "matched")
        self.assertEqual(len(response["candidates"]), 3)
        self.assertTrue(all(c["match"]["score"] >= 90 for c in response["candidates"]))

    def test_unreadable_window_is_not_confirmed_absence(self) -> None:
        window = Window("window-a", "0xabc", 100, "20", title="mosh")
        response = Resolver().resolve(_request((window,), name="ask"),
            StaticCollector(TopologySnapshot(
                (WindowObservation(window, (), "partial"),), _unreachable_target())))
        self.assertEqual(response["status"], "unresolved")
        self.assertEqual([r["code"] for r in response["reasons"]],
                         ["local_collection_incomplete"])

    def test_local_tmux_client_pid_and_location_rank_window_without_exact_proof(self) -> None:
        window = Window("window-a", "0xabc", 100, "20", title="osanwe:mike")
        root = ProcessNode(_identity(LOCAL, 100, "20"), None, ("ghostty",))
        client = ProcessNode(_identity(LOCAL, 200, "30"), root.identity,
                             ("tmux",))
        request = _request(
            (window,), tmux=TmuxLocation("ask", "1", "%1"), machine=LOCAL,
        )
        target = TargetObservation(
            LOCAL, None, "/tmp/tmux-default", (), None,
            (TmuxClient("/dev/pts/1", client.identity,
                        "ask", "1", "%1"),),
            "partial",
            (ObservationError(
                "local_tmux_match_only", "tmux",
                "strict target ancestry was not collected",
            ),),
        )
        response = Resolver().resolve(request, StaticCollector(TopologySnapshot(
            (WindowObservation(window, (root, client)),), target,
        )))
        self.assertEqual(response["status"], "matched")
        match = response["candidates"][0]["match"]
        self.assertEqual(match["score"], 92)
        self.assertTrue(any(item["code"] == "tmux_client_window_subtree_hint"
                            for item in match["evidence"]))
        self.assertTrue(any(item["code"] == "tmux_client_not_exact_proof"
                            for item in match["uncertainty"]))
        self.assertNotIn("proof", response["candidates"][0])


if __name__ == "__main__":
    unittest.main()
