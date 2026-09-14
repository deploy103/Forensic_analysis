"""Tests for execution-environment discovery (nodes.py).

The real sandbox has no forensic-server/Windows/Kali SSH credentials
configured, so these tests exercise: (1) the default,
no-config state (local only), and (2) a synthetic ``nodes.json`` pointing at
a deliberately-unreachable alias, to prove a configured-but-unreachable node
is honestly reported ``UNAVAILABLE`` rather than fabricated as online.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

import unittest

from pyforensic import nodes  # noqa: E402


class TestLocalNode(unittest.TestCase):
    def test_local_node_is_always_online_and_holds_evidence(self):
        node = nodes.local_node()
        self.assertEqual(node.alias, nodes.LOCAL_ALIAS)
        self.assertEqual(node.status, "ONLINE")
        self.assertTrue(node.holds_evidence)

    def test_local_node_probes_requested_tools(self):
        node = nodes.local_node(probe_tools=["python3", "definitely-not-a-real-tool-xyz"])
        self.assertTrue(node.tools["python3"])
        self.assertFalse(node.tools["definitely-not-a-real-tool-xyz"])


class TestDiscoverNodesNoConfig(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_discover_nodes_reports_only_local_when_no_config_file_exists(self):
        discovered = nodes.discover_nodes(self.work, probe_tools=["python3"])
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0].alias, nodes.LOCAL_ALIAS)

    def test_nodes_config_env_override_missing_file_still_degrades_to_local_only(self):
        env_path = os.path.join(self.work, "does-not-exist.json")
        os.environ["FORENSIC_SOLVER_NODES_CONFIG"] = env_path
        try:
            discovered = nodes.discover_nodes(self.work)
        finally:
            del os.environ["FORENSIC_SOLVER_NODES_CONFIG"]
        self.assertEqual([n.alias for n in discovered], [nodes.LOCAL_ALIAS])


class TestDiscoverNodesWithUnreachableRemote(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)
        self.config_path = os.path.join(self.work, "nodes.json")
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump([{"alias": "definitely-unreachable-test-alias-xyz", "kind": "server"}], handle)
        os.environ["FORENSIC_SOLVER_NODES_CONFIG"] = self.config_path

    def tearDown(self):
        del os.environ["FORENSIC_SOLVER_NODES_CONFIG"]

    def test_unreachable_configured_node_reported_unavailable_not_fabricated(self):
        discovered = nodes.discover_nodes(self.work)
        aliases = {n.alias: n for n in discovered}
        self.assertIn(nodes.LOCAL_ALIAS, aliases)
        self.assertIn("definitely-unreachable-test-alias-xyz", aliases)
        remote = aliases["definitely-unreachable-test-alias-xyz"]
        self.assertEqual(remote.status, "UNAVAILABLE")

    def test_malformed_config_entries_without_alias_are_skipped(self):
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump([{"kind": "server"}, "not-even-a-dict", {"alias": "ok-alias"}], handle)
        discovered = nodes.discover_nodes(self.work)
        aliases = {n.alias for n in discovered}
        self.assertIn("ok-alias", aliases)
        self.assertEqual(len(discovered), 2)  # local + ok-alias only

    def test_include_remote_false_skips_config_entirely(self):
        discovered = nodes.discover_nodes(self.work, include_remote=False)
        self.assertEqual([n.alias for n in discovered], [nodes.LOCAL_ALIAS])


class TestNodesToJsonable(unittest.TestCase):
    def test_nodes_to_jsonable_round_trips_through_json(self):
        discovered = [nodes.local_node()]
        payload = json.dumps(nodes.nodes_to_jsonable(discovered))
        restored = json.loads(payload)
        self.assertEqual(restored[0]["alias"], nodes.LOCAL_ALIAS)


if __name__ == "__main__":
    unittest.main()
