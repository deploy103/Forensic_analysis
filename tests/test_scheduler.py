"""Tests for the resource-aware node scheduler (scheduler.py)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402,F401

import unittest

from pyforensic.nodes import NodeState
from pyforensic.scheduler import TaskRequirement, rank_nodes, score_node


def _node(**overrides) -> NodeState:
    defaults = dict(
        alias="n", kind="generic", status="ONLINE", cpu_count=4, load_avg_1m=0.5,
        mem_total_mb=8192, mem_available_mb=4096, disk_free_mb=10240,
        os_name="test", tools={}, holds_evidence=False, detail="",
    )
    defaults.update(overrides)
    return NodeState(**defaults)


class TestOfflineNodesNeverSelected(unittest.TestCase):
    def test_offline_node_scores_negative_infinity(self):
        node = _node(status="OFFLINE")
        scored = score_node(node, TaskRequirement())
        self.assertEqual(scored.score, float("-inf"))

    def test_unavailable_node_scores_negative_infinity(self):
        node = _node(status="UNAVAILABLE")
        scored = score_node(node, TaskRequirement())
        self.assertEqual(scored.score, float("-inf"))

    def test_rank_nodes_puts_online_node_before_offline_node(self):
        online = _node(alias="online", status="ONLINE")
        offline = _node(alias="offline", status="OFFLINE")
        ranked = rank_nodes([offline, online], TaskRequirement())
        self.assertEqual(ranked[0].node.alias, "online")


class TestResourceFitAndTools(unittest.TestCase):
    def test_node_with_more_available_memory_scores_higher(self):
        low_mem = _node(alias="low", mem_available_mb=512)
        high_mem = _node(alias="high", mem_available_mb=8192)
        requirement = TaskRequirement(resource_class="MEDIUM")
        ranked = rank_nodes([low_mem, high_mem], requirement)
        self.assertEqual(ranked[0].node.alias, "high")

    def test_node_missing_required_tools_scores_lower_than_node_with_them(self):
        has_tools = _node(alias="has", tools={"file": True, "python3": True})
        missing_tools = _node(alias="missing", tools={"file": False, "python3": False})
        requirement = TaskRequirement(required_tools=["file", "python3"])
        ranked = rank_nodes([missing_tools, has_tools], requirement)
        self.assertEqual(ranked[0].node.alias, "has")

    def test_node_holding_evidence_avoids_transfer_cost_penalty(self):
        local = _node(alias="local", holds_evidence=True)
        remote = _node(alias="remote", holds_evidence=False)
        requirement = TaskRequirement(evidence_size_mb=1024)
        ranked = rank_nodes([remote, local], requirement)
        self.assertEqual(ranked[0].node.alias, "local")


class TestHistoricalSuccess(unittest.TestCase):
    def test_history_lookup_boosts_score_for_historically_successful_node(self):
        proven = _node(alias="proven")
        unproven = _node(alias="unproven")
        requirement = TaskRequirement(required_tools=["file"])
        lookup = lambda tool, alias: 1.0 if alias == "proven" else 0.0  # noqa: E731
        ranked = rank_nodes([unproven, proven], requirement, history_lookup=lookup)
        self.assertEqual(ranked[0].node.alias, "proven")

    def test_no_history_lookup_defaults_to_zero_contribution(self):
        node = _node()
        scored = score_node(node, TaskRequirement(required_tools=["file"]), history_lookup=None)
        self.assertEqual(scored.breakdown["historical_success"], 0.0)


if __name__ == "__main__":
    unittest.main()
