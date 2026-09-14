"""Resource-aware node scheduler.

Uses the following scoring formula::

    score = tool_available + resource_fit + data_locality + execution_speed
            + historical_success - transfer_cost - current_load - resource_pressure

Every term is normalized to roughly ``[-1, 1]`` so the formula stays legible;
the resulting score is only ever meaningful as a *relative ranking between
nodes for one task*, never compared across different tasks. A node that is
``OFFLINE``/``UNAVAILABLE`` is never selected (score ``-inf``) regardless of
how well it would otherwise fit, since a node that cannot be reached cannot
run anything -- this is what makes the scheduler degrade safely to
local-only execution when no remote node is configured or reachable.
"""

from __future__ import annotations

import dataclasses

from .nodes import NodeState

RESOURCE_CLASS_MB = {"LIGHT": 256, "MEDIUM": 1024, "HEAVY": 4096, "VERY_HEAVY": 16384}


@dataclasses.dataclass
class TaskRequirement:
    required_tools: list[str] = dataclasses.field(default_factory=list)
    resource_class: str = "MEDIUM"
    evidence_size_mb: float = 0.0


@dataclasses.dataclass
class ScoredNode:
    node: NodeState
    score: float
    breakdown: dict


def _resource_fit(node: NodeState, requirement: TaskRequirement) -> float:
    need_mb = RESOURCE_CLASS_MB.get(requirement.resource_class, RESOURCE_CLASS_MB["MEDIUM"])
    if node.mem_available_mb is None:
        return 0.0
    if node.mem_available_mb <= 0:
        return -1.0
    ratio = node.mem_available_mb / need_mb
    return max(-1.0, min(1.0, ratio - 1.0))


def _current_load_penalty(node: NodeState) -> float:
    if node.load_avg_1m is None or not node.cpu_count:
        return 0.0
    normalized = node.load_avg_1m / node.cpu_count
    return max(0.0, min(1.0, normalized - 0.5))


def _resource_pressure_penalty(node: NodeState) -> float:
    if node.disk_free_mb is not None and node.disk_free_mb < 512:
        return 1.0
    if node.mem_available_mb is not None and node.mem_available_mb < 128:
        return 1.0
    return 0.0


def _tool_score(node: NodeState, requirement: TaskRequirement) -> float:
    if not requirement.required_tools:
        return 1.0
    have = sum(1 for t in requirement.required_tools if node.tools.get(t))
    return have / len(requirement.required_tools)


def _transfer_cost(node: NodeState, requirement: TaskRequirement) -> float:
    if node.holds_evidence:
        return 0.0
    return max(0.0, min(1.0, requirement.evidence_size_mb / 2048))


def _data_locality(node: NodeState) -> float:
    return 1.0 if node.holds_evidence else 0.0


def _historical_success(history_lookup, node: NodeState, requirement: TaskRequirement) -> float:
    if history_lookup is None:
        return 0.0
    tools = requirement.required_tools or ["*"]
    return max(history_lookup(tool, node.alias) for tool in tools)


def score_node(node: NodeState, requirement: TaskRequirement, *, history_lookup=None) -> ScoredNode:
    if node.status in ("OFFLINE", "UNAVAILABLE"):
        return ScoredNode(node=node, score=float("-inf"), breakdown={"status": node.status})
    breakdown = {
        "tool_available": _tool_score(node, requirement),
        "resource_fit": _resource_fit(node, requirement),
        "data_locality": _data_locality(node),
        "historical_success": _historical_success(history_lookup, node, requirement),
        "transfer_cost": -_transfer_cost(node, requirement),
        "current_load": -_current_load_penalty(node),
        "resource_pressure": -_resource_pressure_penalty(node),
    }
    return ScoredNode(node=node, score=sum(breakdown.values()), breakdown=breakdown)


def rank_nodes(nodes: list[NodeState], requirement: TaskRequirement, *, history_lookup=None) -> list[ScoredNode]:
    scored = [score_node(n, requirement, history_lookup=history_lookup) for n in nodes]
    scored.sort(key=lambda s: s.score, reverse=True)
    return scored
