"""Adaptive execution-history store: per (tool, node) success/failure counters.

Persisted as an append-only JSONL file under a state directory so repeated
``solve`` runs -- and, once an operator configures real remote nodes -- a
distributed scheduler builds up genuine scheduling signal over time instead
of guessing cold on every invocation. Independent of any case (a case
directory can be a throwaway temp dir in tests; execution history is a
cross-case, cross-session log), so its location is controlled by its own
environment variable, mirroring the ``FORENSIC_SOLVER_CASES_DIR`` pattern
used for cases.
"""

from __future__ import annotations

import dataclasses
import json
import os

from . import locking, timeutil

STATE_DIR_ENV = "FORENSIC_SOLVER_STATE_DIR"
HISTORY_FILE = "execution-history.jsonl"


def state_dir() -> str:
    path = os.environ.get(STATE_DIR_ENV) or os.path.join(os.path.expanduser("~"), ".forensic_solver")
    os.makedirs(path, exist_ok=True)
    return path


def _history_path() -> str:
    return os.path.join(state_dir(), HISTORY_FILE)


@dataclasses.dataclass
class ExecutionRecord:
    tool: str
    node_alias: str
    outcome: str  # "success" | "failure"
    duration_seconds: float
    recorded_utc: str


def record_execution(tool: str, node_alias: str, outcome: str, duration_seconds: float) -> None:
    """Best-effort telemetry: never raises, never blocks the caller's real work."""
    record = ExecutionRecord(
        tool=tool, node_alias=node_alias, outcome=outcome,
        duration_seconds=round(duration_seconds, 6), recorded_utc=timeutil.now_utc_iso(),
    )
    line = json.dumps(dataclasses.asdict(record), ensure_ascii=False, sort_keys=True)
    try:
        locking.locked_append_lines(_history_path(), [line])
    except OSError:
        pass


def read_history() -> list[dict]:
    path = _history_path()
    if not os.path.isfile(path) or os.path.islink(path):
        return []
    records = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def success_rate(tool: str, node_alias: str) -> float:
    records = [r for r in read_history() if r.get("tool") == tool and r.get("node_alias") == node_alias]
    if not records:
        return 0.0
    successes = sum(1 for r in records if r.get("outcome") == "success")
    return successes / len(records)


def make_history_lookup():
    """Return a ``(tool, node_alias) -> float`` function, cached for one call site's lifetime."""
    cache: dict[tuple[str, str], float] = {}

    def lookup(tool: str, node_alias: str) -> float:
        key = (tool, node_alias)
        if key not in cache:
            cache[key] = success_rate(tool, node_alias)
        return cache[key]

    return lookup
