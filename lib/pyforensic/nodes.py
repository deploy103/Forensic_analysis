"""Execution-environment discovery: local resource state plus optional configured remote nodes.

This module inventories which execution environments are actually available
right now (this local machine, plus any operator-
configured SSH aliases such as a forensic server, a Kali box, or a Windows
host reachable via SSH) and their current resource/tool state, without ever
inventing connection details that were not supplied.

A remote node only exists here if it is listed in ``config/nodes.json`` (or
the file named by ``FORENSIC_SOLVER_NODES_CONFIG``) *and* actually answers
an SSH connectivity check -- exactly like the existing ``bin/remote-check``
already does for the single ``forensic`` alias, generalized to any number of
named aliases. Absent that file, :func:`discover_nodes` reports exactly one
node: ``local``,
always ``ONLINE``, since it is where the evidence file already lives and
where at least Python itself is guaranteed to run.
"""

from __future__ import annotations

import dataclasses
import json
import os
import platform
import shutil

from . import remote
from .triage.common import tool_available

NODES_CONFIG_ENV = "FORENSIC_SOLVER_NODES_CONFIG"
DEFAULT_NODES_CONFIG_NAME = "nodes.json"

LOCAL_ALIAS = "local"

RESOURCE_CLASSES = ("LIGHT", "MEDIUM", "HEAVY", "VERY_HEAVY")
NODE_STATUSES = ("ONLINE", "DEGRADED", "BUSY", "OFFLINE", "UNAVAILABLE")

_REMOTE_SSH_CHECK_TIMEOUT = 8
_REMOTE_TOOL_PROBE_TIMEOUT = 10


@dataclasses.dataclass
class NodeState:
    alias: str
    kind: str  # "local" | "server" | "windows" | "wsl" | "kali" | "generic"
    status: str  # one of NODE_STATUSES
    cpu_count: int | None = None
    load_avg_1m: float | None = None
    mem_total_mb: int | None = None
    mem_available_mb: int | None = None
    disk_free_mb: int | None = None
    os_name: str | None = None
    tools: dict = dataclasses.field(default_factory=dict)
    holds_evidence: bool = False
    detail: str = ""


def _read_local_meminfo() -> tuple[int | None, int | None]:
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            info = {}
            for line in handle:
                key, sep, rest = line.partition(":")
                if sep:
                    info[key.strip()] = rest.strip()
    except OSError:
        return None, None
    total = avail = None
    if "MemTotal" in info:
        total = int(info["MemTotal"].split()[0]) // 1024
    if "MemAvailable" in info:
        avail = int(info["MemAvailable"].split()[0]) // 1024
    return total, avail


def local_node(*, probe_tools: list[str] | None = None) -> NodeState:
    cpu_count = os.cpu_count()
    try:
        load1, _, _ = os.getloadavg()
    except (OSError, AttributeError):
        load1 = None
    mem_total, mem_avail = _read_local_meminfo()
    try:
        disk_free = shutil.disk_usage(".").free // (1024 * 1024)
    except OSError:
        disk_free = None
    tools = {t: tool_available(t) for t in (probe_tools or [])}
    return NodeState(
        alias=LOCAL_ALIAS, kind="local", status="ONLINE",
        cpu_count=cpu_count, load_avg_1m=load1,
        mem_total_mb=mem_total, mem_available_mb=mem_avail,
        disk_free_mb=disk_free, os_name=platform.platform(),
        tools=tools, holds_evidence=True,
        detail="local execution environment (this machine)",
    )


def _load_remote_config(project_root: str) -> list[dict]:
    path = os.environ.get(NODES_CONFIG_ENV) or os.path.join(project_root, "config", DEFAULT_NODES_CONFIG_NAME)
    if not os.path.isfile(path) or os.path.islink(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    return [entry for entry in data if isinstance(entry, dict) and entry.get("alias")]


def probe_remote_node(entry: dict, *, probe_tools: list[str] | None = None) -> NodeState:
    alias = entry["alias"]
    kind = entry.get("kind", "generic")
    try:
        proc = remote.run(remote.ssh_check_argv(alias=alias), timeout=_REMOTE_SSH_CHECK_TIMEOUT)
    except remote.RemoteError as exc:
        return NodeState(alias=alias, kind=kind, status="UNAVAILABLE",
                          detail=f"invalid alias configuration: {exc}")
    except Exception as exc:  # ssh binary missing, timeout, etc. -- never crash discovery
        return NodeState(alias=alias, kind=kind, status="UNAVAILABLE",
                          detail=f"connectivity check failed: {exc}")
    if proc.returncode != 0:
        return NodeState(alias=alias, kind=kind, status="UNAVAILABLE",
                          detail=f"not configured or unreachable (ssh exit {proc.returncode})")

    tools: dict[str, bool] = {}
    if probe_tools:
        probe_cmd = " && ".join(
            f"command -v {t} >/dev/null 2>&1 && echo {t}=1 || echo {t}=0" for t in probe_tools
        )
        try:
            tproc = remote.run(remote.ssh_argv(["sh", "-c", probe_cmd], alias=alias), timeout=_REMOTE_TOOL_PROBE_TIMEOUT)
            for line in tproc.stdout.decode("utf-8", "replace").splitlines():
                name, sep, val = line.partition("=")
                if sep:
                    tools[name.strip()] = val.strip() == "1"
        except Exception:
            pass  # connectivity already confirmed; tool probe is best-effort on top
    return NodeState(alias=alias, kind=kind, status="ONLINE", tools=tools, detail="reachable via SSH")


def discover_nodes(project_root: str, *, probe_tools: list[str] | None = None, include_remote: bool = True) -> list[NodeState]:
    nodes = [local_node(probe_tools=probe_tools)]
    if include_remote:
        for entry in _load_remote_config(project_root):
            nodes.append(probe_remote_node(entry, probe_tools=probe_tools))
    return nodes


def nodes_to_jsonable(nodes: list[NodeState]) -> list[dict]:
    return [dataclasses.asdict(n) for n in nodes]
