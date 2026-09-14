"""Artifact transfer to/from a configured remote node, hash-verified and cached.

Wraps the existing SSH-alias-based push/pull argv builders in
:mod:`pyforensic.remote`; a remote node is only ever a name already
configured by the analyst in their own ``~/.ssh/config`` (see
``config/ssh_config.example``) -- this module never invents connection
details. The cache (keyed by destination node, destination path, and
SHA-256 of the local content) means re-running a solve/distribution step
never re-ships bytes that are already known to be present at that
destination.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os

from . import locking, remote, timeutil
from .history import state_dir

CACHE_FILE = "transfer-cache.jsonl"


def _cache_path() -> str:
    return os.path.join(state_dir(), CACHE_FILE)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _already_transferred(node_alias: str, sha256: str, remote_path: str) -> bool:
    path = _cache_path()
    if not os.path.isfile(path) or os.path.islink(path):
        return False
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("node_alias") == node_alias and rec.get("sha256") == sha256 and rec.get("remote_path") == remote_path:
                return True
    return False


def _record_transfer(node_alias: str, sha256: str, remote_path: str, direction: str) -> None:
    record = {
        "node_alias": node_alias, "sha256": sha256, "remote_path": remote_path,
        "direction": direction, "recorded_utc": timeutil.now_utc_iso(),
    }
    try:
        locking.locked_append_lines(_cache_path(), [json.dumps(record, ensure_ascii=False, sort_keys=True)])
    except OSError:
        pass


@dataclasses.dataclass
class TransferResult:
    ok: bool
    skipped_cached: bool
    sha256: str
    detail: str


def push_artifact(local_path: str, node_alias: str, remote_path: str) -> TransferResult:
    sha256 = sha256_file(local_path)
    if _already_transferred(node_alias, sha256, remote_path):
        return TransferResult(ok=True, skipped_cached=True, sha256=sha256,
                               detail="identical content already transferred to this node/path")
    try:
        argv = remote.scp_push_argv(local_path, remote_path, alias=node_alias)
        proc = remote.run(argv, timeout=300)
    except remote.RemoteError as exc:
        return TransferResult(ok=False, skipped_cached=False, sha256=sha256, detail=str(exc))
    ok = proc.returncode == 0
    if ok:
        _record_transfer(node_alias, sha256, remote_path, "push")
    return TransferResult(ok=ok, skipped_cached=False, sha256=sha256,
                           detail="pushed" if ok else proc.stdout.decode("utf-8", "replace"))


def pull_artifact(remote_path: str, local_path: str, node_alias: str) -> TransferResult:
    try:
        argv = remote.scp_pull_argv(remote_path, local_path, alias=node_alias)
        proc = remote.run(argv, timeout=300)
    except remote.RemoteError as exc:
        return TransferResult(ok=False, skipped_cached=False, sha256="", detail=str(exc))
    ok = proc.returncode == 0
    sha256 = sha256_file(local_path) if ok and os.path.isfile(local_path) else ""
    if ok:
        _record_transfer(node_alias, sha256, remote_path, "pull")
    return TransferResult(ok=ok, skipped_cached=False, sha256=sha256,
                           detail="pulled" if ok else proc.stdout.decode("utf-8", "replace"))
