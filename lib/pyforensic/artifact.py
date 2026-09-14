"""Generated-artifact recording and verification.

An "artifact" is a file produced by analysis (extracted archive member, dumped
region, decoded blob, ...) that the analyst wants to cite as evidence for a
flag candidate. Recording one binds its path and SHA-256 into
``notes/artifacts-manifest.jsonl`` so a later edit or swap of that file is
detectable, the same way :mod:`case` protects original evidence.

Containment is enforced the same way as everywhere else in this project:
by chaining ``dir_fd``-relative opens component-by-component from the case
root, not by comparing ``os.path.realpath()`` strings. A symlink placed
anywhere on the path -- including a symlinked ``workspace`` directory
itself -- is rejected rather than silently followed.

Design choice (documented because the requirements ask every non-obvious
trade-off to be written down): :func:`verify_artifacts` reports *every*
difference between the manifest and the actual `workspace/` inventory,
including files that exist on disk but were never recorded
(``DirectoryVerification.extra``). The pass/fail gate in :mod:`gate`
treats a mismatched hash or a missing recorded file as a hard failure, but
treats unrecorded scratch files as a warning, not a hard failure --
extraction tools routinely produce many incidental files, and forcing an
analyst to individually register every one of them would not improve
integrity, only add friction. What integrity *does* require is that any
artifact actually cited as the basis for a flag be recorded and unchanged,
which the hard-failure path enforces.
"""

from __future__ import annotations

import dataclasses
import json
import os

from . import caselayout, locking, manifest, pathsafety, timeutil
from .case import UnknownCase, _case_dir_or_raise  # noqa: F401 (re-exported for callers)


class ArtifactError(Exception):
    pass


class ArtifactRejected(ArtifactError):
    pass


def _relative_to_case(case_dir: str, artifact_path: str) -> list[str]:
    abs_case_dir = os.path.abspath(case_dir)
    abs_artifact = os.path.abspath(artifact_path)
    try:
        rel = os.path.relpath(abs_artifact, abs_case_dir)
    except ValueError as exc:  # different drive on some platforms; not on POSIX but be safe
        raise ArtifactRejected(f"artifact path is not comparable to case directory: {exc}") from exc
    try:
        components = pathsafety.split_relative_components(rel)
    except pathsafety.InvalidComponent as exc:
        raise ArtifactRejected(f"artifact path escapes the case directory: {artifact_path!r}") from exc
    if components[0] != caselayout.WORKSPACE_DIR:
        raise ArtifactRejected(
            f"artifact must be inside {caselayout.WORKSPACE_DIR}/: {artifact_path!r}"
        )
    return components


def _open_artifact_regular(case_dir: str, components: list[str]) -> int:
    *dirs, filename = components
    root_fd = pathsafety.open_dir_nofollow(case_dir)
    try:
        current = os.dup(root_fd)
        try:
            for part in dirs:
                nxt = pathsafety.open_dir_nofollow(part, dir_fd=current)
                os.close(current)
                current = nxt
            return pathsafety.open_regular_nofollow(filename, dir_fd=current)
        finally:
            os.close(current)
    finally:
        os.close(root_fd)


def record_artifact(
    cases_root: str,
    case_name: str,
    artifact_path: str,
    *,
    producing_log_id: str | None = None,
    parent_artifact: str | None = None,
) -> dict:
    case_dir = _case_dir_or_raise(cases_root, case_name)
    components = _relative_to_case(case_dir, artifact_path)
    workspace_relative = "/".join(components[1:])
    if not workspace_relative:
        raise ArtifactRejected(f"artifact path has no filename: {artifact_path!r}")

    manifest_path = os.path.join(case_dir, caselayout.ARTIFACT_MANIFEST)
    lock_path = os.path.join(case_dir, ".artifacts.lock")
    with locking.exclusive_lock(lock_path):
        existing = manifest.load_artifact_manifest(manifest_path)
        existing_paths = {record["path"] for record in existing}
        if workspace_relative in existing_paths:
            raise ArtifactRejected(f"artifact already recorded: {workspace_relative}")

        if producing_log_id is not None:
            commands_path = os.path.join(case_dir, caselayout.COMMANDS_JSONL)
            if not _log_id_exists(commands_path, producing_log_id):
                raise ArtifactRejected(f"producing_log_id not found in command log: {producing_log_id}")

        if parent_artifact is not None and parent_artifact not in existing_paths:
            raise ArtifactRejected(f"parent_artifact not previously recorded: {parent_artifact}")

        fd = _open_artifact_regular(case_dir, components)
        try:
            st = os.fstat(fd)
            if st.st_nlink != 1:
                raise ArtifactRejected(
                    f"artifact {workspace_relative!r} has {st.st_nlink} hard links; "
                    "refusing to record a file with links outside this case"
                )
            digest, size = pathsafety.fd_sha256(fd)
        finally:
            os.close(fd)

        record = {
            "path": workspace_relative,
            "sha256": digest,
            "size": size,
            "recorded_utc": timeutil.now_utc_iso(),
            "producing_log_id": producing_log_id,
            "parent_artifact": parent_artifact,
        }
        manifest.append_records(manifest_path, [json.dumps(record, ensure_ascii=False, sort_keys=True)])
    return record


def _log_id_exists(commands_jsonl_path: str, log_id: str) -> bool:
    if not os.path.exists(commands_jsonl_path):
        return False
    with open(commands_jsonl_path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("log_id") == log_id:
                return True
    return False


@dataclasses.dataclass
class ArtifactVerification:
    directory: manifest.DirectoryVerification

    @property
    def ok(self) -> bool:
        return not self.directory.mismatched and not self.directory.missing


def verify_artifacts(cases_root: str, case_name: str) -> ArtifactVerification:
    case_dir = _case_dir_or_raise(cases_root, case_name)
    workspace_dir = os.path.join(case_dir, caselayout.WORKSPACE_DIR)
    manifest_path = os.path.join(case_dir, caselayout.ARTIFACT_MANIFEST)
    records = manifest.load_artifact_manifest(manifest_path)
    result = manifest.verify_directory(records, workspace_dir)
    return ArtifactVerification(directory=result)
