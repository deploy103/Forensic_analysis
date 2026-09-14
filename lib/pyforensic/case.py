"""Case creation and evidence intake: the transactional, symlink-safe core.

Design summary:

* ``create_case`` builds the *entire* new case in a temporary sibling
  directory under the cases root, then publishes it with a single
  ``os.rename``. If the destination name is taken by the time the rename
  runs, the rename itself fails atomically (directory-to-directory rename
  onto a non-empty/occupied name is rejected by the kernel) -- so under a
  concurrent-create race, exactly one caller's rename wins and the loser
  cleans up its own temp directory. No partial case is ever visible at the
  final path.
* ``add_evidence`` stages every new file under an unpredictable
  ``tempfile.mkstemp`` name inside ``evidence/`` first, verifies each copy,
  and only then "commits" by hard-linking every staged file to its real
  name (``os.link`` raises ``EEXIST`` instead of silently overwriting) and
  appending one batched manifest write. A per-case ``flock`` serializes
  concurrent ``add-evidence`` calls so two concurrent requests for the same
  filename cannot both believe they won.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import tempfile

from . import caselayout, locking, manifest, pathsafety, timeutil


class CaseError(Exception):
    pass


class InvalidCaseName(CaseError):
    pass


class CaseAlreadyExists(CaseError):
    pass


class UnknownCase(CaseError):
    pass


class EvidenceRejected(CaseError):
    pass


def resolve_cases_root(explicit: str | None, project_root: str) -> str:
    root = explicit or os.path.join(project_root, "cases")
    os.makedirs(root, exist_ok=True)
    if pathsafety.is_symlink_lstat(root):
        raise CaseError(f"cases root must not be a symlink: {root!r}")
    return os.path.realpath(root)


def case_dir_path(cases_root: str, name: str) -> str:
    try:
        pathsafety.validate_case_name(name)
    except pathsafety.InvalidComponent as exc:
        raise InvalidCaseName(str(exc)) from exc
    return os.path.join(cases_root, name)


def _reject_duplicate_basenames(sources: list[str]) -> dict[str, str]:
    by_name: dict[str, str] = {}
    for source in sources:
        base = os.path.basename(os.path.normpath(source))
        if not base or base in (".", ".."):
            raise EvidenceRejected(f"evidence source has no usable filename: {source!r}")
        if base in by_name and by_name[base] != source:
            raise EvidenceRejected(
                f"two evidence sources share the same filename {base!r}: "
                f"{by_name[base]!r} and {source!r}"
            )
        by_name[base] = source
    return by_name


@dataclasses.dataclass
class CopiedEvidence:
    basename: str
    sha256: str
    size: int


def _copy_one_evidence(source_path: str, dest_dir_path: str) -> CopiedEvidence:
    """Defensively copy one evidence source into an already-created destination directory.

    Returns the recorded fields for the manifest. Raises on any unsafe
    condition. The destination is created via ``tempfile.mkstemp`` (random,
    unpredictable name, ``O_EXCL`` under the hood) and the caller commits
    it to its final name once the whole batch has staged successfully.
    """
    src_fd, src_stat = pathsafety.open_source_for_copy(source_path)
    try:
        before = pathsafety.Identity.from_stat(src_stat)
        tmp_fd, tmp_path = tempfile.mkstemp(prefix=".partial-", dir=dest_dir_path)
        try:
            pathsafety.sparse_aware_copy(src_fd, tmp_fd, src_stat.st_size)
            os.fsync(tmp_fd)
            after_src = os.fstat(src_fd)
            pathsafety.require_unchanged(before, after_src, f"evidence source {source_path!r}")
            digest, size = pathsafety.fd_sha256(tmp_fd)
        finally:
            os.close(tmp_fd)
        pathsafety.strip_all_write_bits(tmp_path)
        basename = os.path.basename(os.path.normpath(source_path))
        return CopiedEvidence(basename=basename, sha256=digest, size=size), tmp_path
    finally:
        os.close(src_fd)


def create_case(cases_root: str, name: str, evidence_sources: list[str]) -> str:
    case_dir = case_dir_path(cases_root, name)
    if os.path.lexists(case_dir):
        raise CaseAlreadyExists(f"case path already exists: {case_dir}")

    _reject_duplicate_basenames(evidence_sources)
    for source in evidence_sources:
        if not os.path.isfile(source) or os.path.islink(source):
            # A cheap pre-flight check; the authoritative rejection happens
            # inside _copy_one_evidence via O_NOFOLLOW, this just fails
            # fast with a clearer message and avoids building a temp case
            # for an obviously-bad request.
            if os.path.islink(source):
                raise EvidenceRejected(f"evidence source is a symlink: {source}")
            raise EvidenceRejected(f"evidence source is not a regular file: {source}")

    tmp_root = tempfile.mkdtemp(prefix=f".new-{name}-", dir=cases_root)
    published = False
    try:
        for sub in caselayout.ALL_SUBDIRS:
            os.makedirs(os.path.join(tmp_root, *sub.split("/")), exist_ok=True)

        created_utc = timeutil.now_utc_iso()
        _write_initial_case_files(tmp_root, name, created_utc)

        evidence_dir = os.path.join(tmp_root, caselayout.EVIDENCE_DIR)
        manifest_lines: list[str] = []
        for source in evidence_sources:
            copied, tmp_path = _copy_one_evidence(source, evidence_dir)
            final_path = os.path.join(evidence_dir, copied.basename)
            os.link(tmp_path, final_path)
            os.unlink(tmp_path)
            record = {
                "path": copied.basename,
                "sha256": copied.sha256,
                "size": copied.size,
                "original_filename": copied.basename,
                "recorded_utc": timeutil.now_utc_iso(),
            }
            import json

            manifest_lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True))
        evidence_manifest_path = os.path.join(tmp_root, caselayout.EVIDENCE_MANIFEST)
        with open(evidence_manifest_path, "w", encoding="utf-8") as handle:
            for line in manifest_lines:
                handle.write(line + "\n")
        open(os.path.join(tmp_root, caselayout.ARTIFACT_MANIFEST), "w").close()

        try:
            os.rename(tmp_root, case_dir)
            published = True
        except OSError as exc:
            raise CaseAlreadyExists(
                f"case {name!r} was created concurrently by another process"
            ) from exc
        return case_dir
    finally:
        if not published:
            shutil.rmtree(tmp_root, ignore_errors=True)


def _write_initial_case_files(tmp_root: str, name: str, created_utc: str) -> None:
    import json

    meta = {
        "schema_version": caselayout.SCHEMA_VERSION,
        "case_name": name,
        "created_utc": created_utc,
    }
    with open(os.path.join(tmp_root, caselayout.CASE_META), "w", encoding="utf-8") as handle:
        json.dump(meta, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    with open(os.path.join(tmp_root, caselayout.CASE_NOTES), "w", encoding="utf-8") as handle:
        handle.write(
            f"# Case: {name}\n\n"
            f"- Created (UTC): {created_utc}\n"
            f"- Status: new\n\n"
            f"## Problem statement\n\nTODO: paste the authorized challenge description here.\n"
        )

    with open(os.path.join(tmp_root, caselayout.COMMANDS_MD), "w", encoding="utf-8") as handle:
        handle.write("# Command log\n\nAppend reproducible commands with `bin/log-command`.\n")
    open(os.path.join(tmp_root, caselayout.COMMANDS_JSONL), "w").close()
    open(os.path.join(tmp_root, caselayout.CANDIDATES_JSONL), "w").close()


def _case_dir_or_raise(cases_root: str, name: str) -> str:
    case_dir = case_dir_path(cases_root, name)
    if pathsafety.is_symlink_lstat(case_dir):
        raise UnknownCase(f"case path is a symlink, refusing to use it: {case_dir}")
    if not os.path.isdir(case_dir):
        raise UnknownCase(f"unknown case: {name}")
    if not os.path.isfile(os.path.join(case_dir, caselayout.CASE_META)):
        raise UnknownCase(f"case is missing {caselayout.CASE_META}; not a valid case: {name}")
    return case_dir


def add_evidence(cases_root: str, name: str, sources: list[str]) -> list[str]:
    case_dir = _case_dir_or_raise(cases_root, name)
    evidence_dir = os.path.join(case_dir, caselayout.EVIDENCE_DIR)
    manifest_path = os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST)

    _reject_duplicate_basenames(sources)

    added: list[str] = []
    lock_path = os.path.join(case_dir, ".evidence.lock")
    with locking.exclusive_lock(lock_path):
        existing_records = manifest.load_evidence_manifest(manifest_path)
        existing_paths = {record["path"] for record in existing_records}

        for source in sources:
            basename = os.path.basename(os.path.normpath(source))
            if basename in existing_paths:
                raise EvidenceRejected(f"evidence filename already exists in case: {basename}")
            if os.path.lexists(os.path.join(evidence_dir, basename)):
                raise EvidenceRejected(f"evidence filename already exists on disk: {basename}")

        staged: list[tuple[CopiedEvidence, str]] = []
        try:
            for source in sources:
                if os.path.islink(source):
                    raise EvidenceRejected(f"evidence source is a symlink: {source}")
                if not os.path.isfile(source):
                    raise EvidenceRejected(f"evidence source is not a regular file: {source}")
                copied, tmp_path = _copy_one_evidence(source, evidence_dir)
                staged.append((copied, tmp_path))

            new_lines = []
            import json

            for copied, tmp_path in staged:
                final_path = os.path.join(evidence_dir, copied.basename)
                os.link(tmp_path, final_path)
                os.unlink(tmp_path)
                added.append(copied.basename)
                record = {
                    "path": copied.basename,
                    "sha256": copied.sha256,
                    "size": copied.size,
                    "original_filename": copied.basename,
                    "recorded_utc": timeutil.now_utc_iso(),
                }
                new_lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True))
            manifest.append_records(manifest_path, new_lines)
        except BaseException:
            for copied, tmp_path in staged:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
                final_path = os.path.join(evidence_dir, copied.basename)
                if copied.basename in added and os.path.exists(final_path):
                    os.unlink(final_path)
            raise
    return added


@dataclasses.dataclass
class EvidenceVerification:
    directory: manifest.DirectoryVerification
    writable_paths: list[str]

    @property
    def ok(self) -> bool:
        return self.directory.ok and not self.writable_paths


def verify_evidence(cases_root: str, name: str) -> EvidenceVerification:
    case_dir = _case_dir_or_raise(cases_root, name)
    evidence_dir = os.path.join(case_dir, caselayout.EVIDENCE_DIR)
    manifest_path = os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST)
    records = manifest.load_evidence_manifest(manifest_path)
    result = manifest.verify_directory(records, evidence_dir)

    writable = []
    for record in records:
        full_path = os.path.join(evidence_dir, *record["path"].split("/"))
        if os.path.exists(full_path) and not pathsafety.is_symlink_lstat(full_path):
            st = os.lstat(full_path)
            if st.st_mode & 0o222:
                writable.append(record["path"])
    return EvidenceVerification(directory=result, writable_paths=writable)
