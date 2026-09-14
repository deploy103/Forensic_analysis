"""Structured JSONL manifests for evidence and generated artifacts.

Each record is one JSON object per line (JSON Lines / ``.jsonl``). JSON's
string escaping is what makes this format safe for filenames containing
spaces, tabs, newlines, quotes, Unicode, glob metacharacters, or a leading
dash -- none of those require special-casing because they are just
characters inside a JSON string, not shell or lexer tokens.

This is a project-integrity record, not a cryptographic signing system: an
attacker or careless operator with write access to the case tree can edit
these files directly, just like they could edit any other project file.
The property this format *does* give you is that accidental corruption,
truncation, or naive tampering (adding/removing a line, editing one field)
is detectable by comparing against the actual directory inventory and
recomputed hashes -- see :func:`verify_directory`.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
from typing import Iterable

from . import pathsafety

_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class ManifestError(Exception):
    """Raised for malformed, duplicate, or otherwise untrustworthy manifest content."""


EVIDENCE_FIELDS = {"path", "sha256", "size", "original_filename", "recorded_utc"}
ARTIFACT_FIELDS = {
    "path",
    "sha256",
    "size",
    "recorded_utc",
    "producing_log_id",
    "parent_artifact",
}


@dataclasses.dataclass(frozen=True)
class Record:
    path: str
    sha256: str
    size: int
    extra: dict

    def line(self) -> str:
        payload = {"path": self.path, "sha256": self.sha256, "size": self.size}
        payload.update(self.extra)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _validate_common(obj: dict, *, line_no: int, required: set[str]) -> None:
    if not isinstance(obj, dict):
        raise ManifestError(f"line {line_no}: record is not a JSON object")
    missing = required - obj.keys()
    if missing:
        raise ManifestError(f"line {line_no}: missing field(s) {sorted(missing)}")
    unknown = obj.keys() - required
    if unknown:
        raise ManifestError(f"line {line_no}: unknown field(s) {sorted(unknown)}")
    for key, value in obj.items():
        if value is None and key not in ("producing_log_id", "parent_artifact"):
            raise ManifestError(f"line {line_no}: field {key!r} is empty")
        if isinstance(value, str) and value.strip() == "" and key not in (
            "producing_log_id",
            "parent_artifact",
        ):
            raise ManifestError(f"line {line_no}: field {key!r} is blank")
    sha = obj["sha256"]
    if not isinstance(sha, str) or not _HEX64_RE.match(sha):
        raise ManifestError(f"line {line_no}: sha256 is not a 64-hex-digit string")
    size = obj["size"]
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ManifestError(f"line {line_no}: size must be a non-negative integer")
    path = obj["path"]
    if not isinstance(path, str):
        raise ManifestError(f"line {line_no}: path must be a string")
    try:
        pathsafety.split_relative_components(path)
    except pathsafety.InvalidComponent as exc:
        raise ManifestError(f"line {line_no}: unsafe manifest path {path!r}: {exc}") from exc
    for utc_field in ("recorded_utc",):
        if utc_field in obj and not _UTC_RE.match(obj[utc_field]):
            raise ManifestError(f"line {line_no}: {utc_field} is not UTC 'YYYY-MM-DDTHH:MM:SSZ'")


def parse_lines(text: str, *, required: set[str]) -> list[dict]:
    records: list[dict] = []
    seen_paths: dict[str, int] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        if raw_line.strip() == "":
            continue
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise ManifestError(f"line {line_no}: invalid JSON: {exc}") from exc
        _validate_common(obj, line_no=line_no, required=required)
        path = obj["path"]
        if path in seen_paths:
            raise ManifestError(
                f"line {line_no}: duplicate manifest path {path!r} "
                f"(first seen at line {seen_paths[path]})"
            )
        seen_paths[path] = line_no
        records.append(obj)
    return records


def _open_manifest_for_read(manifest_path: str) -> str:
    """Read manifest content while rejecting a symlinked or hardlinked manifest file.

    A hardlink count greater than one means some other directory entry
    shares this exact inode; because manifests are meant to be an
    append-only record owned by one case, a second link would let someone
    mutate "the manifest" by writing through a different, unnoticed path.
    """
    directory, filename = os.path.split(manifest_path)
    dir_fd = pathsafety.open_dir_nofollow(directory or ".")
    try:
        fd = pathsafety.open_regular_nofollow(filename, dir_fd=dir_fd)
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
        if st.st_nlink != 1:
            raise ManifestError(f"manifest {manifest_path!r} has {st.st_nlink} hard links; refusing to trust it")
        size = st.st_size
        data = b""
        offset = 0
        while offset < size:
            chunk = os.pread(fd, 4 * 1024 * 1024, offset)
            if not chunk:
                break
            data += chunk
            offset += len(chunk)
        return data.decode("utf-8")
    finally:
        os.close(fd)


def read_protected_file(path: str) -> str:
    """Public entry point: read a file while rejecting symlinks/hardlinks.

    Shared by the reviewer/final-gate modules to read
    ``candidates.jsonl``/``review.jsonl``/``final.json``/``reproduction.json``
    with the same anti-tamper guarantees manifests get.
    """
    return _open_manifest_for_read(path)


def load_evidence_manifest(manifest_path: str) -> list[dict]:
    if not os.path.exists(manifest_path):
        return []
    text = _open_manifest_for_read(manifest_path)
    return parse_lines(text, required=EVIDENCE_FIELDS)


def load_artifact_manifest(manifest_path: str) -> list[dict]:
    if not os.path.exists(manifest_path):
        return []
    text = _open_manifest_for_read(manifest_path)
    return parse_lines(text, required=ARTIFACT_FIELDS)


def append_records(manifest_path: str, lines: Iterable[str]) -> None:
    """Append pre-rendered JSON lines to a manifest, holding an exclusive lock.

    Opens with ``O_NOFOLLOW`` (refusing a symlinked manifest path) and
    ``O_APPEND`` (so concurrent, lock-protected appenders cannot clobber
    each other's bytes even if the lock were somehow bypassed), and
    ``fsync``s before releasing so a later reader never observes a
    torn write.
    """
    from . import locking

    try:
        locking.locked_append_lines(manifest_path, lines)
    except OSError as exc:
        raise ManifestError(str(exc)) from exc


@dataclasses.dataclass
class DirectoryVerification:
    ok: bool
    matched: list[str]
    mismatched: list[tuple[str, str]]  # (path, reason)
    missing: list[str]  # in manifest, not on disk
    extra: list[str]  # on disk, not in manifest


def verify_directory(records: list[dict], root_dir: str) -> DirectoryVerification:
    """Cross-check manifest records against the *actual* directory inventory.

    This does more than replay hashes for each recorded path: it also
    walks the real directory and demands the file sets match exactly, so
    an added, removed, or swapped-in file is caught even if every
    recorded hash still checks out for the files that are still present
    unmodified.
    """
    manifest_paths = {record["path"] for record in records}

    on_disk: set[str] = set()
    root_fd = pathsafety.open_dir_nofollow(root_dir)
    try:
        _collect_regular_files(root_fd, prefix="", out=on_disk)
    finally:
        os.close(root_fd)

    missing = sorted(manifest_paths - on_disk)
    extra = sorted(on_disk - manifest_paths)

    matched: list[str] = []
    mismatched: list[tuple[str, str]] = []
    root_fd = pathsafety.open_dir_nofollow(root_dir)
    try:
        for record in records:
            path = record["path"]
            if path in missing:
                continue
            try:
                fd = _open_relative_regular(root_fd, path)
            except pathsafety.PathSafetyError as exc:
                mismatched.append((path, str(exc)))
                continue
            try:
                st = os.fstat(fd)
                if st.st_nlink != 1:
                    mismatched.append((path, f"hard-linked (nlink={st.st_nlink})"))
                    continue
                digest, size = pathsafety.fd_sha256(fd)
                if size != record["size"]:
                    mismatched.append((path, f"size mismatch: manifest={record['size']} actual={size}"))
                elif digest != record["sha256"]:
                    mismatched.append((path, f"sha256 mismatch: manifest={record['sha256']} actual={digest}"))
                else:
                    matched.append(path)
            finally:
                os.close(fd)
    finally:
        os.close(root_fd)

    ok = not mismatched and not missing and not extra
    return DirectoryVerification(ok=ok, matched=matched, mismatched=mismatched, missing=missing, extra=extra)


def _collect_regular_files(dir_fd: int, *, prefix: str, out: set[str]) -> None:
    with os.scandir(dir_fd) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        st = os.lstat(name, dir_fd=dir_fd)
        rel = f"{prefix}{name}"
        import stat as statmod

        if statmod.S_ISLNK(st.st_mode):
            out.add(rel + "\x00symlink")
            continue
        if statmod.S_ISDIR(st.st_mode):
            sub_fd = pathsafety.open_dir_nofollow(name, dir_fd=dir_fd)
            try:
                _collect_regular_files(sub_fd, prefix=rel + "/", out=out)
            finally:
                os.close(sub_fd)
            continue
        if statmod.S_ISREG(st.st_mode):
            out.add(rel)
        else:
            out.add(rel + "\x00special")


def _open_relative_regular(root_fd: int, relative_path: str) -> int:
    components = pathsafety.split_relative_components(relative_path)
    *dirs, filename = components
    current = os.dup(root_fd)
    try:
        for part in dirs:
            nxt = pathsafety.open_dir_nofollow(part, dir_fd=current)
            os.close(current)
            current = nxt
        return pathsafety.open_regular_nofollow(filename, dir_fd=current)
    finally:
        os.close(current)
