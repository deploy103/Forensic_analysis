"""Symlink-, traversal-, and TOCTOU-resistant filesystem primitives.

Every helper here uses ``openat``-style directory-fd walks (``os.open`` with
``dir_fd=``) instead of a single ``os.path.realpath()`` call. Resolving a
path once and trusting it is not a defense: an attacker (or a racing
process) can replace any path component between the check and the later
use. Holding an open directory file descriptor for each already-verified
component and opening the next component *relative to that fd* closes that
race, because the fd always refers to the inode that was verified, even if
the name is later unlinked or replaced.

Trust boundary: this module defends against a malicious *evidence file* or
a concurrent unprivileged process racing the case tree. It does not defend
against an attacker with the same OS-user privileges as the analyst running
these tools -- that attacker can simply edit the manifests directly. That
weaker boundary is intentional and is documented in ``docs/architecture.md``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import errno
import os
import stat
import time
from pathlib import PurePosixPath


class PathSafetyError(Exception):
    """Base class for all rejected-input conditions in this module."""


class InvalidComponent(PathSafetyError):
    """A path/relative-path string contains an unsafe component."""


class SymlinkRejected(PathSafetyError):
    """A path component (intermediate or final) is a symlink."""


class NotRegularFile(PathSafetyError):
    """The final component exists but is not a regular file."""


class EscapesRoot(PathSafetyError):
    """The resolved path is not contained by the expected root."""


class SourceChanged(PathSafetyError):
    """A source file's identity changed between check and use (TOCTOU)."""


class PermissionDenied(PathSafetyError):
    """The final component exists but the OS refused to open it (EACCES/EPERM)."""


def split_relative_components(relative: str) -> list[str]:
    """Validate and split a manifest-style relative path.

    Rejects absolute paths, empty segments, ``.``/``..``, NUL bytes, and
    trailing slashes. Returns the path split on ``/`` (manifests always use
    forward slashes regardless of host OS, so paths are portable and
    unambiguous to parse).
    """
    if not relative:
        raise InvalidComponent("empty path")
    if "\x00" in relative:
        raise InvalidComponent("path contains a NUL byte")
    if relative.startswith("/") or relative.startswith("\\"):
        raise InvalidComponent(f"absolute path rejected: {relative!r}")
    # PurePosixPath handles ".." / "." detection uniformly regardless of
    # separators an attacker might smuggle in from a crafted manifest line.
    parts = relative.split("/")
    components: list[str] = []
    for part in parts:
        if part in ("", ".", ".."):
            raise InvalidComponent(f"unsafe path component {part!r} in {relative!r}")
        if "\\" in part:
            raise InvalidComponent(f"backslash rejected in component {part!r}")
        components.append(part)
    if not components:
        raise InvalidComponent(f"path has no components: {relative!r}")
    return components


def validate_case_name(name: str) -> None:
    """Raise InvalidComponent unless ``name`` is a safe, single case dirname."""
    if not name or len(name) > 200:
        raise InvalidComponent("case name must be 1-200 characters")
    if name in (".", "..", ".template"):
        raise InvalidComponent(f"reserved case name: {name!r}")
    if not name[0].isalnum():
        raise InvalidComponent("case name must start with a letter or digit")
    allowed = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    )
    if any(ch not in allowed for ch in name):
        raise InvalidComponent(
            "case name may only contain letters, digits, dot, underscore, hyphen"
        )
    if "/" in name or "\\" in name or "\x00" in name:
        raise InvalidComponent("case name may not contain path separators")


@dataclasses.dataclass(frozen=True)
class Identity:
    """Minimal filesystem identity snapshot used for before/after TOCTOU checks."""

    dev: int
    ino: int
    size: int
    mtime_ns: int
    mode: int

    @classmethod
    def from_stat(cls, st: os.stat_result) -> "Identity":
        return cls(st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, stat.S_IFMT(st.st_mode))


def open_dir_nofollow(path: str, *, dir_fd: int | None = None) -> int:
    """Open ``path`` as a directory, rejecting it if it is itself a symlink."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        return os.open(path, flags, dir_fd=dir_fd)
    except OSError as exc:
        # ELOOP: kernel refused to follow a symlink because of O_NOFOLLOW.
        # ENOTDIR: combined with O_DIRECTORY, some kernels report a
        # symlink-to-directory (or a plain file) this way instead of
        # ELOOP. Either way the component cannot be safely used as a
        # directory hop, so both are treated as the same rejection.
        if exc.errno in (errno.ELOOP, errno.ENOTDIR):
            raise SymlinkRejected(
                f"directory component is a symlink or not a directory: {path!r}"
            ) from exc
        raise


@contextlib.contextmanager
def opened_dir_nofollow(path: str, *, dir_fd: int | None = None):
    fd = open_dir_nofollow(path, dir_fd=dir_fd)
    try:
        yield fd
    finally:
        os.close(fd)


def walk_dirs_nofollow(root_path: str, intermediate_components: list[str]) -> int:
    """Open ``root_path`` then each intermediate component via dir_fd chaining.

    Returns an open fd for the final intermediate directory (or the root
    itself if ``intermediate_components`` is empty). The caller is
    responsible for closing it. Every hop rejects symlinks, so a component
    swapped for a symlink after an earlier check but before a later one
    cannot redirect the walk outside the root.
    """
    current = open_dir_nofollow(root_path)
    try:
        for component in intermediate_components:
            next_fd = open_dir_nofollow(component, dir_fd=current)
            os.close(current)
            current = next_fd
    except BaseException:
        os.close(current)
        raise
    return current


def open_regular_nofollow(
    filename: str,
    *,
    dir_fd: int,
    flags: int = os.O_RDONLY,
) -> int:
    """Open ``filename`` beneath ``dir_fd``, rejecting non-regular files.

    Uses ``O_NOFOLLOW`` so a symlink final component is rejected outright,
    then confirms via ``fstat`` on the *opened fd* (not the path) that the
    result is a plain regular file -- this also rejects FIFOs, sockets,
    devices, and directories opened without ``O_DIRECTORY``.

    Always includes ``O_NONBLOCK``: opening a FIFO with a plain blocking
    ``O_RDONLY`` hangs the whole process until a writer shows up, which
    would turn a crafted "evidence" FIFO into a denial-of-service against
    the analyst. ``O_NONBLOCK`` has no effect on regular-file I/O, so this
    is free for the legitimate case and only changes behavior for the
    special files we reject anyway.
    """
    open_flags = flags | os.O_NOFOLLOW | os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        open_flags |= os.O_CLOEXEC
    try:
        fd = os.open(filename, open_flags, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SymlinkRejected(f"{filename!r} is a symlink") from exc
        if exc.errno in (errno.EACCES, errno.EPERM):
            raise PermissionDenied(f"{filename!r} could not be opened: {exc}") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            kind = stat.S_IFMT(st.st_mode)
            raise NotRegularFile(f"{filename!r} is not a regular file (mode={oct(kind)})")
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_source_for_copy(path: str) -> tuple[int, os.stat_result]:
    """Open an *evidence source* path defensively for reading.

    Rejects symlinks, FIFOs, sockets, devices, and directories. The parent
    directory is walked with :func:`walk_dirs_nofollow` so a symlinked
    parent directory cannot redirect the open either. Returns the open fd
    and its fstat result (the authoritative identity, since it comes from
    the fd, not a second stat-by-path call).
    """
    directory, filename = os.path.split(os.path.normpath(path))
    directory = directory or "."
    parts = [part for part in PurePosixPath(directory).parts if part not in ("", ".")]
    is_absolute = os.path.isabs(directory)
    root = "/" if is_absolute else "."
    if is_absolute:
        parts = list(parts)[1:] if parts and parts[0] == "/" else parts
    parent_fd = walk_dirs_nofollow(root, parts)
    try:
        fd = open_regular_nofollow(filename, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        st = os.fstat(fd)
        return fd, st
    except BaseException:
        os.close(fd)
        raise


def require_unchanged(before: Identity, st_after: os.stat_result, description: str) -> None:
    after = Identity.from_stat(st_after)
    if before != after:
        raise SourceChanged(
            f"{description} changed identity between check and use "
            f"(before={before!r} after={after!r})"
        )


def fd_sha256(fd: int, *, chunk_size: int = 4 * 1024 * 1024) -> tuple[str, int]:
    """Hash a whole file from an already-open fd without disturbing its offset."""
    import hashlib

    digest = hashlib.sha256()
    total = 0
    offset = 0
    while True:
        chunk = os.pread(fd, chunk_size, offset)
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
        offset += len(chunk)
    return digest.hexdigest(), total


_SEEK_DATA = getattr(os, "SEEK_DATA", 3)
_SEEK_HOLE = getattr(os, "SEEK_HOLE", 4)


def sparse_aware_copy(src_fd: int, dst_fd: int, total_size: int) -> None:
    """Copy ``total_size`` bytes from ``src_fd`` to ``dst_fd`` preserving holes.

    Uses ``SEEK_DATA``/``SEEK_HOLE`` to find real data extents in the
    source and only writes those extents into the (pre-truncated) sparse
    destination, so unallocated regions of a sparse evidence file are not
    materialized on copy. Falls back to a plain sequential copy if the
    filesystem does not support hole reporting (``ENXIO``/``EINVAL`` on the
    first probe) -- observed in practice on WSL2 ``drvfs`` (``/mnt/c``)
    mounts, which report the entire file as one data extent regardless of
    actual content, so this fallback path is what normally executes there.
    """
    os.ftruncate(dst_fd, total_size)
    if total_size == 0:
        return
    try:
        os.lseek(src_fd, 0, _SEEK_HOLE)
        supports_holes = True
    except OSError:
        supports_holes = False

    if not supports_holes:
        _plain_copy(src_fd, dst_fd, total_size)
        return

    offset = 0
    chunk_size = 4 * 1024 * 1024
    while offset < total_size:
        try:
            data_start = os.lseek(src_fd, offset, _SEEK_DATA)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                break  # no more data; remainder stays a hole
            raise
        try:
            hole_start = os.lseek(src_fd, data_start, _SEEK_HOLE)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                hole_start = total_size
            else:
                raise
        extent_end = min(hole_start, total_size)
        write_offset = data_start
        while write_offset < extent_end:
            length = min(chunk_size, extent_end - write_offset)
            block = os.pread(src_fd, length, write_offset)
            if not block:
                break
            os.pwrite(dst_fd, block, write_offset)
            write_offset += len(block)
        offset = extent_end if extent_end > offset else total_size


def _plain_copy(src_fd: int, dst_fd: int, total_size: int, *, chunk_size: int = 4 * 1024 * 1024) -> None:
    offset = 0
    while offset < total_size:
        block = os.pread(src_fd, chunk_size, offset)
        if not block:
            break
        os.pwrite(dst_fd, block, offset)
        offset += len(block)


def strip_all_write_bits(path: str) -> None:
    """Best-effort removal of every write bit.

    On POSIX filesystems this yields exact ``a-w`` semantics. On WSL2
    ``drvfs`` (``/mnt/c``) mounts, permission bits collapse to a binary
    writable(777)/read-only(555) state tied to the Windows read-only file
    attribute -- verified empirically: ``chmod 644`` reports back as
    ``777`` and removing the write bits reports back as ``555`` -- but the
    kernel does still reject writes and appends to the fd in that state.
    Callers must not rely on the *exact* resulting mode, only on the write
    rejection, and must treat SHA-256 verification as the authoritative
    integrity control rather than the permission bits.
    """
    st = os.stat(path)
    os.chmod(path, st.st_mode & ~0o222 & 0o7777)


def is_symlink_lstat(path: str) -> bool:
    try:
        return stat.S_ISLNK(os.lstat(path).st_mode)
    except OSError:
        return False


def monotonic_ns() -> int:
    return time.monotonic_ns()
