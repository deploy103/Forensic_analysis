"""Advisory file locking so concurrent CLI invocations do not interleave writes."""

from __future__ import annotations

import contextlib
import fcntl
import os

from typing import Iterable


@contextlib.contextmanager
def exclusive_lock(lock_path: str, *, create_mode: int = 0o600):
    """Hold an exclusive ``flock`` on ``lock_path`` for the duration of the block.

    The lock file is opened (created if missing) with ``O_NOFOLLOW`` so a
    symlink swapped in for the lock file cannot redirect the lock (and
    thus cannot be used to make two writers believe they both hold it).
    ``flock`` blocks until acquired -- callers that need bounded waiting
    should wrap this in their own timeout/alarm.
    """
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(lock_path, flags, create_mode)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield fd
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextlib.contextmanager
def try_exclusive_lock(lock_path: str, *, create_mode: int = 0o600):
    """Like :func:`exclusive_lock` but raises :class:`BlockingIOError` instead of waiting.

    Used for the single-winner case-creation race: exactly one concurrent
    ``new-case`` invocation should proceed past the lock while the rest
    fail fast with a clear "already being created" error.
    """
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(lock_path, flags, create_mode)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield fd
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def locked_append_lines(path: str, lines: Iterable[str], *, nlink_check: bool = True) -> None:
    """Append newline-terminated JSON/text lines to ``path`` under an exclusive lock.

    Shared by every append-only structured log in this project (evidence
    and artifact manifests, the command JSONL log). Opens with
    ``O_NOFOLLOW`` (rejects a symlinked destination) and ``O_APPEND``
    (concurrent, lock-serialized appenders cannot tear each other's
    writes), ``fsync``s before releasing the lock, and -- unless the
    caller is creating the file for the first time -- refuses to write to
    a file with more than one hard link, since a second link would let a
    file at a different, unnoticed path observe or extend "the log".
    """
    lock_path = path + ".lock"
    with exclusive_lock(lock_path):
        directory, filename = os.path.split(path)
        dir_fd = os.open(directory or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
            fd = os.open(filename, flags, 0o600, dir_fd=dir_fd)
        finally:
            os.close(dir_fd)
        try:
            if nlink_check:
                st = os.fstat(fd)
                if st.st_nlink != 1:
                    raise OSError(f"{path!r} has {st.st_nlink} hard links; refusing to append")
            payload = "".join(line + "\n" for line in lines).encode("utf-8")
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
