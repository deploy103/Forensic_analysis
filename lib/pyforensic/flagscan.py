"""Bounded, streaming flag-pattern scanner with hard timeouts on regex evaluation.

Two independent hazards drive this module's design:

1. A crafted evidence file could be gigabytes in size. Whole-file
   ``mmap`` + a single ``re.finditer`` call (the original implementation)
   maps the entire thing into memory at once. This scanner instead reads
   fixed-size chunks via ``os.pread`` and searches each chunk
   independently, with a byte overlap between consecutive chunks so a
   match spanning a chunk boundary is not missed. Matches that land in
   the overlap region are naturally found by both the chunk that precedes
   the boundary and the one that follows it, so results are de-duplicated
   by ``(pattern label, absolute offset)``.
2. Either a built-in or a user-supplied regex can be pathological
   (catastrophic backtracking) on adversarial input, causing the C-level
   ``re`` engine to hang. ``signal.alarm`` cannot interrupt that: CPython's
   ``re`` engine does not poll for pending signals while inside a single
   match attempt. The only reliable stop button is a *different process*
   that can be killed. So every file is scanned inside a forked child
   process with a wall-clock timeout; if that child is killed for running
   too long, the parent re-attempts the same file one pattern at a time
   (each in its own short-timeout child) to identify exactly which
   pattern is pathological. Patterns that complete are still reported;
   the offending pattern is recorded as a skipped/timed-out pattern for
   that file rather than silently discarding the whole file's results.
"""

from __future__ import annotations

import dataclasses
import json
import multiprocessing
import os
import re
import sys

from . import pathsafety

_SNIPPET_MAX_BYTES = 256

# Independent of the per-file/per-pattern execution timeout below: an
# absurdly long regex source (megabytes of alternation, say) can itself
# make *compilation* slow or memory-hungry before a single byte of the
# evidence file is ever scanned, and a timeout on execution does nothing
# to bound that. This caps the source string length itself.
_MAX_USER_PATTERN_LENGTH = 500

BUILTIN_PATTERNS: list[tuple[str, str]] = [
    ("flag_braces", r"(?i)\bflag\{[^{}\r\n]{1,200}\}"),
    ("generic_tagged_braces", r"\b[A-Za-z][A-Za-z0-9_]{2,24}\{[^{}\r\n]{1,200}\}"),
    ("htb_braces", r"(?i)\bHTB\{[^{}\r\n]{1,200}\}"),
    ("picoctf_braces", r"(?i)\bpicoCTF\{[^{}\r\n]{1,200}\}"),
    # A bare 2-letter tag like "DH" is one character short of
    # generic_tagged_braces's 3-character minimum (chosen to avoid
    # matching noise like "a{...}" or "to{...}"), so this competition's
    # own flag format needs its own explicit pattern to be found at all.
    ("dh_braces", r"(?i)\bDH\{[^{}\r\n]{1,200}\}"),
    ("ctf_braces", r"(?i)\bCTF\{[^{}\r\n]{1,200}\}"),
]


class FlagScanError(Exception):
    pass


class InvalidPattern(FlagScanError):
    pass


class InvalidScanPath(FlagScanError):
    pass


@dataclasses.dataclass(frozen=True)
class NamedPattern:
    label: str
    source: str


def compile_patterns(extra_patterns: list[str] | None) -> list[NamedPattern]:
    named = [NamedPattern(label, source) for label, source in BUILTIN_PATTERNS]
    for idx, source in enumerate(extra_patterns or []):
        if len(source) > _MAX_USER_PATTERN_LENGTH:
            raise InvalidPattern(
                f"user regex #{idx} is {len(source)} characters, exceeding the "
                f"{_MAX_USER_PATTERN_LENGTH}-character limit"
            )
        named.append(NamedPattern(f"user_{idx}", source))
    for np in named:
        try:
            re.compile(np.source.encode("utf-8"))
        except re.error as exc:
            raise InvalidPattern(f"invalid regex {np.source!r}: {exc}") from exc
    return named


@dataclasses.dataclass
class Match:
    path: str
    pattern: str
    offset: int
    length: int
    snippet: str


@dataclasses.dataclass
class SkippedPattern:
    path: str
    pattern: str
    reason: str


@dataclasses.dataclass
class ScanResult:
    matches: list[Match]
    skipped: list[SkippedPattern]
    files_scanned: int
    files_skipped_nonregular: int
    capped: bool


def _iter_regular_files(root: str) -> list[str]:
    """Recursively list regular files under ``root``, sorted, symlinks excluded.

    Uses the same ``dir_fd``-chained walk as the rest of the project so a
    symlinked subdirectory cannot redirect the scan outside ``root``.
    Returns paths relative to ``root`` using ``/`` separators.
    """
    results: list[str] = []
    root_fd = pathsafety.open_dir_nofollow(root)
    try:
        _walk(root_fd, "", results)
    finally:
        os.close(root_fd)
    results.sort()
    return results


def _walk(dir_fd: int, prefix: str, out: list[str]) -> None:
    import stat as statmod

    with os.scandir(dir_fd) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        st = os.lstat(name, dir_fd=dir_fd)
        rel = f"{prefix}{name}"
        if statmod.S_ISLNK(st.st_mode):
            continue
        if statmod.S_ISDIR(st.st_mode):
            sub_fd = pathsafety.open_dir_nofollow(name, dir_fd=dir_fd)
            try:
                _walk(sub_fd, rel + "/", out)
            finally:
                os.close(sub_fd)
        elif statmod.S_ISREG(st.st_mode):
            out.append(rel)


def _scan_fd_worker(fd: int, patterns: list[NamedPattern], chunk_size: int, overlap: int,
                     max_matches: int, queue) -> None:
    try:
        compiled = [(p.label, re.compile(p.source.encode("utf-8"))) for p in patterns]
        size = os.fstat(fd).st_size
        seen: set[tuple[str, int]] = set()
        results: list[tuple[str, int, bytes]] = []
        pos = 0
        while True:
            read_len = min(chunk_size, size - pos)
            if read_len <= 0:
                break
            chunk = os.pread(fd, read_len, pos)
            for label, regex in compiled:
                for m in regex.finditer(chunk):
                    abs_off = pos + m.start()
                    key = (label, abs_off)
                    if key in seen:
                        continue
                    seen.add(key)
                    full_match = m.group(0)
                    span = full_match[:_SNIPPET_MAX_BYTES]
                    results.append((label, abs_off, span, len(full_match)))
                    if len(results) >= max_matches:
                        queue.put(("ok", results))
                        return
            next_pos = pos + read_len
            if next_pos >= size:
                break
            pos = max(0, next_pos - overlap)
        queue.put(("ok", results))
    except BaseException as exc:  # noqa: BLE001 - report, do not crash the parent
        queue.put(("error", str(exc)))


_CTX = multiprocessing.get_context("fork")


def _run_fd_scan_with_timeout(fd: int, patterns: list[NamedPattern], *, chunk_size: int,
                               overlap: int, max_matches: int, timeout: float):
    queue = _CTX.Queue()
    proc = _CTX.Process(target=_scan_fd_worker, args=(fd, patterns, chunk_size, overlap, max_matches, queue))
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate()
        proc.join(2)
        if proc.is_alive():
            proc.kill()
            proc.join()
        return None
    try:
        status, payload = queue.get_nowait()
    except Exception:
        return []
    if status == "error":
        return []
    return payload


def scan_path(
    root: str,
    *,
    extra_patterns: list[str] | None = None,
    chunk_size: int = 1024 * 1024,
    overlap: int = 4096,
    max_matches_per_file: int = 1000,
    max_total_matches: int = 50000,
    per_file_timeout: float = 20.0,
    per_pattern_timeout: float = 5.0,
) -> ScanResult:
    if overlap >= chunk_size:
        raise FlagScanError("overlap must be smaller than chunk_size")
    if not os.path.exists(root):
        raise InvalidScanPath(f"path does not exist: {root}")

    patterns = compile_patterns(extra_patterns)

    if os.path.isdir(root) and not os.path.islink(root):
        relative_files = _iter_regular_files(root)
        base_dir = root
    elif os.path.isfile(root) and not os.path.islink(root):
        base_dir = os.path.dirname(os.path.abspath(root)) or "."
        relative_files = [os.path.basename(root)]
    else:
        raise InvalidScanPath(f"path is not a regular file or directory (or is a symlink): {root}")

    matches: list[Match] = []
    skipped: list[SkippedPattern] = []
    files_scanned = 0
    files_skipped_nonregular = 0
    capped = False

    dir_fd = pathsafety.open_dir_nofollow(base_dir)
    try:
        for rel_path in relative_files:
            if len(matches) >= max_total_matches:
                capped = True
                break
            try:
                fd = _open_relative(dir_fd, rel_path)
            except pathsafety.PathSafetyError:
                files_skipped_nonregular += 1
                continue
            try:
                remaining = max_total_matches - len(matches)
                per_file_cap = min(max_matches_per_file, remaining)
                result = _run_fd_scan_with_timeout(
                    fd, patterns, chunk_size=chunk_size, overlap=overlap,
                    max_matches=per_file_cap, timeout=per_file_timeout,
                )
                if result is None:
                    # Whole-file (all patterns) scan timed out; bisect to
                    # find which pattern is pathological, one at a time.
                    for np in patterns:
                        single = _run_fd_scan_with_timeout(
                            fd, [np], chunk_size=chunk_size, overlap=overlap,
                            max_matches=per_file_cap, timeout=per_pattern_timeout,
                        )
                        if single is None:
                            skipped.append(SkippedPattern(
                                path=rel_path, pattern=np.label,
                                reason=f"regex evaluation exceeded {per_pattern_timeout}s and was killed",
                            ))
                            continue
                        for label, abs_off, span, full_len in single:
                            matches.append(Match(
                                path=rel_path, pattern=label, offset=abs_off,
                                length=full_len, snippet=span.decode("utf-8", "replace"),
                            ))
                else:
                    for label, abs_off, span, full_len in result:
                        matches.append(Match(
                            path=rel_path, pattern=label, offset=abs_off,
                            length=full_len, snippet=span.decode("utf-8", "replace"),
                        ))
                files_scanned += 1
            finally:
                os.close(fd)
    finally:
        os.close(dir_fd)

    return ScanResult(
        matches=matches, skipped=skipped, files_scanned=files_scanned,
        files_skipped_nonregular=files_skipped_nonregular, capped=capped,
    )


def _open_relative(root_fd: int, relative_path: str) -> int:
    components = relative_path.split("/")
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


def matches_to_jsonl(result: ScanResult) -> str:
    lines = []
    for m in result.matches:
        lines.append(json.dumps(dataclasses.asdict(m), ensure_ascii=False, sort_keys=True))
    for s in result.skipped:
        record = dataclasses.asdict(s)
        record["skipped"] = True
        lines.append(json.dumps(record, ensure_ascii=False, sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")
