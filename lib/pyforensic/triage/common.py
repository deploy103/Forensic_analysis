"""Shared contract for every triage wrapper.

Every triage module in this package returns a :class:`TriageResult` with
one of five outcomes, distinguished deliberately because "the tool ran
and found nothing interesting" and "the tool isn't installed" and "this
input isn't the format this wrapper expects" all require different next
actions from an analyst (or an orchestrating agent), and collapsing them
into a single boolean or a single exit code (as the previous
implementation did) throws that information away:

* ``full_success`` -- the wrapper's own parsing (and/or an external tool)
  completed and produced a structured result.
* ``partial_success`` -- some analysis completed but a component was
  skipped or failed (e.g. a native parser worked but an optional external
  tool that would add more detail is missing).
* ``tool_missing`` -- the wrapper requires an external tool that is not
  on ``PATH``, and has no native fallback for this input.
* ``input_mismatch`` -- the input does not look like the format this
  wrapper handles (e.g. ``fpcap`` given a PNG file).
* ``parser_failure`` -- the input looked like the right format but a
  parser raised while reading it (corrupt/truncated/adversarial input).
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess

from .. import errors, pathsafety

MAX_EXTRACT_TOTAL_BYTES = 500 * 1024 * 1024  # zip/tar-bomb guard for extraction
BOMB_RATIO_WARNING = 100  # uncompressed:compressed ratio considered suspicious

OUTCOME_EXIT_CODES = {
    "full_success": errors.TRIAGE_OK,
    "partial_success": errors.TRIAGE_PARTIAL_SUCCESS,
    "tool_missing": errors.TRIAGE_TOOL_MISSING,
    "input_mismatch": errors.TRIAGE_INPUT_MISMATCH,
    "parser_failure": errors.TRIAGE_PARSER_FAILURE,
}


@dataclasses.dataclass
class TriageResult:
    outcome: str
    tool: str
    summary: str
    details: dict = dataclasses.field(default_factory=dict)
    warnings: list[str] = dataclasses.field(default_factory=list)

    def exit_code(self) -> int:
        return OUTCOME_EXIT_CODES[self.outcome]

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def open_input_safely(path: str) -> tuple[int, os.stat_result]:
    """Open a triage input the same symlink/TOCTOU-safe way evidence is opened.

    Triage targets are usually evidence files or workspace artifacts that
    have already passed through :mod:`pyforensic.case` /
    :mod:`pyforensic.artifact`, but a wrapper can also be pointed at an
    arbitrary path directly, so the same defenses apply here too.
    """
    return pathsafety.open_source_for_copy(path)


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_tool(argv: list[str], *, timeout: float = 60) -> subprocess.CompletedProcess | None:
    """Run an external tool, returning ``None`` if it is not on PATH.

    Any other failure (bad exit status, timeout) is returned as a normal
    ``CompletedProcess``/raised ``TimeoutExpired`` for the caller to
    interpret, since those are meaningful outcomes, not "tool missing".
    """
    if not tool_available(argv[0]):
        return None
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)


def read_prefix(fd: int, n: int) -> bytes:
    return os.pread(fd, n, 0)


def safe_member_components(member_name: str) -> list[str] | None:
    """Validate an archive member name, returning ``None`` if it is unsafe.

    Rejects absolute paths, ``..`` traversal, and NUL/backslash smuggling
    via :func:`pathsafety.split_relative_components`. Archive formats
    (zip, tar) allow member names that a naive ``os.path.join`` would
    happily walk outside the extraction root ("zip-slip"/"tar-slip"), so
    every member must pass through this before any filesystem write.
    """
    try:
        return pathsafety.split_relative_components(member_name)
    except pathsafety.InvalidComponent:
        return None


def safe_extract_bytes(dest_root: str, components: list[str], data: bytes, *, mode: int = 0o644) -> None:
    """Write ``data`` to ``components`` beneath ``dest_root``, symlink-safe.

    Every intermediate directory is created (if missing) and re-opened
    with ``O_NOFOLLOW`` so a member that plants a symlink cannot redirect
    a later member's write outside ``dest_root``. The final file is
    created with ``O_CREAT | O_EXCL | O_NOFOLLOW`` so it can never
    overwrite an existing file (including one a malicious earlier member
    in the same archive planted) nor follow a symlink.
    """
    dir_fd = pathsafety.open_dir_nofollow(dest_root)
    try:
        for component in components[:-1]:
            try:
                os.mkdir(component, mode=0o755, dir_fd=dir_fd)
            except FileExistsError:
                pass
            next_fd = pathsafety.open_dir_nofollow(component, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        fd = os.open(components[-1], flags, mode, dir_fd=dir_fd)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)
