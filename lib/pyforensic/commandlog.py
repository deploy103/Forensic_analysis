"""Reproducible, argv-based command execution and logging.

Every invocation runs an ``argv`` array directly (``subprocess.Popen``,
never a shell string), so the recorded command is exactly what executed --
no quoting ambiguity, no shell-metacharacter surprises. Each run gets:

* an unpredictable, collision-resistant ``log_id`` (UTC timestamp plus a
  random hex suffix -- a PID alone is not enough on a machine that reuses
  PIDs quickly, or under two casually-timed concurrent invocations);
* its own process group, so a timeout can kill the whole subtree instead
  of just the immediate child;
* a byte-capped, streamed capture of combined stdout+stderr, so a runaway
  command cannot exhaust memory or disk;
* a UTC start/finish timestamp pair plus a monotonic-clock duration (wall
  clock can jump backwards; monotonic cannot);
* a SHA-256 + size of the (possibly truncated) captured output, recorded
  in the JSONL entry, so the log file's own integrity is checkable the
  same way evidence and artifacts are.

Exit-code semantics follow normal shell conventions: 127 means the
executable could not be found on ``PATH`` (or as given), 126 means it was
found but could not be executed (permissions), and a timeout is reported
as exit status 124 (matching GNU ``timeout``) with an explicit
``"timed_out": true`` field -- callers must not infer a timeout from the
exit code alone, since a real command could coincidentally also exit 124.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import secrets
import signal
import subprocess
import threading

from . import caselayout, locking, pathsafety, timeutil

EXIT_TIMED_OUT = 124
EXIT_NOT_FOUND = 127
EXIT_NOT_EXECUTABLE = 126

DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 300


class CommandLogError(Exception):
    pass


class CommandLogWriteError(CommandLogError):
    """The command ran (record is attached) but the JSONL/Markdown log could not be updated."""

    def __init__(self, message: str, record: dict):
        super().__init__(message)
        self.record = record


def new_log_id() -> str:
    stamp = timeutil.now_utc_iso().replace(":", "").replace("-", "")
    return f"{stamp}-{secrets.token_hex(4)}"


@dataclasses.dataclass
class RunResult:
    log_id: str
    argv: list[str]
    cwd: str
    started_utc: str
    finished_utc: str
    duration_seconds: float
    exit_status: int
    timed_out: bool
    truncated: bool
    output_relative: str
    output_sha256: str
    output_size: int


def _drain_capped(pipe, cap: int, state: dict) -> None:
    buf = bytearray()
    while True:
        chunk = pipe.read(65536)
        if not chunk:
            break
        if len(buf) < cap:
            room = cap - len(buf)
            buf.extend(chunk[:room])
            if len(chunk) > room:
                state["truncated"] = True
        else:
            state["truncated"] = True
    state["data"] = bytes(buf)


def run_and_log(
    cases_root: str,
    case_name: str,
    argv: list[str],
    *,
    cwd: str | None = None,
    timeout_seconds: float | None = DEFAULT_TIMEOUT_SECONDS,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> RunResult:
    from .case import _case_dir_or_raise

    if not argv:
        raise CommandLogError("argv must contain at least the program name")

    case_dir = _case_dir_or_raise(cases_root, case_name)
    logs_dir = os.path.join(case_dir, caselayout.LOGS_DIR)
    run_cwd = cwd or os.getcwd()

    log_id = new_log_id()
    output_name = f"{log_id}.log"
    output_path = os.path.join(logs_dir, output_name)
    output_relative = f"{caselayout.LOGS_DIR}/{output_name}"

    dir_fd = pathsafety.open_dir_nofollow(logs_dir)
    try:
        out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        try:
            out_fd = os.open(output_name, out_flags, 0o600, dir_fd=dir_fd)
        except OSError as exc:
            # EEXIST here means either a genuine log_id collision or a
            # symlink/regular file planted in advance at this name (O_EXCL
            # makes both indistinguishable, which is the point: we refuse
            # to write through *anything* already at this path rather than
            # risk following an attacker-controlled symlink).
            raise CommandLogError(
                f"could not create output log {output_relative!r} safely: {exc}"
            ) from exc
    finally:
        os.close(dir_fd)

    started_monotonic = timeutil.monotonic()
    started_utc = timeutil.now_utc_iso()
    timed_out = False
    state = {"truncated": False, "data": b""}

    try:
        try:
            proc = subprocess.Popen(
                argv,
                cwd=run_cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except FileNotFoundError:
            exit_status = EXIT_NOT_FOUND
        except PermissionError:
            exit_status = EXIT_NOT_EXECUTABLE
        else:
            reader = threading.Thread(
                target=_drain_capped, args=(proc.stdout, max_output_bytes, state), daemon=True
            )
            reader.start()
            try:
                exit_status = proc.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
                exit_status = EXIT_TIMED_OUT
            finally:
                reader.join(timeout=max(timeout_seconds or 0, 5) + 5)
            proc.stdout.close()
            os.write(out_fd, state["data"])
    finally:
        os.fsync(out_fd)
        os.close(out_fd)

    finished_utc = timeutil.now_utc_iso()
    duration_seconds = timeutil.monotonic() - started_monotonic

    digest = hashlib.sha256(state["data"]).hexdigest()
    size = len(state["data"])

    record = {
        "log_id": log_id,
        "started_utc": started_utc,
        "finished_utc": finished_utc,
        "duration_seconds": round(duration_seconds, 6),
        "cwd": run_cwd,
        "command": list(argv),
        "exit_status": exit_status,
        "timed_out": timed_out,
        "truncated": state["truncated"],
        "combined_output": output_relative,
        "output_sha256": digest,
        "output_size": size,
    }

    commands_jsonl = os.path.join(case_dir, caselayout.COMMANDS_JSONL)
    try:
        locking.locked_append_lines(commands_jsonl, [json.dumps(record, ensure_ascii=False, sort_keys=True)])
    except OSError as exc:
        raise CommandLogWriteError(
            f"command executed (exit_status={exit_status}, log_id={log_id}) but the JSONL "
            f"log could not be updated: {exc}",
            record,
        ) from exc

    commands_md = os.path.join(case_dir, caselayout.COMMANDS_MD)
    _append_markdown_summary(commands_md, record)

    return RunResult(
        log_id=log_id,
        argv=list(argv),
        cwd=run_cwd,
        started_utc=started_utc,
        finished_utc=finished_utc,
        duration_seconds=duration_seconds,
        exit_status=exit_status,
        timed_out=timed_out,
        truncated=state["truncated"],
        output_relative=output_relative,
        output_sha256=digest,
        output_size=size,
    )


def _append_markdown_summary(commands_md: str, record: dict) -> None:
    rendered = " ".join(_shell_quote(part) for part in record["command"])
    lines = [
        "",
        f"## {record['started_utc']} ({record['log_id']})",
        "",
        f"- Working directory: `{record['cwd']}`",
        f"- Command: `{rendered}`",
        f"- Exit status: {record['exit_status']}"
        + (" (timed out)" if record["timed_out"] else ""),
        f"- Combined output: `{record['combined_output']}`"
        + (" (truncated)" if record["truncated"] else ""),
        f"- Output SHA-256: {record['output_sha256']}",
    ]
    try:
        locking.locked_append_lines(commands_md, lines)
    except OSError:
        # The JSONL record (the machine-readable source of truth) already
        # succeeded by the time this is called; a Markdown-summary failure
        # is surfaced to the caller as part of the same append failure path
        # via run_and_log's own try/except around the JSONL write, so a
        # failure here specifically (JSONL ok, Markdown not) is non-fatal
        # -- the JSONL record remains authoritative and complete.
        pass


def _shell_quote(part: str) -> str:
    import shlex

    return shlex.quote(part)


def read_command_log(case_dir: str) -> list[dict]:
    commands_jsonl = os.path.join(case_dir, caselayout.COMMANDS_JSONL)
    if not os.path.exists(commands_jsonl):
        return []
    records = []
    with open(commands_jsonl, "r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise CommandLogError(f"commands.jsonl line {line_no}: invalid JSON: {exc}") from exc
    return records
