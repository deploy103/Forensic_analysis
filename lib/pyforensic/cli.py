"""Single dispatch point for every ``bin/*`` command.

Each ``bin/<name>`` file is an identical trampoline that imports
:func:`main` and calls it with no arguments; :func:`main` looks at
``os.path.basename(sys.argv[0])`` to decide which command was invoked
(the same "busybox" pattern used by coreutils multi-call binaries), so
adding a new command only means adding one entry to :data:`COMMANDS`
plus one new file under ``bin/``.

Every command accepts an optional trailing ``--json`` flag to switch its
output from a human-readable summary to a machine-readable JSON object on
stdout, for use by orchestrating agents/scripts.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys

from . import artifact, case, caselayout, commandlog, errors, flagscan, gate, nodes, remote, report, solve, status
from .triage import archive, disk, document, dispatch, image, memory, pcap
from .triage import sqlite as triage_sqlite

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _cases_root() -> str:
    return case.resolve_cases_root(os.environ.get("FORENSIC_SOLVER_CASES_DIR"), PROJECT_ROOT)


def _pop_json_flag(argv: list[str]) -> tuple[list[str], bool]:
    if "--json" in argv:
        argv = [a for a in argv if a != "--json"]
        return argv, True
    return argv, False


def _to_jsonable(obj):
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {k: _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_jsonable(v) for v in obj]
    return obj


def _emit(obj, *, as_json: bool, human: str) -> None:
    if as_json:
        print(json.dumps(_to_jsonable(obj), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(human)


def _err(message: str) -> None:
    print(message, file=sys.stderr)


# --- case lifecycle -------------------------------------------------------

def cmd_new_case(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if not argv:
        _err("Usage: new-case <case-name> [evidence-file ...] [--json]")
        return errors.USAGE_ERROR
    name, sources = argv[0], argv[1:]
    try:
        case_dir = case.create_case(_cases_root(), name, sources)
    except case.CaseError as exc:
        _err(f"new-case failed: {exc}")
        return errors.GENERIC_FAILURE
    _emit({"case": name, "case_dir": case_dir, "evidence_count": len(sources)},
          as_json=as_json, human=f"Created case: {case_dir}")
    return errors.OK


def cmd_add_evidence(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if len(argv) < 2:
        _err("Usage: add-evidence <case-name> <evidence-file> [more...] [--json]")
        return errors.USAGE_ERROR
    name, sources = argv[0], argv[1:]
    try:
        added = case.add_evidence(_cases_root(), name, sources)
    except case.CaseError as exc:
        _err(f"add-evidence failed: {exc}")
        return errors.GENERIC_FAILURE
    _emit({"case": name, "added": added}, as_json=as_json, human=f"Added {len(added)} evidence file(s): {added}")
    return errors.OK


def cmd_verify_evidence(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if len(argv) != 1:
        _err("Usage: verify-evidence <case-name> [--json]")
        return errors.USAGE_ERROR
    try:
        result = case.verify_evidence(_cases_root(), argv[0])
    except case.CaseError as exc:
        _err(f"verify-evidence failed: {exc}")
        return errors.GENERIC_FAILURE
    human = "Evidence OK" if result.ok else f"Evidence FAILED: {result.directory.mismatched + [(p, 'missing') for p in result.directory.missing]}"
    _emit(result, as_json=as_json, human=human)
    return errors.OK if result.ok else errors.GENERIC_FAILURE


def cmd_record_artifact(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if len(argv) < 2:
        _err("Usage: record-artifact <case-name> <artifact-path> [--log-id ID] [--parent PATH] [--json]")
        return errors.USAGE_ERROR
    name, artifact_path = argv[0], argv[1]
    rest = argv[2:]
    log_id = parent = None
    i = 0
    while i < len(rest):
        if rest[i] == "--log-id" and i + 1 < len(rest):
            log_id = rest[i + 1]
            i += 2
        elif rest[i] == "--parent" and i + 1 < len(rest):
            parent = rest[i + 1]
            i += 2
        else:
            _err(f"Unrecognized argument: {rest[i]}")
            return errors.USAGE_ERROR
    try:
        record = artifact.record_artifact(_cases_root(), name, artifact_path, producing_log_id=log_id, parent_artifact=parent)
    except artifact.ArtifactError as exc:
        _err(f"record-artifact failed: {exc}")
        return errors.GENERIC_FAILURE
    _emit(record, as_json=as_json, human=f"Recorded artifact: {record['path']} ({record['sha256']})")
    return errors.OK


def cmd_verify_artifacts(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if len(argv) != 1:
        _err("Usage: verify-artifacts <case-name> [--json]")
        return errors.USAGE_ERROR
    try:
        result = artifact.verify_artifacts(_cases_root(), argv[0])
    except artifact.ArtifactError as exc:
        _err(f"verify-artifacts failed: {exc}")
        return errors.GENERIC_FAILURE
    human = "Artifacts OK" if result.ok else f"Artifacts FAILED: mismatched={result.directory.mismatched} missing={result.directory.missing}"
    _emit(result, as_json=as_json, human=human)
    return errors.OK if result.ok else errors.GENERIC_FAILURE


def cmd_list_cases(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    names = status.list_cases(_cases_root())
    _emit({"cases": names}, as_json=as_json, human="\n".join(names) if names else "(no cases)")
    return errors.OK


def cmd_case_status(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if len(argv) != 1:
        _err("Usage: case-status <case-name> [--json]")
        return errors.USAGE_ERROR
    try:
        result = status.case_status(_cases_root(), argv[0])
    except case.CaseError as exc:
        _err(f"case-status failed: {exc}")
        return errors.GENERIC_FAILURE
    human = (
        f"case={result.name} evidence_ok={result.evidence_integrity_ok} "
        f"artifacts_ok={result.artifact_integrity_ok} commands={result.command_count} "
        f"final={result.final_status}"
    )
    _emit(result, as_json=as_json, human=human)
    return errors.OK


def cmd_case_doctor(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if len(argv) != 1:
        _err("Usage: case-doctor <case-name> [--json]")
        return errors.USAGE_ERROR
    findings = status.case_doctor(_cases_root(), argv[0])
    human = "\n".join(f"[{f.severity}] {f.message}" for f in findings) if findings else "No findings."
    _emit({"findings": [dataclasses.asdict(f) for f in findings]}, as_json=as_json, human=human)
    return errors.GENERIC_FAILURE if any(f.severity == "error" for f in findings) else errors.OK


def cmd_case_report(argv: list[str]) -> int:
    if len(argv) != 1:
        _err("Usage: case-report <case-name>")
        return errors.USAGE_ERROR
    try:
        print(report.generate_report(_cases_root(), argv[0]))
    except case.CaseError as exc:
        _err(f"case-report failed: {exc}")
        return errors.GENERIC_FAILURE
    return errors.OK


def cmd_log_command(argv: list[str]) -> int:
    if len(argv) < 2:
        _err("Usage: log-command <case-name> [--] <command> [args...]")
        return errors.USAGE_ERROR
    name = argv[0]
    rest = argv[1:]
    if rest and rest[0] == "--":
        rest = rest[1:]
    if not rest:
        _err("Usage: log-command <case-name> [--] <command> [args...]")
        return errors.USAGE_ERROR
    try:
        result = commandlog.run_and_log(_cases_root(), name, rest)
    except commandlog.CommandLogError as exc:
        _err(f"log-command failed: {exc}")
        return errors.GENERIC_FAILURE
    output_path = os.path.join(_cases_root(), name, result.output_relative)
    with open(output_path, "rb") as handle:
        sys.stdout.buffer.write(handle.read())
    _err(f"[log-command] exit_status={result.exit_status} timed_out={result.timed_out} log_id={result.log_id}")
    return result.exit_status


def cmd_flag_scan(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if not argv:
        _err("Usage: flag-scan <path> [--pattern REGEX ...] [--json]")
        return errors.FLAG_SCAN_USAGE_ERROR
    target = argv[0]
    extra_patterns = []
    rest = argv[1:]
    i = 0
    while i < len(rest):
        if rest[i] == "--pattern" and i + 1 < len(rest):
            extra_patterns.append(rest[i + 1])
            i += 2
        else:
            _err(f"Unrecognized argument: {rest[i]}")
            return errors.FLAG_SCAN_USAGE_ERROR
    try:
        result = flagscan.scan_path(target, extra_patterns=extra_patterns or None)
    except flagscan.InvalidScanPath as exc:
        _err(str(exc))
        return errors.FLAG_SCAN_INVALID_PATH
    except flagscan.InvalidPattern as exc:
        _err(str(exc))
        return errors.FLAG_SCAN_USAGE_ERROR
    if as_json:
        print(flagscan.matches_to_jsonl(result))
    else:
        for m in result.matches:
            print(f"{m.path}:{m.offset}\t{m.pattern}\t{m.snippet!r}")
        for s in result.skipped:
            _err(f"[skipped] {s.path}: pattern {s.pattern!r} timed out ({s.reason})")
    return errors.FLAG_SCAN_MATCHES_FOUND if result.matches else errors.FLAG_SCAN_NO_MATCHES


# --- result gate ------------------------------------------------------

def cmd_add_candidate(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    required = ["--flag", "--evidence", "--locator", "--transformation", "--log-id"]
    opts = _parse_kv_flags(argv[1:], {"--flag": "flag", "--evidence": "evidence_path", "--locator": "locator",
                                       "--transformation": "transformation", "--log-id": "log_id",
                                       "--artifact": "artifact_path"})
    if not argv or opts is None or any(k not in opts for k in ("flag", "evidence_path", "locator", "transformation", "log_id")):
        _err("Usage: add-candidate <case-name> --flag F --evidence PATH --locator JSON --transformation T --log-id ID [--artifact PATH] [--json]")
        return errors.USAGE_ERROR
    try:
        opts["locator"] = json.loads(opts["locator"])
    except json.JSONDecodeError as exc:
        _err(f"--locator must be a JSON object: {exc}")
        return errors.USAGE_ERROR
    if not isinstance(opts["locator"], dict):
        _err("--locator must decode to a JSON object")
        return errors.USAGE_ERROR
    try:
        record = gate.add_candidate(_cases_root(), argv[0], **opts)
    except gate.GateError as exc:
        _err(f"add-candidate failed: {exc}")
        return errors.GENERIC_FAILURE
    _emit(record, as_json=as_json, human=f"Added candidate {record['candidate_id']}")
    return errors.OK


def cmd_add_review(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    opts = _parse_kv_flags(argv[1:], {"--reviewer": "reviewer", "--verdict": "verdict", "--concerns": "concerns"})
    candidate_ids = _extract_repeated(argv[1:], "--candidate")
    if not argv or opts is None or "reviewer" not in opts or "verdict" not in opts or not candidate_ids:
        _err("Usage: add-review <case-name> --reviewer NAME --verdict V --candidate ID [--candidate ID ...] [--concerns TEXT] [--json]")
        return errors.USAGE_ERROR
    opts["candidate_ids"] = candidate_ids
    try:
        record = gate.add_review(_cases_root(), argv[0], **opts)
    except gate.GateError as exc:
        _err(f"add-review failed: {exc}")
        return errors.GENERIC_FAILURE
    _emit(record, as_json=as_json, human="Added review")
    return errors.OK


def cmd_set_reproduction(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    opts = _parse_kv_flags(argv[1:], {"--candidate": "candidate_id", "--log-id": "log_id", "--summary": "commands_summary"})
    if not argv or opts is None or any(k not in opts for k in ("candidate_id", "log_id", "commands_summary")):
        _err("Usage: set-reproduction <case-name> --candidate ID --log-id ID --summary TEXT [--json]")
        return errors.USAGE_ERROR
    try:
        record = gate.set_reproduction(_cases_root(), argv[0], **opts)
    except gate.GateError as exc:
        _err(f"set-reproduction failed: {exc}")
        return errors.GENERIC_FAILURE
    _emit(record, as_json=as_json, human="Reproduction recorded")
    return errors.OK


def cmd_set_final(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    opts = _parse_kv_flags(argv[1:], {"--candidate": "candidate_id"})
    if not argv or opts is None or "candidate_id" not in opts:
        _err("Usage: set-final <case-name> --candidate ID [--json]")
        return errors.USAGE_ERROR
    try:
        record = gate.set_final(_cases_root(), argv[0], **opts)
    except gate.GateError as exc:
        _err(f"set-final failed: {exc}")
        return errors.GENERIC_FAILURE
    _emit(record, as_json=as_json, human=f"Final result set: flag={record['flag']}")
    return errors.OK


def cmd_result_check(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if len(argv) != 1:
        _err("Usage: result-check <case-name> [--json]")
        return errors.GATE_USAGE_ERROR
    try:
        result = gate.run_gate(_cases_root(), argv[0])
    except case.CaseError as exc:
        _err(f"result-check failed: {exc}")
        return errors.GATE_USAGE_ERROR
    human = "GATE: PASS" if result.ok else "GATE: FAIL\n" + "\n".join(f"- {r}" for r in result.reasons)
    _emit(result, as_json=as_json, human=human)
    return errors.GATE_PASS if result.ok else errors.GATE_FAIL


def _parse_kv_flags(argv: list[str], mapping: dict[str, str]) -> dict | None:
    result: dict = {}
    i = 0
    while i < len(argv):
        flag = argv[i]
        if flag == "--candidate" and "--candidate" not in mapping:
            i += 2
            continue  # handled separately by _extract_repeated for multi-value flags
        if flag in mapping:
            if i + 1 >= len(argv):
                return None
            result[mapping[flag]] = argv[i + 1]
            i += 2
        else:
            return None
    return result


def _extract_repeated(argv: list[str], flag: str) -> list[str]:
    values = []
    i = 0
    while i < len(argv):
        if argv[i] == flag and i + 1 < len(argv):
            values.append(argv[i + 1])
            i += 2
        else:
            i += 1
    return values


# --- triage -------------------------------------------------------------

_TRIAGE_MODULES = {
    "ftriage": None,  # dispatch, handled specially
    "farchive": archive,
    "fpcap": pcap,
    "fsqlite": triage_sqlite,
    "fstego": image,
    "fmemory": memory,
    "fdisk": disk,
    "fdocument": document,
}


def _run_triage(command_name: str, argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    if len(argv) != 1:
        _err(f"Usage: {command_name} <file> [--json]")
        return errors.TRIAGE_INPUT_MISMATCH
    target = argv[0]
    if not os.path.isfile(target) or os.path.islink(target):
        _err(f"Not a regular file: {target}")
        return errors.TRIAGE_INPUT_MISMATCH
    module = _TRIAGE_MODULES[command_name]
    try:
        result = dispatch.detect_and_inspect(target) if module is None else module.inspect(target)
    except Exception as exc:  # a triage wrapper must never crash the CLI on adversarial input
        _err(f"{command_name} failed unexpectedly: {exc}")
        return errors.TRIAGE_PARSER_FAILURE
    human = f"[{result.outcome}] {result.summary}" + ("\n" + "\n".join(f"  ! {w}" for w in result.warnings) if result.warnings else "")
    _emit(result, as_json=as_json, human=human)
    return result.exit_code()


def cmd_triage_case(argv: list[str]) -> int:
    """Verify a case's integrity, then run generic triage over every evidence file."""
    argv, as_json = _pop_json_flag(argv)
    if len(argv) != 1:
        _err("Usage: triage-case <case-name> [--json]")
        return errors.USAGE_ERROR
    name = argv[0]
    try:
        ev = case.verify_evidence(_cases_root(), name)
    except case.CaseError as exc:
        _err(f"triage-case failed: {exc}")
        return errors.GENERIC_FAILURE
    if not ev.ok:
        _err("triage-case aborted: evidence integrity check failed, run verify-evidence for details")
        return errors.GENERIC_FAILURE
    case_dir = os.path.join(_cases_root(), name)
    evidence_dir = os.path.join(case_dir, caselayout.EVIDENCE_DIR)
    results = {}
    worst = errors.TRIAGE_OK
    for entry in sorted(os.listdir(evidence_dir)):
        full = os.path.join(evidence_dir, entry)
        if not os.path.isfile(full) or os.path.islink(full):
            continue
        result = dispatch.detect_and_inspect(full)
        results[entry] = _to_jsonable(result)
        worst = max(worst, result.exit_code()) if result.exit_code() != errors.TRIAGE_OK else worst
    _emit({"case": name, "triage": results}, as_json=as_json,
          human="\n".join(f"{name}: [{r['outcome']}] {r['summary']}" for name, r in results.items()))
    return errors.OK


# --- environment / remote -------------------------------------------------

def cmd_tool_inventory(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    toolset_path = os.path.join(PROJECT_ROOT, "config", "toolset.txt")
    tools = []
    if os.path.isfile(toolset_path):
        with open(toolset_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    tools.append(line)
    from .triage.common import tool_available
    found = {t: tool_available(t) for t in tools}
    human = "\n".join(f"{'OK  ' if ok else 'MISS'}  {t}" for t, ok in found.items())
    _emit({"tools": found}, as_json=as_json, human=human)
    return errors.OK


def cmd_remote_check(argv: list[str]) -> int:
    argv, as_json = _pop_json_flag(argv)
    alias = argv[0] if argv else remote.DEFAULT_ALIAS
    try:
        proc = remote.run(remote.ssh_check_argv(alias=alias), timeout=15)
    except remote.RemoteError as exc:
        _err(str(exc))
        return errors.GENERIC_FAILURE
    except Exception as exc:
        _err(f"remote-check failed: {exc}")
        return errors.GENERIC_FAILURE
    ok = proc.returncode == 0
    _emit({"alias": alias, "returncode": proc.returncode, "output": proc.stdout.decode("utf-8", "replace")},
          as_json=as_json, human=("Connected" if ok else f"Failed (exit {proc.returncode})"))
    return errors.OK if ok else errors.GENERIC_FAILURE


def cmd_remote_exec(argv: list[str]) -> int:
    dry_run = bool(argv) and argv[0] == "--dry-run"
    if dry_run:
        argv = argv[1:]
    if not argv:
        _err("Usage: remote-exec [--dry-run] <command> [args...]")
        return errors.USAGE_ERROR
    try:
        if dry_run:
            print(remote.render_remote_command(argv))
            return errors.OK
        proc = remote.run(remote.ssh_argv(argv), timeout=120)
    except remote.RemoteError as exc:
        _err(str(exc))
        return errors.GENERIC_FAILURE
    except Exception as exc:
        _err(f"remote-exec failed: {exc}")
        return errors.GENERIC_FAILURE
    sys.stdout.buffer.write(proc.stdout)
    return proc.returncode


def cmd_remote_copy(argv: list[str]) -> int:
    dry_run = bool(argv) and argv[0] == "--dry-run"
    if dry_run:
        argv = argv[1:]
    if len(argv) != 3 or argv[0] not in ("push", "pull"):
        _err("Usage: remote-copy [--dry-run] <push|pull> <local-path> <remote-path>")
        return errors.USAGE_ERROR
    direction, local_path, remote_path = argv
    try:
        if direction == "push":
            built_argv = remote.scp_push_argv(local_path, remote_path)
        else:
            built_argv = remote.scp_pull_argv(remote_path, local_path)
        if dry_run:
            print(remote.render_remote_command(built_argv))
            return errors.OK
        proc = remote.run(built_argv, timeout=300)
    except remote.RemoteError as exc:
        _err(str(exc))
        return errors.GENERIC_FAILURE
    except Exception as exc:
        _err(f"remote-copy failed: {exc}")
        return errors.GENERIC_FAILURE
    sys.stdout.buffer.write(proc.stdout)
    return proc.returncode


def cmd_solve(argv: list[str]) -> int:
    """The single competition-facing command: analyze one file end to end, no other command needed."""
    argv, as_json = _pop_json_flag(argv)
    use_latest = "--latest" in argv
    argv = [a for a in argv if a != "--latest"]
    if len(argv) > 1 or (argv and use_latest):
        _err("Usage: solve [FILE | --latest] [--json]")
        return errors.SOLVE_USAGE_ERROR
    file_arg = argv[0] if argv else None
    try:
        result = solve.run_solve(_cases_root(), PROJECT_ROOT, source_path=file_arg, use_latest=use_latest)
    except solve.NoCandidateFile as exc:
        _err(f"solve: {exc}")
        return errors.SOLVE_NO_CANDIDATE_FILE
    except solve.SolveError as exc:
        _err(f"solve failed: {exc}")
        return errors.GENERIC_FAILURE
    if as_json:
        print(json.dumps(_to_jsonable(result), ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(solve.render_human_report(result))
    return errors.SOLVE_FLAG_FOUND if result.best is not None else errors.SOLVE_NO_FLAG_FOUND


def cmd_nodes_status(argv: list[str]) -> int:
    """Debugging/internal: show what execution environments solve currently sees."""
    argv, as_json = _pop_json_flag(argv)
    if argv:
        _err("Usage: nodes-status [--json]")
        return errors.USAGE_ERROR
    discovered = nodes.discover_nodes(PROJECT_ROOT, probe_tools=["file", "python3"])
    human = "\n".join(f"{n.alias} [{n.kind}] status={n.status} {n.detail}" for n in discovered)
    _emit({"nodes": nodes.nodes_to_jsonable(discovered)}, as_json=as_json, human=human)
    return errors.OK


COMMANDS = {
    "new-case": cmd_new_case,
    "add-evidence": cmd_add_evidence,
    "verify-evidence": cmd_verify_evidence,
    "record-artifact": cmd_record_artifact,
    "verify-artifacts": cmd_verify_artifacts,
    "list-cases": cmd_list_cases,
    "case-status": cmd_case_status,
    "case-doctor": cmd_case_doctor,
    "case-report": cmd_case_report,
    "log-command": cmd_log_command,
    "flag-scan": cmd_flag_scan,
    "add-candidate": cmd_add_candidate,
    "add-review": cmd_add_review,
    "set-reproduction": cmd_set_reproduction,
    "set-final": cmd_set_final,
    "result-check": cmd_result_check,
    "triage-case": cmd_triage_case,
    "ftriage": lambda argv: _run_triage("ftriage", argv),
    "farchive": lambda argv: _run_triage("farchive", argv),
    "fpcap": lambda argv: _run_triage("fpcap", argv),
    "fsqlite": lambda argv: _run_triage("fsqlite", argv),
    "fstego": lambda argv: _run_triage("fstego", argv),
    "fmemory": lambda argv: _run_triage("fmemory", argv),
    "fdisk": lambda argv: _run_triage("fdisk", argv),
    "fdocument": lambda argv: _run_triage("fdocument", argv),
    "tool-inventory": cmd_tool_inventory,
    "remote-check": cmd_remote_check,
    "remote-exec": cmd_remote_exec,
    "remote-copy": cmd_remote_copy,
    "solve": cmd_solve,
    "nodes-status": cmd_nodes_status,
}


def main(argv: list[str] | None = None, *, command_name: str | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if command_name is None:
        command_name = os.path.basename(sys.argv[0])
    handler = COMMANDS.get(command_name)
    if handler is None:
        _err(f"Unknown command: {command_name!r} (known: {sorted(COMMANDS)})")
        return errors.USAGE_ERROR
    return handler(argv)


if __name__ == "__main__":
    sys.exit(main())
