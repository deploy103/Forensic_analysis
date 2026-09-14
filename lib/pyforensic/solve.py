"""``solve``: the single competition-facing command.

Given a file (explicit path, auto-picked
from the current directory, or the newest file in ``~/Downloads``), this
module drives the entire pipeline -- case creation, evidence intake with
SHA-256 recording, format-specific triage, recursive extraction of nested
archives/compressed streams, flag-pattern scanning, candidate ranking, and a
terminal report ending with a prominent ``[FLAG]`` block when one is found
-- without the caller ever touching ``new-case``/``add-evidence``/
``triage-case``/``flag-scan`` directly. Those remain available under
``bin/`` for internal/debugging use.

Every step that runs an external command (``ftriage``, ``flag-scan``) goes
through :func:`pyforensic.commandlog.run_and_log`, so the resulting
``log_id`` values are real, hash-bound entries in the case's own command
log -- the same mechanism ``bin/add-candidate`` requires. Recursive
extraction of nested archive members is *not* individually logged (it can
touch hundreds of files inside a deeply nested archive); it runs in-process
against :mod:`pyforensic.triage.dispatch`, matching the scope decision that
only the top-level, evidentiary steps need to be reproducible subprocess
invocations.

This module also makes (and honestly records) a lightweight execution-node
decision via :mod:`pyforensic.nodes`/:mod:`pyforensic.scheduler`. Without a
configured and reachable remote node, every ``solve`` run executes locally;
the scheduler's ranking of configured remote nodes is still computed and
attached to the result as informational logging, but ``solve`` never claims
to have executed somewhere it did not.
"""

from __future__ import annotations

import dataclasses
import json
import os
import secrets

from . import caselayout, case, commandlog, errors, gate, history, manifest, nodes, scheduler, timeutil
from .triage import archive, dispatch

DOWNLOADS_DIR_ENV = "FORENSIC_SOLVER_DOWNLOADS_DIR"

MAX_EXTRACT_DEPTH = 5
MAX_RECURSIVE_FILES = 500
TOP_RECORD_LIMIT = 10

_KNOWN_FLAG_TAGS = {"flag", "dh", "ctf", "htb", "picoctf", "key", "secret"}
_SPECIFIC_PATTERNS = {"flag_braces", "htb_braces", "picoctf_braces", "dh_braces", "ctf_braces"}


class SolveError(Exception):
    pass


class NoCandidateFile(SolveError):
    pass


@dataclasses.dataclass
class RankedCandidate:
    flag: str
    pattern: str
    file: str
    offset: int
    score: float
    log_id: str
    source: str
    candidate_id: str | None = None


@dataclasses.dataclass
class SolveResult:
    case_name: str
    case_dir: str
    source_path: str
    evidence_path: str
    evidence_sha256: str
    triage: dict
    extracted_files: list[str]
    extraction_warnings: list[str]
    truncated_recursion: bool
    candidates: list[RankedCandidate]
    best: RankedCandidate | None
    execution_plan: dict


# --- file selection --------------------------------------------------------

def pick_auto_file(directory: str) -> str:
    """Pick the most recently modified regular, non-hidden file directly in ``directory``."""
    try:
        entries = os.scandir(directory)
    except OSError as exc:
        raise NoCandidateFile(f"cannot list directory {directory!r}: {exc}") from exc
    candidates: list[tuple[float, str]] = []
    with entries:
        for entry in entries:
            if entry.name.startswith("."):
                continue
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                mtime = entry.stat(follow_symlinks=False).st_mtime
            except OSError:
                continue
            candidates.append((mtime, entry.name))
    if not candidates:
        raise NoCandidateFile(f"no analyzable file found in {directory!r}")
    candidates.sort(key=lambda pair: pair[0], reverse=True)
    return os.path.join(directory, candidates[0][1])


def pick_latest_download() -> str:
    downloads_dir = os.environ.get(DOWNLOADS_DIR_ENV) or os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.isdir(downloads_dir):
        raise NoCandidateFile(f"downloads directory not found: {downloads_dir!r}")
    return pick_auto_file(downloads_dir)


def _resolve_source(source_path: str | None, use_latest: bool) -> str:
    if source_path:
        if not os.path.isfile(source_path) or os.path.islink(source_path):
            raise NoCandidateFile(f"not a regular file: {source_path}")
        return os.path.abspath(source_path)
    if use_latest:
        return pick_latest_download()
    return pick_auto_file(os.getcwd())


# --- case creation ----------------------------------------------------------

def _gen_case_name() -> str:
    stamp = timeutil.now_utc_iso().replace(":", "").replace("-", "")
    return f"solve-{stamp}-{secrets.token_hex(3)}"


def _create_with_retry(cases_root: str, evidence_path: str, *, attempts: int = 5) -> tuple[str, str]:
    last_exc: Exception | None = None
    for _ in range(attempts):
        name = _gen_case_name()
        try:
            case_dir = case.create_case(cases_root, name, [evidence_path])
            return name, case_dir
        except case.CaseAlreadyExists as exc:
            last_exc = exc
            continue
    raise SolveError(f"could not allocate a unique case name after {attempts} attempts: {last_exc}")


# --- distributed-execution decision (informational; see module docstring) --

def _plan_execution(project_root: str, evidence_abs_path: str) -> dict:
    try:
        size_mb = os.path.getsize(evidence_abs_path) / (1024 * 1024)
    except OSError:
        size_mb = 0.0
    requirement = scheduler.TaskRequirement(
        required_tools=["file", "python3"], resource_class="MEDIUM", evidence_size_mb=size_mb,
    )
    try:
        discovered = nodes.discover_nodes(project_root, probe_tools=requirement.required_tools)
        ranked = scheduler.rank_nodes(discovered, requirement, history_lookup=history.make_history_lookup())
    except Exception as exc:  # environment discovery must never break solve itself
        return {
            "executed_on": nodes.LOCAL_ALIAS,
            "scheduler_ranking": [],
            "note": f"node discovery failed ({exc}); ran locally",
        }
    return {
        "executed_on": nodes.LOCAL_ALIAS,
        "scheduler_ranking": [
            {"alias": s.node.alias, "status": s.node.status, "score": s.score} for s in ranked
        ],
        "note": (
            "remote dispatch is not wired into solve's live pipeline; this ranking is "
            "logged for future use once real remote nodes are configured. "
            "solve always executes locally today."
        ),
    }


# --- triage / flag-scan invocation (logged, hash-bound) --------------------

def _read_log_output(case_dir: str, run_result: commandlog.RunResult) -> bytes:
    path = os.path.join(case_dir, run_result.output_relative)
    with open(path, "rb") as handle:
        return handle.read()


def _run_ftriage_logged(cases_root: str, case_name: str, case_dir: str, project_root: str, target: str) -> dict:
    bin_ftriage = os.path.join(project_root, "bin", "ftriage")
    run_result = commandlog.run_and_log(cases_root, case_name, [bin_ftriage, target, "--json"])
    outcome = "success" if run_result.exit_status in (errors.TRIAGE_OK, errors.TRIAGE_PARTIAL_SUCCESS) else "failure"
    history.record_execution("ftriage", nodes.LOCAL_ALIAS, outcome, run_result.duration_seconds)
    raw = _read_log_output(case_dir, run_result)
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return {
            "outcome": "parser_failure", "tool": "ftriage",
            "summary": "ftriage did not produce valid JSON output", "details": {}, "warnings": [],
        }


def _run_flagscan_logged(cases_root: str, case_name: str, case_dir: str, project_root: str, target_dir: str) -> tuple[str, list[dict]]:
    bin_flag_scan = os.path.join(project_root, "bin", "flag-scan")
    run_result = commandlog.run_and_log(cases_root, case_name, [bin_flag_scan, target_dir, "--json"])
    outcome = "success" if run_result.exit_status in (errors.FLAG_SCAN_MATCHES_FOUND, errors.FLAG_SCAN_NO_MATCHES) else "failure"
    history.record_execution("flag-scan", nodes.LOCAL_ALIAS, outcome, run_result.duration_seconds)
    raw = _read_log_output(case_dir, run_result)
    matches = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("skipped"):
            continue
        matches.append(rec)
    return run_result.log_id, matches


# --- recursive extraction ---------------------------------------------------

def _recursive_extract(case_dir: str, evidence_abs_path: str) -> tuple[list[str], list[str], bool]:
    extracted_root = os.path.join(case_dir, caselayout.WORKSPACE_EXTRACTED)
    extracted_files: list[str] = []
    warnings: list[str] = []
    truncated = False
    queue: list[tuple[str, int]] = [(evidence_abs_path, 0)]
    processed = 0

    while queue:
        if processed >= MAX_RECURSIVE_FILES:
            truncated = True
            warnings.append(f"stopped after processing {MAX_RECURSIVE_FILES} file(s) (recursion cap)")
            break
        current_path, depth = queue.pop(0)
        processed += 1

        try:
            result = dispatch.detect_and_inspect(current_path)
        except Exception as exc:  # a wrapper crashing must not abort the whole solve run
            warnings.append(f"triage crashed on {current_path}: {exc}")
            continue

        if result.details.get("detected_as") != "archive":
            continue
        if depth >= MAX_EXTRACT_DEPTH:
            truncated = True
            warnings.append(f"stopped recursing into {current_path}: max depth {MAX_EXTRACT_DEPTH} reached")
            continue

        dest_subdir = os.path.join(extracted_root, secrets.token_hex(8))
        os.makedirs(dest_subdir, exist_ok=True)

        extract_result = archive.extract(current_path, dest_subdir)
        if extract_result.outcome == "input_mismatch":
            extract_result = archive.decompress_single_stream(current_path, dest_subdir)
        if extract_result.outcome == "parser_failure":
            warnings.append(f"extraction failed for {current_path}: {extract_result.summary}")
            continue
        warnings.extend(extract_result.warnings)

        for root, _dirs, files in os.walk(dest_subdir):
            for fname in files:
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, case_dir).replace(os.sep, "/")
                extracted_files.append(rel)
                queue.append((full, depth + 1))

    return extracted_files, warnings, truncated


# --- ranking -----------------------------------------------------------------

def _extract_tag(snippet: str) -> str:
    idx = snippet.find("{")
    return snippet[:idx].lower() if idx > 0 else ""


def _score_match(pattern: str, snippet: str) -> float:
    score = 0.0
    if pattern in _SPECIFIC_PATTERNS:
        score += 100.0
    score += 80.0 if _extract_tag(snippet) in _KNOWN_FLAG_TAGS else 10.0
    return score


def rank_candidates(scan_records: list[dict]) -> list[RankedCandidate]:
    candidates = [
        RankedCandidate(
            flag=rec["snippet"], pattern=rec["pattern"], file=rec["display_file"],
            offset=rec["offset"], score=_score_match(rec["pattern"], rec["snippet"]),
            log_id=rec["log_id"], source=rec["source"],
        )
        for rec in scan_records
    ]
    candidates.sort(key=lambda c: (-c.score, c.file, c.offset))
    seen: set[str] = set()
    deduped = []
    for candidate in candidates:
        if candidate.flag in seen:
            continue
        seen.add(candidate.flag)
        deduped.append(candidate)
    return deduped


def _record_candidates(cases_root: str, case_name: str, evidence_relpath: str, ranked: list[RankedCandidate]) -> None:
    for candidate in ranked[:TOP_RECORD_LIMIT]:
        locator = {
            "source": candidate.source, "file": candidate.file,
            "offset": candidate.offset, "pattern": candidate.pattern,
        }
        transformation = (
            "solve: direct evidence flag-scan" if candidate.source == "evidence"
            else "solve: recursive extraction + flag-scan"
        )
        try:
            record = gate.add_candidate(
                cases_root, case_name, flag=candidate.flag, evidence_path=evidence_relpath,
                locator=locator, transformation=transformation, log_id=candidate.log_id,
            )
            candidate.candidate_id = record["candidate_id"]
        except gate.GateError:
            continue  # best-effort: ranking/reporting must not depend on gate bookkeeping succeeding


# --- orchestration ------------------------------------------------------------

def run_solve(
    cases_root: str, project_root: str, *, source_path: str | None = None, use_latest: bool = False,
) -> SolveResult:
    resolved_source = _resolve_source(source_path, use_latest)
    case_name, case_dir = _create_with_retry(cases_root, resolved_source)

    evidence_dir = os.path.join(case_dir, caselayout.EVIDENCE_DIR)
    evidence_records = manifest.load_evidence_manifest(os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))
    evidence_record = evidence_records[0]
    evidence_relpath = evidence_record["path"]
    evidence_sha256 = evidence_record["sha256"]
    evidence_abs_path = os.path.join(evidence_dir, evidence_relpath)

    execution_plan = _plan_execution(project_root, evidence_abs_path)

    triage_result = _run_ftriage_logged(cases_root, case_name, case_dir, project_root, evidence_abs_path)

    extracted_files, extraction_warnings, truncated_recursion = _recursive_extract(case_dir, evidence_abs_path)

    scan_records: list[dict] = []
    ev_log_id, ev_matches = _run_flagscan_logged(cases_root, case_name, case_dir, project_root, evidence_dir)
    for m in ev_matches:
        scan_records.append({
            "pattern": m["pattern"], "offset": m["offset"], "snippet": m["snippet"],
            "log_id": ev_log_id, "display_file": f"{caselayout.EVIDENCE_DIR}/{m['path']}", "source": "evidence",
        })

    if extracted_files:
        extracted_root = os.path.join(case_dir, caselayout.WORKSPACE_EXTRACTED)
        ex_log_id, ex_matches = _run_flagscan_logged(cases_root, case_name, case_dir, project_root, extracted_root)
        for m in ex_matches:
            scan_records.append({
                "pattern": m["pattern"], "offset": m["offset"], "snippet": m["snippet"],
                "log_id": ex_log_id, "display_file": f"{caselayout.WORKSPACE_EXTRACTED}/{m['path']}", "source": "extracted",
            })

    ranked = rank_candidates(scan_records)
    _record_candidates(cases_root, case_name, evidence_relpath, ranked)
    best = ranked[0] if ranked else None

    return SolveResult(
        case_name=case_name, case_dir=case_dir, source_path=resolved_source,
        evidence_path=evidence_relpath, evidence_sha256=evidence_sha256,
        triage=triage_result, extracted_files=extracted_files,
        extraction_warnings=extraction_warnings, truncated_recursion=truncated_recursion,
        candidates=ranked, best=best, execution_plan=execution_plan,
    )


def render_human_report(result: SolveResult) -> str:
    lines = [
        f"[SOLVE] case={result.case_name}",
        f"source: {result.source_path}",
        f"evidence: {result.evidence_path} (sha256={result.evidence_sha256})",
        f"executed on: {result.execution_plan.get('executed_on')}",
        f"triage: [{result.triage.get('outcome')}] {result.triage.get('summary')}",
    ]
    if result.extracted_files:
        suffix = " (truncated)" if result.truncated_recursion else ""
        lines.append(f"extracted {len(result.extracted_files)} file(s) recursively{suffix}")
    for warning in result.extraction_warnings:
        lines.append(f"  ! {warning}")
    lines.append(f"candidates found: {len(result.candidates)}")
    for candidate in result.candidates[:5]:
        lines.append(
            f"  - {candidate.flag!r} (pattern={candidate.pattern}, file={candidate.file}, "
            f"offset={candidate.offset}, score={candidate.score:.0f})"
        )
    lines.append("")
    if result.best is not None:
        lines.append("[FLAG]")
        lines.append(result.best.flag)
    else:
        lines.append("[NO FLAG FOUND]")
    return "\n".join(lines)
