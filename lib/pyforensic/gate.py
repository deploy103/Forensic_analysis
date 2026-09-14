"""Structured reviewer / final-result gate.

Replaces the previous "a few ``grep -Eq`` patterns against Markdown files"
result check. That approach could be satisfied by any text that happened
to contain the right substrings -- including a fabricated line pasted in
by hand -- and could not detect a review that was written *before* the
evidence or candidate list was last edited.

The structured records this module validates
(``result/candidates.jsonl``, ``result/review.jsonl``,
``result/reproduction.json``, ``result/final.json``) are bound together by
content hashes: a review record snapshots the SHA-256 of the evidence
manifest, artifact manifest, and candidates file *as they existed at
review time*; if any of those change afterward, :func:`run_gate` reports
the review as stale rather than accepting it. A reproduction record
similarly snapshots the evidence hash and the hash of the referenced
command's captured output, so the gate can tell whether the reproduction
still matches current reality.

Documented limit (same trust boundary as everywhere else in this
project): this is tamper-*evidence*, not a cryptographic signature. An
operator with write access to the whole case tree could, in principle,
edit every bound file and recompute every hash to match -- but doing so
requires actually reproducing matching evidence, command output, and
candidate data, which is the point: the chain cannot be satisfied by
editing text describing an outcome without the outcome itself being real.
"""

from __future__ import annotations

import dataclasses
import errno
import hashlib
import json
import os

from . import caselayout, commandlog, locking, manifest, pathsafety, strictjson, timeutil
from .artifact import verify_artifacts
from .case import _case_dir_or_raise, verify_evidence

CANDIDATE_FIELDS = {
    "candidate_id",
    "flag",
    "evidence_path",
    "locator",
    "transformation",
    "log_id",
    "artifact_path",
    "recorded_utc",
}
REVIEW_FIELDS = {
    "reviewer",
    "reviewed_utc",
    "verdict",
    "candidate_ids",
    "concerns",
    "binding",
}
REPRODUCTION_FIELDS = {
    "candidate_id",
    "log_id",
    "output_sha256",
    "evidence_path",
    "evidence_sha256",
    "commands_summary",
    "recorded_utc",
}
FINAL_FIELDS = {"status", "flag", "candidate_id", "evidence_path", "set_utc"}

VALID_VERDICTS = {"verified", "rejected", "needs-more-evidence"}


class GateError(Exception):
    pass


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read_jsonl_records(path: str, required_fields: set[str], label: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    text = manifest.read_protected_file(path)
    records = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = strictjson.loads_strict(line, root_name=f"{label}[{line_no}]")
        except strictjson.StrictJSONError as exc:
            raise GateError(f"{label} line {line_no}: {exc}") from exc
        if not isinstance(obj, dict):
            raise GateError(f"{label} line {line_no}: record is not a JSON object")
        missing = required_fields - obj.keys()
        if missing:
            raise GateError(f"{label} line {line_no}: missing field(s) {sorted(missing)}")
        unknown = obj.keys() - required_fields
        if unknown:
            raise GateError(f"{label} line {line_no}: unknown field(s) {sorted(unknown)}")
        records.append(obj)
    return records


def _read_json_object(path: str, required_fields: set[str], label: str) -> dict | None:
    if not os.path.exists(path):
        return None
    text = manifest.read_protected_file(path)
    if text.strip() == "":
        return None
    try:
        obj = strictjson.loads_strict(text, root_name=label)
    except strictjson.StrictJSONError as exc:
        raise GateError(f"{label}: {exc}") from exc
    if not isinstance(obj, dict):
        raise GateError(f"{label}: record is not a JSON object")
    missing = required_fields - obj.keys()
    if missing:
        raise GateError(f"{label}: missing field(s) {sorted(missing)}")
    unknown = obj.keys() - required_fields
    if unknown:
        raise GateError(f"{label}: unknown field(s) {sorted(unknown)}")
    return obj


@dataclasses.dataclass
class GateResult:
    ok: bool
    reasons: list[str]


def run_gate(cases_root: str, case_name: str) -> GateResult:
    reasons: list[str] = []
    try:
        case_dir = _case_dir_or_raise(cases_root, case_name)
    except Exception as exc:
        return GateResult(ok=False, reasons=[str(exc)])

    ev = verify_evidence(cases_root, case_name)
    if not ev.ok:
        reasons.append(f"evidence integrity check failed: {ev.directory.mismatched or ev.directory.missing or ev.directory.extra or ev.writable_paths}")

    art = verify_artifacts(cases_root, case_name)
    if not art.ok:
        reasons.append(f"artifact integrity check failed: {art.directory.mismatched or art.directory.missing}")

    candidates_path = os.path.join(case_dir, caselayout.CANDIDATES_JSONL)
    try:
        candidates = _read_jsonl_records(candidates_path, CANDIDATE_FIELDS, "candidates.jsonl")
    except GateError as exc:
        return GateResult(ok=False, reasons=reasons + [str(exc)])
    candidates_by_id = {}
    for rec in candidates:
        if rec["candidate_id"] in candidates_by_id:
            reasons.append(f"duplicate candidate_id: {rec['candidate_id']}")
        candidates_by_id[rec["candidate_id"]] = rec

    evidence_paths = {r["path"] for r in manifest.load_evidence_manifest(
        os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))}
    commands = {r.get("log_id"): r for r in commandlog.read_command_log(case_dir)}

    for rec in candidates:
        if rec["evidence_path"] not in evidence_paths:
            reasons.append(f"candidate {rec['candidate_id']}: evidence_path not in evidence manifest: {rec['evidence_path']}")
        if rec["log_id"] not in commands:
            reasons.append(f"candidate {rec['candidate_id']}: log_id not found in command log: {rec['log_id']}")
        if not rec["flag"].strip():
            reasons.append(f"candidate {rec['candidate_id']}: flag is blank")

    try:
        final = _read_json_object(os.path.join(case_dir, caselayout.FINAL_JSON), FINAL_FIELDS, "final.json")
    except GateError as exc:
        return GateResult(ok=False, reasons=reasons + [str(exc)])
    if final is None:
        return GateResult(ok=False, reasons=reasons + ["final.json is missing or empty"])
    if final["status"] != "verified":
        reasons.append(f"final.status is {final['status']!r}, expected 'verified'")
    if not final["flag"].strip():
        reasons.append("final.flag is blank")

    final_candidate = candidates_by_id.get(final["candidate_id"])
    if final_candidate is None:
        reasons.append(f"final.candidate_id does not match any recorded candidate: {final['candidate_id']}")
    else:
        if final["flag"] != final_candidate["flag"]:
            reasons.append("final.flag does not match the referenced candidate's flag")
        if final["evidence_path"] != final_candidate["evidence_path"]:
            reasons.append("final.evidence_path does not match the referenced candidate's evidence_path")

    try:
        reproduction = _read_json_object(
            os.path.join(case_dir, caselayout.REPRODUCTION_JSON), REPRODUCTION_FIELDS, "reproduction.json"
        )
    except GateError as exc:
        return GateResult(ok=False, reasons=reasons + [str(exc)])
    if reproduction is None:
        reasons.append("reproduction.json is missing or empty")
    else:
        if reproduction["candidate_id"] != final.get("candidate_id"):
            reasons.append("reproduction.candidate_id does not match final.candidate_id")
        log_record = commands.get(reproduction["log_id"])
        if log_record is None:
            reasons.append(f"reproduction.log_id not found in command log: {reproduction['log_id']}")
        else:
            if log_record.get("exit_status") != 0:
                reasons.append(f"reproduction references a command that did not exit 0 (log_id={reproduction['log_id']})")
            output_path = os.path.join(case_dir, log_record["combined_output"])
            if os.path.exists(output_path) and not os.path.islink(output_path):
                with open(output_path, "rb") as handle:
                    actual_output_hash = hashlib.sha256(handle.read()).hexdigest()
                if actual_output_hash != reproduction["output_sha256"]:
                    reasons.append("reproduction.output_sha256 does not match the current command output file")
            else:
                reasons.append(f"reproduction references a missing/symlinked output file: {output_path}")
        evidence_record = next((r for r in manifest.load_evidence_manifest(
            os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST)) if r["path"] == reproduction["evidence_path"]), None)
        if evidence_record is None:
            reasons.append(f"reproduction.evidence_path not in evidence manifest: {reproduction['evidence_path']}")
        elif evidence_record["sha256"] != reproduction["evidence_sha256"]:
            reasons.append("reproduction.evidence_sha256 does not match the current evidence manifest")

    review_path = os.path.join(case_dir, caselayout.REVIEW_JSONL)
    try:
        reviews = _read_jsonl_records(review_path, REVIEW_FIELDS, "review.jsonl")
    except GateError as exc:
        return GateResult(ok=False, reasons=reasons + [str(exc)])

    current_hashes = {
        "evidence_manifest_sha256": _sha256_text(
            manifest.read_protected_file(os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))
        ) if os.path.exists(os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST)) else None,
        "artifact_manifest_sha256": _sha256_text(
            manifest.read_protected_file(os.path.join(case_dir, caselayout.ARTIFACT_MANIFEST))
        ) if os.path.exists(os.path.join(case_dir, caselayout.ARTIFACT_MANIFEST)) else None,
        "candidates_sha256": _sha256_text(
            manifest.read_protected_file(candidates_path)
        ) if os.path.exists(candidates_path) else None,
    }

    verifying_reviews = []
    for rec in reviews:
        if rec["verdict"] not in VALID_VERDICTS:
            reasons.append(f"review has invalid verdict: {rec['verdict']!r}")
            continue
        if not rec["reviewer"].strip():
            reasons.append("review.reviewer is blank")
        if rec["verdict"] == "verified" and final["candidate_id"] in rec["candidate_ids"]:
            verifying_reviews.append(rec)

    if not verifying_reviews:
        reasons.append(f"no review record with verdict='verified' covers candidate {final['candidate_id']!r}")
    else:
        fresh = [rec for rec in verifying_reviews if rec["binding"] == current_hashes]
        if not fresh:
            reasons.append(
                "every 'verified' review for this candidate is stale: its recorded binding hashes "
                "no longer match the current evidence/artifact manifests or candidates.jsonl "
                "(something changed after the review was recorded)"
            )

    return GateResult(ok=not reasons, reasons=reasons)


def _write_json_object_safe(path: str, obj: dict) -> None:
    """Create-or-overwrite a single-JSON-object file, rejecting a symlinked or hardlinked target."""
    lock_path = path + ".lock"
    with locking.exclusive_lock(lock_path):
        directory, filename = os.path.split(path)
        dir_fd = pathsafety.open_dir_nofollow(directory or ".")
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW
            try:
                fd = os.open(filename, flags, 0o600, dir_fd=dir_fd)
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise GateError(f"{path!r} is a symlink; refusing to overwrite") from exc
                raise
        finally:
            os.close(dir_fd)
        try:
            st = os.fstat(fd)
            if st.st_nlink != 1:
                raise GateError(f"{path!r} has {st.st_nlink} hard links; refusing to overwrite")
            os.ftruncate(fd, 0)
            payload = (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)


def _current_binding_hashes(case_dir: str, candidates_path: str) -> dict:
    def hash_if_exists(path: str) -> str | None:
        if not os.path.exists(path):
            return None
        return _sha256_text(manifest.read_protected_file(path))

    return {
        "evidence_manifest_sha256": hash_if_exists(os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST)),
        "artifact_manifest_sha256": hash_if_exists(os.path.join(case_dir, caselayout.ARTIFACT_MANIFEST)),
        "candidates_sha256": hash_if_exists(candidates_path),
    }


def add_candidate(
    cases_root: str,
    case_name: str,
    *,
    flag: str,
    evidence_path: str,
    locator: dict,
    transformation: str,
    log_id: str,
    artifact_path: str | None = None,
) -> dict:
    case_dir = _case_dir_or_raise(cases_root, case_name)
    if not flag.strip():
        raise GateError("flag must not be blank")
    evidence_paths = {r["path"] for r in manifest.load_evidence_manifest(
        os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))}
    if evidence_path not in evidence_paths:
        raise GateError(f"evidence_path not in evidence manifest: {evidence_path}")
    commands = commandlog.read_command_log(case_dir)
    if not any(r.get("log_id") == log_id for r in commands):
        raise GateError(f"log_id not found in command log: {log_id}")

    candidates_path = os.path.join(case_dir, caselayout.CANDIDATES_JSONL)
    lock_path = os.path.join(case_dir, ".candidates.lock")
    with locking.exclusive_lock(lock_path):
        existing = _read_jsonl_records(candidates_path, CANDIDATE_FIELDS, "candidates.jsonl")
        next_index = len(existing) + 1
        candidate_id = f"c{next_index}"
        while any(r["candidate_id"] == candidate_id for r in existing):
            next_index += 1
            candidate_id = f"c{next_index}"
        record = {
            "candidate_id": candidate_id,
            "flag": flag,
            "evidence_path": evidence_path,
            "locator": locator,
            "transformation": transformation,
            "log_id": log_id,
            "artifact_path": artifact_path,
            "recorded_utc": timeutil.now_utc_iso(),
        }
        locking.locked_append_lines(candidates_path, [json.dumps(record, ensure_ascii=False, sort_keys=True)])
    return record


def add_review(
    cases_root: str,
    case_name: str,
    *,
    reviewer: str,
    verdict: str,
    candidate_ids: list[str],
    concerns: str = "none",
) -> dict:
    case_dir = _case_dir_or_raise(cases_root, case_name)
    if not reviewer.strip():
        raise GateError("reviewer must not be blank")
    if verdict not in VALID_VERDICTS:
        raise GateError(f"verdict must be one of {sorted(VALID_VERDICTS)}")
    if not candidate_ids:
        raise GateError("candidate_ids must not be empty")

    candidates_path = os.path.join(case_dir, caselayout.CANDIDATES_JSONL)
    candidates = _read_jsonl_records(candidates_path, CANDIDATE_FIELDS, "candidates.jsonl")
    known_ids = {r["candidate_id"] for r in candidates}
    unknown = [cid for cid in candidate_ids if cid not in known_ids]
    if unknown:
        raise GateError(f"candidate_ids not found: {unknown}")

    review_path = os.path.join(case_dir, caselayout.REVIEW_JSONL)
    record = {
        "reviewer": reviewer,
        "reviewed_utc": timeutil.now_utc_iso(),
        "verdict": verdict,
        "candidate_ids": list(candidate_ids),
        "concerns": concerns,
        "binding": _current_binding_hashes(case_dir, candidates_path),
    }
    locking.locked_append_lines(review_path, [json.dumps(record, ensure_ascii=False, sort_keys=True)])
    return record


def set_reproduction(
    cases_root: str,
    case_name: str,
    *,
    candidate_id: str,
    log_id: str,
    commands_summary: str,
) -> dict:
    case_dir = _case_dir_or_raise(cases_root, case_name)
    candidates_path = os.path.join(case_dir, caselayout.CANDIDATES_JSONL)
    candidates = {r["candidate_id"]: r for r in _read_jsonl_records(candidates_path, CANDIDATE_FIELDS, "candidates.jsonl")}
    candidate = candidates.get(candidate_id)
    if candidate is None:
        raise GateError(f"unknown candidate_id: {candidate_id}")

    commands = {r.get("log_id"): r for r in commandlog.read_command_log(case_dir)}
    log_record = commands.get(log_id)
    if log_record is None:
        raise GateError(f"log_id not found in command log: {log_id}")
    if log_record.get("exit_status") != 0:
        raise GateError(f"referenced command did not exit 0: {log_id}")

    output_path = os.path.join(case_dir, log_record["combined_output"])
    if not os.path.isfile(output_path) or os.path.islink(output_path):
        raise GateError(f"command output file is missing or a symlink: {output_path}")
    with open(output_path, "rb") as handle:
        output_sha256 = hashlib.sha256(handle.read()).hexdigest()

    evidence_records = manifest.load_evidence_manifest(os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))
    evidence_record = next((r for r in evidence_records if r["path"] == candidate["evidence_path"]), None)
    if evidence_record is None:
        raise GateError(f"candidate's evidence_path not in evidence manifest: {candidate['evidence_path']}")

    record = {
        "candidate_id": candidate_id,
        "log_id": log_id,
        "output_sha256": output_sha256,
        "evidence_path": candidate["evidence_path"],
        "evidence_sha256": evidence_record["sha256"],
        "commands_summary": commands_summary,
        "recorded_utc": timeutil.now_utc_iso(),
    }
    _write_json_object_safe(os.path.join(case_dir, caselayout.REPRODUCTION_JSON), record)
    return record


def set_final(cases_root: str, case_name: str, *, candidate_id: str) -> dict:
    case_dir = _case_dir_or_raise(cases_root, case_name)
    candidates_path = os.path.join(case_dir, caselayout.CANDIDATES_JSONL)
    candidates = {r["candidate_id"]: r for r in _read_jsonl_records(candidates_path, CANDIDATE_FIELDS, "candidates.jsonl")}
    candidate = candidates.get(candidate_id)
    if candidate is None:
        raise GateError(f"unknown candidate_id: {candidate_id}")

    record = {
        "status": "verified",
        "flag": candidate["flag"],
        "candidate_id": candidate_id,
        "evidence_path": candidate["evidence_path"],
        "set_utc": timeutil.now_utc_iso(),
    }
    _write_json_object_safe(os.path.join(case_dir, caselayout.FINAL_JSON), record)
    return record
