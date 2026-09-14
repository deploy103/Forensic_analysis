"""Case listing, status summary, and self-diagnostic ("doctor") checks."""

from __future__ import annotations

import dataclasses
import os

from . import caselayout, commandlog, gate, pathsafety
from .artifact import verify_artifacts
from .case import UnknownCase, _case_dir_or_raise, verify_evidence


def list_cases(cases_root: str) -> list[str]:
    if not os.path.isdir(cases_root):
        return []
    names = []
    for entry in os.scandir(cases_root):
        if not entry.name.startswith(".") and entry.is_dir(follow_symlinks=False):
            names.append(entry.name)
    return sorted(names)


def _count_regular_files(directory: str) -> int:
    if not os.path.isdir(directory) or os.path.islink(directory):
        return 0
    count = 0
    root_fd = pathsafety.open_dir_nofollow(directory)
    try:
        count = _count_walk(root_fd)
    finally:
        os.close(root_fd)
    return count


def _count_walk(dir_fd: int) -> int:
    import stat as statmod

    total = 0
    with os.scandir(dir_fd) as entries:
        names = [e.name for e in entries]
    for name in names:
        st = os.lstat(name, dir_fd=dir_fd)
        if statmod.S_ISDIR(st.st_mode):
            sub_fd = pathsafety.open_dir_nofollow(name, dir_fd=dir_fd)
            try:
                total += _count_walk(sub_fd)
            finally:
                os.close(sub_fd)
        elif statmod.S_ISREG(st.st_mode):
            total += 1
    return total


@dataclasses.dataclass
class CaseStatus:
    name: str
    evidence_file_count: int
    evidence_integrity_ok: bool
    workspace_file_count: int
    artifact_integrity_ok: bool
    command_count: int
    final_status: str  # "verified" | "pending" | "unverified-candidate" | "no-candidate"


def case_status(cases_root: str, case_name: str) -> CaseStatus:
    case_dir = _case_dir_or_raise(cases_root, case_name)

    ev = verify_evidence(cases_root, case_name)
    art = verify_artifacts(cases_root, case_name)
    commands = commandlog.read_command_log(case_dir)

    candidates_path = os.path.join(case_dir, caselayout.CANDIDATES_JSONL)
    final_path = os.path.join(case_dir, caselayout.FINAL_JSON)
    try:
        final = gate._read_json_object(final_path, gate.FINAL_FIELDS, "final.json")
    except gate.GateError:
        final = None
    try:
        candidates = gate._read_jsonl_records(candidates_path, gate.CANDIDATE_FIELDS, "candidates.jsonl")
    except gate.GateError:
        candidates = []

    if final is not None and final.get("status") == "verified":
        gate_result = gate.run_gate(cases_root, case_name)
        final_status = "verified" if gate_result.ok else "unverified-candidate"
    elif candidates:
        final_status = "pending"
    else:
        final_status = "no-candidate"

    return CaseStatus(
        name=case_name,
        evidence_file_count=len(ev.directory.matched) + len(ev.directory.mismatched),
        evidence_integrity_ok=ev.ok,
        workspace_file_count=_count_regular_files(os.path.join(case_dir, caselayout.WORKSPACE_DIR)),
        artifact_integrity_ok=art.ok,
        command_count=len(commands),
        final_status=final_status,
    )


@dataclasses.dataclass
class DoctorFinding:
    severity: str  # "error" | "warning"
    message: str


def case_doctor(cases_root: str, case_name: str) -> list[DoctorFinding]:
    """Deeper structural self-check than :func:`case_status` -- meant for humans debugging a case."""
    findings: list[DoctorFinding] = []
    try:
        case_dir = _case_dir_or_raise(cases_root, case_name)
    except UnknownCase as exc:
        return [DoctorFinding("error", str(exc))]

    for sub in caselayout.ALL_SUBDIRS:
        full = os.path.join(case_dir, *sub.split("/"))
        if not os.path.isdir(full):
            findings.append(DoctorFinding("error", f"missing required subdirectory: {sub}"))
        elif os.path.islink(full):
            findings.append(DoctorFinding("error", f"required subdirectory is a symlink: {sub}"))

    ev = verify_evidence(cases_root, case_name)
    if not ev.ok:
        for path, reason in ev.directory.mismatched:
            findings.append(DoctorFinding("error", f"evidence hash mismatch: {path}: {reason}"))
        for path in ev.directory.missing:
            findings.append(DoctorFinding("error", f"evidence recorded but missing on disk: {path}"))
        for path in ev.directory.extra:
            findings.append(DoctorFinding("error", f"evidence file present but not recorded: {path}"))
        for path in ev.writable_paths:
            findings.append(DoctorFinding("warning", f"evidence file is still writable: {path}"))

    art = verify_artifacts(cases_root, case_name)
    for path, reason in art.directory.mismatched:
        findings.append(DoctorFinding("error", f"artifact hash mismatch: {path}: {reason}"))
    for path in art.directory.missing:
        findings.append(DoctorFinding("error", f"artifact recorded but missing on disk: {path}"))
    for path in art.directory.extra:
        findings.append(DoctorFinding("warning", f"workspace file present but never recorded as an artifact: {path}"))

    gate_result = gate.run_gate(cases_root, case_name)
    if not gate_result.ok:
        for reason in gate_result.reasons:
            if reason.startswith("evidence integrity") or reason.startswith("artifact integrity"):
                continue  # already reported above with more detail
            findings.append(DoctorFinding("warning", f"final result gate: {reason}"))

    return findings
