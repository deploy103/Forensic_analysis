"""Human-readable case report generation.

``generate_report`` only ever *returns* a string; it never writes into the
case directory itself. If a report were persisted under
``result/report.md`` and a later "include everything under result/" pass
folded that file back into the next report, each regeneration would
embed every previous report inside the new one -- unbounded growth from a
purely mechanical mistake. Keeping report generation a pure read -> string
function sidesteps the problem entirely; callers who want a saved copy
write it wherever they like outside the case tree (or accept that the
report is a point-in-time snapshot, not part of the case's own record).
"""

from __future__ import annotations

import os

from . import caselayout, commandlog, gate, manifest, timeutil
from .artifact import verify_artifacts
from .case import _case_dir_or_raise, verify_evidence


def _read_text_or_placeholder(path: str) -> str:
    if not os.path.isfile(path) or os.path.islink(path):
        return "_No record._"
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        content = handle.read().strip()
    return content if content else "_No record._"


def _section(title: str, body: str) -> str:
    return f"\n## {title}\n\n{body}\n"


def generate_report(cases_root: str, case_name: str) -> str:
    case_dir = _case_dir_or_raise(cases_root, case_name)

    ev = verify_evidence(cases_root, case_name)
    art = verify_artifacts(cases_root, case_name)
    commands = commandlog.read_command_log(case_dir)
    gate_result = gate.run_gate(cases_root, case_name)

    lines = [f"# Case report: {case_name}", "", f"Generated (UTC): {timeutil.now_utc_iso()}"]

    lines.append(_section("Case notes", _read_text_or_placeholder(os.path.join(case_dir, caselayout.CASE_NOTES))))

    ev_lines = [f"- {r['path']}  `{r['sha256']}`  ({r['size']} bytes)" for r in manifest.load_evidence_manifest(
        os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))]
    ev_lines.append(f"- Integrity check: {'PASS' if ev.ok else 'FAIL'}")
    lines.append(_section("Evidence", "\n".join(ev_lines) if ev_lines else "_No evidence recorded._"))

    art_lines = [f"- {r['path']}  `{r['sha256']}`  ({r['size']} bytes)" for r in manifest.load_artifact_manifest(
        os.path.join(case_dir, caselayout.ARTIFACT_MANIFEST))]
    art_lines.append(f"- Integrity check: {'PASS' if art.ok else 'FAIL'}")
    if art.directory.extra:
        art_lines.append(f"- Unrecorded workspace files: {len(art.directory.extra)}")
    lines.append(_section("Generated artifacts", "\n".join(art_lines) if art_lines else "_No artifacts recorded._"))

    lines.append(_section("Commands executed", f"{len(commands)} command(s) logged in `{caselayout.COMMANDS_JSONL}`."))

    try:
        candidates = gate._read_jsonl_records(
            os.path.join(case_dir, caselayout.CANDIDATES_JSONL), gate.CANDIDATE_FIELDS, "candidates.jsonl")
    except gate.GateError as exc:
        candidates = []
        lines.append(_section("Flag candidates", f"_Could not read candidates: {exc}_"))
    else:
        cand_lines = [f"- `{c['candidate_id']}`: flag from `{c['evidence_path']}` (transformation: {c['transformation']})"
                      for c in candidates]
        lines.append(_section("Flag candidates", "\n".join(cand_lines) if cand_lines else "_No candidates recorded._"))

    lines.append(_section(
        "Final result gate",
        "PASS" if gate_result.ok else "FAIL:\n" + "\n".join(f"- {reason}" for reason in gate_result.reasons),
    ))

    return "\n".join(lines) + "\n"
