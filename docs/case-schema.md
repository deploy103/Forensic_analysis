# Case record schema

Every directory under `cases/` except `.template` is one independent authorized challenge.

## Required records

| Path | Owner | Meaning |
|---|---|---|
| `notes/case.md` | supervisor | case name, creation time, status, supplied problem statement |
| `notes/case-meta.json` | intake helpers | case metadata (name, created_utc) |
| `notes/evidence-manifest.jsonl` | intake helpers | one JSON record per evidence file, relative to `evidence/` |
| `notes/artifacts-manifest.jsonl` | analysis helpers | one JSON record per generated workspace file, relative to the case root |
| `logs/commands.md` | command logger | human-readable command index |
| `logs/commands.jsonl` | command logger | one structured record per command |
| `logs/*.log` | command logger | combined stdout/stderr, named by UTC run ID and process ID |
| `result/candidates.jsonl` | supervisor/specialists | one JSON record per flag candidate, with its evidence chain |
| `result/review.jsonl` | reviewer | one JSON record per reviewer verdict, hash-bound to the manifests at review time |
| `result/final.json` | supervisor | the single accepted flag, bound to one reviewed, reproduced candidate |
| `result/reproduction.json` | supervisor/reviewer | the minimal tested command that reproduces the final candidate |

Every record in every `.jsonl`/`.json` file under `notes/`, `logs/`, and `result/` is a JSON
object with an exact, closed field set: an unknown extra field or a missing required field is
rejected, not silently ignored (see `manifest.py`'s `EVIDENCE_FIELDS`/`ARTIFACT_FIELDS` and
`gate.py`'s `CANDIDATE_FIELDS`/`REVIEW_FIELDS`/`REPRODUCTION_FIELDS`/`FINAL_FIELDS`). Nothing
under `result/` is meant to be hand-edited; each file is written only by its own CLI command
(`bin/add-candidate`, `bin/add-review`, `bin/set-reproduction`, `bin/set-final`).

## Evidence/artifact manifest JSONL fields

- `path`: file path (relative to `evidence/` for the evidence manifest, relative to the case root for the artifact manifest)
- `sha256`, `size`: integrity hash and byte size
- `recorded_utc`: ISO-8601 UTC timestamp
- `original_filename` (evidence manifest only): the source filename before intake
- `producing_log_id`, `parent_artifact` (artifact manifest only): provenance -- which logged command produced this file, and which prior artifact (if any) it was derived from

## Command JSONL fields

- `started_utc`, `finished_utc`: ISO-8601 UTC timestamps
- `duration_seconds`: integer wall-clock duration
- `cwd`: command working directory
- `command`: argument array, not a display-only shell string
- `exit_status`: process exit status before `tee`
- `combined_output`: case-relative raw log path
- `output_sha256`: integrity hash for that raw log

Consumers must tolerate future additional fields. A failed command is a valid record and does not imply that its output supports a finding.

## Result-gate JSON/JSONL fields

- `result/candidates.jsonl` -- one record per candidate: `candidate_id`, `flag`, `evidence_path`, `locator` (format-specific, e.g. a byte offset), `transformation` (free-text description of how the flag was derived from the evidence, e.g. `"none"` or `"base64-decoded"`), `log_id` (the command-log entry that produced this candidate), `artifact_path` (optional), `recorded_utc`.
- `result/review.jsonl` -- one record per reviewer verdict: `reviewer`, `reviewed_utc`, `verdict` (`verified` / `rejected` / `needs-more-evidence`), `candidate_ids` (the candidates this verdict covers), `concerns`, and `binding` -- the SHA-256 of the evidence manifest, artifact manifest, and `candidates.jsonl` text *as they existed at review time*. If any of those three files change afterward, the review's `binding` no longer matches current state and the gate reports it as stale.
- `result/reproduction.json` -- the minimal reproduction: `candidate_id`, `log_id` (must reference a logged command that exited 0), `output_sha256` (re-checked live against the actual on-disk output file, not just trusted from the log record), `evidence_path`, `evidence_sha256`, `commands_summary`, `recorded_utc`.
- `result/final.json` -- the single accepted result: `status` (must be `"verified"`), `flag`, `candidate_id`, `evidence_path`, `set_utc`.

## Integrity rules

- Evidence manifest paths are relative to `evidence/`; artifact manifest paths are relative to the case root.
- Evidence write bits are removed during intake, but hashes remain the authoritative integrity check.
- Raw evidence and bulk-generated products are intentionally untracked by Git.
- `bin/result-check` (`gate.run_gate`) is the machine-enforced minimum gate, not a replacement for forensic judgment: it can confirm a reviewed, reproduced, hash-consistent chain exists, but cannot confirm the flag is actually correct.
