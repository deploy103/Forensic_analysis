# Playbook: Archive/container (zip, tar, gzip, bzip2, xz)

## 1. Scope and input identification

Applies to `PK\x03\x04`/`PK\x05\x06`/`PK\x07\x08` (zip), `\x1f\x8b` (gzip), `BZh` (bzip2),
`\xfd7zXZ\x00` (xz), and a `ustar\x00`/`ustar  \x00` magic at offset 257 (tar). `bin/farchive`
(`lib/pyforensic/triage/archive.py`) recognizes all of these natively via `zipfile`/`tarfile`/
`gzip`/`bz2`/`lzma` -- no external `7z`/`unzip` binary is required or shelled out to. If the
zip also contains `[Content_Types].xml`, it is an OOXML document and `bin/fdocument` (see
`DOCUMENT.md`) is the more specific playbook -- `bin/ftriage` already tries document dispatch
before archive dispatch for exactly this reason.

## 2. Evidence read-only principle

Never open the evidence archive for writing and never extract in place. `archive.py`'s
`extract()` only ever writes into a caller-supplied `dest_dir`; run it against a `workspace/`
destination, never against `evidence/`.

## 3. Initial observations

1. `sha256sum cases/<case>/evidence/<file>` -- confirm against `notes/evidence-manifest.jsonl`.
2. `bin/farchive cases/<case>/evidence/<file>` -- reports format, entry count, total
   uncompressed/compressed bytes, CRC failures, zip-slip/tar-slip member names, and the
   uncompressed:compressed ratio (bomb warning above `common.BOMB_RATIO_WARNING`).
3. For a single-stream gzip/bzip2/xz, `bin/farchive` decompresses only a bounded 4 MiB probe
   and reports the *inner* format it can see -- treat a `truncated` probe warning as "there is
   more here, not a stop condition," not as an error.

## 4. Hypothesis branching

- CRC failure reported -> corruption or a deliberately crafted bad-CRC member; compare byte
  size against what the member's local file header claims before assuming corruption.
- Zip-slip/tar-slip names reported -> the archive was built to escape the extraction directory;
  the flag is likely inside a rejected member -- extract it by name into `workspace/` under a
  sanitized name rather than trusting the embedded path.
- Suspicious compression ratio -> possible zip bomb; do not run a full recursive extractor.
  Inspect the entry list and sizes first, extract only the specific member(s) that look
  relevant, and keep `max_total_bytes` enforced.
- Encrypted member (`encrypted: true` in an entry) -> note it as a candidate for a password
  found elsewhere in the case (notes, another extracted file, a PNG tEXt chunk, etc.) rather
  than guessing blindly.

## 5. Stop conditions

- Do not attempt more than a handful of password guesses sourced from evidence already on
  hand; brute-forcing an unknown zip password is out of scope for this playbook.
- Never remove `archive.py`'s `max_total_bytes` cap or re-implement extraction with a raw
  `zipfile`/`tarfile` call that skips `common.safe_member_components` traversal checks.
- Stop recursing into nested archives past 3 levels unless a specific observation (a name, a
  size, a string match) justifies going deeper.

## 6. Exact commands

```bash
bin/farchive cases/<case>/evidence/<file> --json
python3 -c "
from pyforensic.triage import archive
import sys
result = archive.extract(sys.argv[1], sys.argv[2])
print(result.outcome, result.summary)
" cases/<case>/evidence/<file> cases/<case>/workspace/extracted
bin/flag-scan cases/<case>/workspace/extracted/<member> --json
```

## 7. Workspace output location

Extracted members go under `cases/<case>/workspace/extracted/`; preserve the sanitized
relative member path so provenance stays obvious.

## 8. Artifact hash recording

```bash
bin/log-command <case> -- python3 -c "from pyforensic.triage import archive; print(archive.extract('cases/<case>/evidence/<file>', 'cases/<case>/workspace/extracted').summary)"
bin/record-artifact <case> cases/<case>/workspace/extracted/<member> --log-id <log-id>
```

## 9. Flag evidence and minimal reproduction

Tie a candidate to the exact member name/offset inside the archive plus any decompression or
decoding step applied afterward:

```bash
bin/add-candidate <case> --flag <flag> --evidence cases/<case>/workspace/extracted/<member> \
  --locator '{"archive_member": "<name>"}' --transformation "zip extraction" --log-id <log-id>
```

## 10. Failure fallback

If `bin/farchive` reports `parser_failure` on a format that still looks archive-like by eye,
next check `bin/tool-inventory` for `7z`/`binwalk`; if absent, escalate to the remote
`forensic` server (`docs/server-contract.md`) rather than installing new packages locally.
If a password is required and none is found in
the case, record that blocker in `notes/case.md` instead of guessing indefinitely.
