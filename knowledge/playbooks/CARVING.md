# Playbook: Generic embedded data/carving

## 1. Scope and input identification

Use this playbook when a file's format is unknown, when `bin/ftriage` reports
`input_mismatch` after trying every specific wrapper, or when a specific wrapper (any of
`ARCHIVE.md`/`PCAP.md`/`SQLITE.md`/`IMAGE_STEGO.md`/`MEMORY.md`/`DISK.md`/`DOCUMENT.md`) has
already identified a container but reports **trailing bytes after its logical end** -- the
common CTF pattern of one known format concatenated with a second, different payload.
`bin/ftriage` (`lib/pyforensic/triage/dispatch.py`) tries, in order, pcap, sqlite, image,
document, archive, disk, then memory (memory is tried last because it treats an
unrecognized-but-parseable file as a valid raw dump rather than a mismatch, which would
otherwise swallow inputs a more specific wrapper further down the list should have caught).

## 2. Evidence read-only principle

Every carve is a **copy-out**, never an in-place edit: read the evidence file through a
read-only fd (or plain `open(..., "rb")`) and write the extracted slice under `workspace/`.
Never truncate, overwrite, or reorder bytes in the evidence file itself.

## 3. Initial observations

1. `sha256sum` the file; confirm its size against the manifest.
2. `bin/ftriage cases/<case>/evidence/<file> --json` -- if a specific format is identified,
   switch to that format's own playbook first; this generic playbook is for what remains
   afterward (unmatched files, or a `trailing_bytes`/size-mismatch warning already reported).
3. `file cases/<case>/evidence/<file>` and a hex view of the head/tail
   (`xxd cases/<case>/evidence/<file> | head`, `xxd cases/<case>/evidence/<file> | tail`) --
   look for a second magic signature partway through the file, not just at offset 0.
4. `bin/flag-scan cases/<case>/evidence/<file> --json` -- a direct string/regex match is
   cheaper than carving and should always be tried before manual offset work.

## 4. Hypothesis branching

- A known magic signature appears at a non-zero offset (grep the same magic-byte table used by
  `archive.py`/`image.py`/`pcap.py`/`sqlite.py`/`document.py` against the whole file, not just
  offset 0) -> carve from that exact offset to end-of-file (or to the next detected magic) and
  re-run `bin/ftriage` against the carved slice.
- A format-specific wrapper already reported a `trailing_bytes` count -> the offset is already
  known exactly (`file_size - trailing_bytes`, or the specific value the wrapper reported); go
  straight to carving that offset, no signature search needed.
- No recognizable magic anywhere, but `bin/fmemory`-style sampled entropy is unusually high for
  a subregion -> that region may be compressed/encrypted; note the byte range as a
  password/key-recovery lead rather than continuing a signature search there.
- Multiple magic signatures found back-to-back -> treat as a concatenation chain; carve and
  triage each segment in turn, in order, recording each as its own evidence-adjacent artifact.

## 5. Stop conditions

- Do not run an unbounded byte-by-byte magic scan over a multi-gigabyte file; search only the
  head/tail plus any offset already implicated by a format wrapper's own warning, and otherwise
  bound a full-file magic sweep by a reasonable chunk size with a hard time budget (the same
  spirit as `flagscan.py`'s own per-file timeout).
- Stop recursive carving (carved output containing yet another concatenated format) after 3
  levels unless a specific observation justifies continuing.
- Never use a raw `mmap()` of a large evidence file for a scan -- this project deliberately
  never mmaps evidence (see `flagscan.py`'s own docstring); use bounded chunked reads instead.

## 6. Exact commands

```bash
bin/ftriage cases/<case>/evidence/<file> --json
bin/flag-scan cases/<case>/evidence/<file> --json
xxd cases/<case>/evidence/<file> | head -5
xxd cases/<case>/evidence/<file> | tail -5
```

Carving a known byte range (never in place):

```bash
bin/log-command <case> -- python3 -c "
data = open('cases/<case>/evidence/<file>', 'rb').read()
open('cases/<case>/workspace/extracted/segment-1.bin', 'wb').write(data[<start>:<end>])
"
bin/ftriage cases/<case>/workspace/extracted/segment-1.bin --json
```

If `binwalk` is confirmed present via `bin/tool-inventory`:

```bash
bin/log-command <case> -- binwalk --dd='.*' -e cases/<case>/evidence/<file>
```

## 7. Workspace output location

Every carved segment goes under `cases/<case>/workspace/extracted/`, numbered in file order
(`segment-1.bin`, `segment-2.bin`, ...) so the concatenation order stays obvious.

## 8. Artifact hash recording

```bash
bin/record-artifact <case> cases/<case>/workspace/extracted/segment-1.bin --log-id <log-id>
```

## 9. Flag evidence and minimal reproduction

Tie a candidate to the exact byte range carved and the format ultimately identified in that
range:

```bash
bin/add-candidate <case> --flag <flag> --evidence cases/<case>/workspace/extracted/segment-1.bin \
  --locator '{"start_offset": <start>, "end_offset": <end>}' --transformation "byte-range carve" \
  --log-id <log-id>
```

## 10. Failure fallback

If a head/tail hex view and a full `bin/flag-scan` pass find nothing, and `bin/ftriage` matched
no format at all, escalate to the remote server for `binwalk`-class recursive signature
scanning rather than hand-rolling an exhaustive local magic-byte sweep. If a specific wrapper
already identified a container but a carve of its reported trailing region also triages as
`input_mismatch`, reconsider whether the trailing bytes are actually random padding rather than
a second payload before continuing to search.
