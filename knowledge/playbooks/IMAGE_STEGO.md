# Playbook: PNG/JPEG/BMP and steganography

## 1. Scope and input identification

Applies to PNG (`\x89PNG\r\n\x1a\n`), JPEG (`\xff\xd8`), and BMP (`BM`) magic bytes; `bin/fstego`
(`lib/pyforensic/triage/image.py`) also recognizes GIF (`GIF87a`/`GIF89a`) as a bonus. Each
format is walked natively via `struct` (chunk/segment/header layout) -- no image library
(Pillow etc.) is a project dependency.

## 2. Evidence read-only principle

`bin/fstego` only ever `os.pread`s the evidence file through a read-only fd. Any bit-plane
extraction, LSB decode, or channel-split output must be written under `workspace/extracted/`,
never overwriting the evidence image.

## 3. Initial observations

1. `sha256sum` the file and confirm against the manifest.
2. `bin/fstego cases/<case>/evidence/<file> --json`:
   - PNG: dimensions, bit depth, color type, chunk list, and bytes appended **after `IEND`**
     (a classic CTF hiding spot) as a `trailing_bytes` warning; also flags `tEXt`/`zTXt`/`iTXt`
     metadata chunks.
   - JPEG: segment list and bytes appended **after EOI** (`0xFFD9`) as a `trailing_bytes`
     warning.
   - BMP: reports a mismatch between the header's own `file_size` field and the actual file
     size -- a strong signal of appended/hidden data.
3. If `exiftool` or `binwalk` happen to be on `PATH` (both confirmed absent on the reference
   host), `bin/fstego` layers their output on top of the native result automatically -- it
   never depends on them, so their absence alone is not a reason to skip triage.

## 4. Hypothesis branching

- `trailing_bytes` warning (PNG after IEND / JPEG after EOI / BMP header vs. actual size
  mismatch) -> a second payload is appended; carve it out with `dd`/Python slicing at the exact
  reported offset (see `CARVING.md`) rather than assuming it is random padding.
- `tEXt`/`zTXt`/`iTXt` chunks present -> read the chunk content directly; PNG text metadata is
  a common place to stash a password or a base64 blob for a nested archive.
- No trailing data and no metadata chunks -> consider LSB/bit-plane steganography; extract
  specific bit planes/channels into `workspace/extracted/` and inspect each visually or
  statistically (entropy per plane) before assuming nothing is hidden.
- BMP file-size mismatch smaller than actual -> data was appended after the declared bitmap;
  same carving approach as PNG/JPEG trailing data.

## 5. Stop conditions

- Do not brute-force every possible LSB channel/bit-plane/stride combination exhaustively;
  start from the most common conventions (last bit of each byte, R/G/B channel order, row-major
  order) and stop once 2-3 conventional layouts have been tried with no legible result, then
  fall back to entropy/visual analysis to decide whether it is worth continuing.
- Cap password guesses against any password-protected companion archive at values already
  present elsewhere in the case evidence -- do not run an unbounded external wordlist locally.

## 6. Exact commands

```bash
bin/fstego cases/<case>/evidence/<file>.png --json
xxd cases/<case>/evidence/<file>.png | tail -20   # eyeball the tail once trailing_bytes is reported
```

Carving the exact trailing payload reported by `bin/fstego` (offset = file size minus
`trailing_bytes`):

```bash
bin/log-command <case> -- python3 -c "
import sys
data = open('cases/<case>/evidence/<file>.png', 'rb').read()
open('cases/<case>/workspace/extracted/trailing.bin', 'wb').write(data[<offset>:])
"
```

If `zsteg`/`stegseek` are confirmed present via `bin/tool-inventory` (both are absent locally):

```bash
bin/log-command <case> -- zsteg cases/<case>/evidence/<file>.png
```

## 7. Workspace output location

Carved trailing data, extracted bit planes, and any decoded channel image go under
`cases/<case>/workspace/extracted/`.

## 8. Artifact hash recording

```bash
bin/record-artifact <case> cases/<case>/workspace/extracted/trailing.bin --log-id <log-id>
```

## 9. Flag evidence and minimal reproduction

Tie a candidate to the exact chunk/segment/offset and the extraction command used:

```bash
bin/add-candidate <case> --flag <flag> --evidence cases/<case>/evidence/<file>.png \
  --locator '{"offset_after_iend": <offset>}' --transformation "carve trailing bytes after IEND" \
  --log-id <log-id>
```

## 10. Failure fallback

If native triage plus a manual trailing-data carve and a couple of conventional LSB attempts
find nothing, run `bin/flag-scan` over the raw evidence file (flags are sometimes stored as
plain ASCII inside a metadata chunk that the native parser reports but does not decode further).
If still nothing, check `bin/tool-inventory` and escalate to the remote server for
`binwalk`/`zsteg`/`stegseek` when they are unavailable locally.
