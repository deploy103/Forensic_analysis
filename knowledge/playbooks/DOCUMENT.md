# Playbook: PDF/Office/OLE

## 1. Scope and input identification

Applies to PDF (`%PDF-` magic), legacy OLE/CFBF Office documents (`\xd0\xcf\x11\xe0\xa1\xb1
\x1a\xe1` magic -- old `.doc`/`.xls`/`.ppt`), and OOXML zip packages (`PK\x03\x04` that also
contains `[Content_Types].xml` -- modern `.docx`/`.xlsx`/`.pptx`). `bin/fdocument`
(`lib/pyforensic/triage/document.py`) tries PDF, then zip-as-OOXML, then OLE, in that order. A
zip that does **not** contain `[Content_Types].xml` is reported `input_mismatch` by the OOXML
check specifically so `bin/ftriage` falls through to `ARCHIVE.md`'s dispatch instead of this
wrapper silently swallowing a plain zip.

## 2. Evidence read-only principle

`bin/fdocument` only ever reads the evidence file (via `os.pread` for PDF/OLE, via `zipfile`
opened for reading for OOXML). Never open the evidence file with any Office/PDF application
that could resave/normalize it, and never let a macro-extraction step execute the macro --
extract the macro *source* only, into `workspace/extracted/`.

## 3. Initial observations

1. `sha256sum` the file and confirm against the manifest.
2. `bin/fdocument cases/<case>/evidence/<file> --json`:
   - PDF: version string, approximate object count, `%%EOF` marker count (more than one
     suggests incremental updates/appended edits), suspicious keys present
     (`/JavaScript`/`/JS`/`/OpenAction`/`/Launch`/`/EmbeddedFile`/`/RichMedia`), whether an
     `/Encrypt` dictionary is declared, and non-whitespace bytes after the final `%%EOF`.
   - OLE/CFBF: version, sector size, and a literal-substring heuristic hit for a
     `Macros`/`VBA` storage name (UTF-16LE) -- explicitly **not** a confirmed macro walk, since
     that needs `olevba` (confirmed absent locally).
   - OOXML: member list, any `vbaProject.bin` part (macro-enabled), and any member name
     rejected as unsafe/traversal-style.
3. Multiple `%%EOF` markers or trailing bytes after the last one are a strong, cheap signal --
   check those before anything else on a PDF.

## 4. Hypothesis branching

- Multiple `%%EOF` markers -> the file has incremental updates; the *earliest* revision may
  contain content removed in a later save. Locate each `%%EOF` offset and diff the object
  tables between revisions.
- Trailing bytes after the final `%%EOF` -> a second payload was appended after the logical PDF
  end, exactly like the PNG/JPEG trailing-data pattern in `IMAGE_STEGO.md` -- carve it out at
  the exact reported offset.
- `/Encrypt` present -> the PDF is password-protected; look for a password in other case
  evidence/notes before attempting anything more elaborate.
- `/JavaScript`/`/OpenAction`/`/Launch` present -> treat the document as potentially active
  content; extract and read the referenced JavaScript object's *bytes* only, never execute it
  (this also falls under the project-wide "never execute recovered executables/active content"
  rule).
- OLE macro heuristic hit, or OOXML `vbaProject.bin` present -> extract the macro storage bytes
  for manual/static reading; do not open the document in an application that would auto-run it.

## 5. Stop conditions

- Do not attempt a full CFBF FAT/directory-chain walk to decompress VBA source in this
  project's own code -- that duplicates `olevba`, confirmed absent locally; escalate rather
  than hand-rolling a partial CFBF parser under time pressure.
- Cap object-table diffing across incremental PDF updates at the number of `%%EOF` markers
  actually found; do not speculate about revisions beyond what the marker count supports.

## 6. Exact commands

```bash
bin/fdocument cases/<case>/evidence/<file>.pdf --json
```

Carving trailing bytes after the final `%%EOF` (offset reported by `bin/fdocument`):

```bash
bin/log-command <case> -- python3 -c "
data = open('cases/<case>/evidence/<file>.pdf', 'rb').read()
open('cases/<case>/workspace/extracted/trailing.bin', 'wb').write(data[<offset>:])
"
```

Extracting an OOXML macro part or any other zip member (never in place):

```bash
bin/log-command <case> -- python3 -c "
import zipfile
with zipfile.ZipFile('cases/<case>/evidence/<file>.docx') as zf:
    zf.extract('word/vbaProject.bin', 'cases/<case>/workspace/extracted')
"
```

If `olevba`/`pdfid`/`pdf-parser` are confirmed present via `bin/tool-inventory` (`olevba` is
confirmed absent locally):

```bash
bin/log-command <case> -- olevba cases/<case>/evidence/<file>.doc
```

## 7. Workspace output location

Carved trailing payloads, extracted macro storages, and any decoded object stream go under
`cases/<case>/workspace/extracted/`.

## 8. Artifact hash recording

```bash
bin/record-artifact <case> cases/<case>/workspace/extracted/vbaProject.bin --log-id <log-id>
```

## 9. Flag evidence and minimal reproduction

Tie a candidate to the exact object number/offset/zip-member path and the extraction command:

```bash
bin/add-candidate <case> --flag <flag> --evidence cases/<case>/evidence/<file>.pdf \
  --locator '{"offset_after_final_eof": <offset>}' --transformation "carve trailing bytes after %%EOF" \
  --log-id <log-id>
```

## 10. Failure fallback

If native triage plus a trailing-data carve find nothing, run `bin/flag-scan` over the raw
document (flags are sometimes stored as plain text inside an uncompressed PDF stream or an
OOXML XML part). For confirmed macro decompilation or PDF stream decompression beyond a literal
byte carve, escalate to the remote server for `olevba`/`pdf-parser`-class tooling rather than
reimplementing a PDF filter/CFBF walker locally.
