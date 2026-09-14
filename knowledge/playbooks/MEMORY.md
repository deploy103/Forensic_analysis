# Playbook: Memory image/Volatility

## 1. Scope and input identification

Applies to raw physical-memory dumps and known container formats: LiME (`EMiL` magic), ELF
core dumps (`\x7fELF`), Windows crash dumps (`PAGEDU64`/`PAGEDUMP`), and Windows hibernation
files (`hibr`/`HIBR`/`wake`). A raw `dd`-style dump with none of these headers is the *common*
case, not an error -- `bin/fmemory` (`lib/pyforensic/triage/memory.py`) reports it as
`format: raw/unidentified` with a warning, still returning size and sampled entropy.

## 2. Evidence read-only principle

`bin/fmemory` samples at most the first 1 MiB via a read-only fd and never writes to the image.
Any process/object dump produced by a plugin must land under `workspace/dumps/`, never back
into the evidence file, and the evidence file itself is never passed to a plugin in a mode that
could write to it.

## 3. Initial observations

1. `sha256sum` the image; record acquisition metadata (source host, tool, timestamp) in
   `notes/case.md` if known.
2. `bin/fmemory cases/<case>/evidence/<file> --json` -- reports container format, file size,
   and Shannon entropy of the first-MiB sample (a near-8.0 sample entropy on a supposedly raw
   memory dump can indicate the image is actually compressed or encrypted).
3. Note whether Volatility (`vol.py`/`vol`/`volatility`) was detected on `PATH` -- confirmed
   absent on the reference host; `bin/fmemory` reports this as a warning, not a failure, since
   its own native container identification never depends on it.

## 4. Hypothesis branching

- `format: raw/unidentified` with normal (not near-8.0) entropy -> proceed as a genuine raw
  physical dump; profile/OS identification will require Volatility on the remote server.
- `format: lime` -> record the LiME header's version and start/end address range; that address
  range is the physical-address window Volatility needs for a correct profile.
- Sample entropy near 8.0 -> hypothesize compression/encryption before spending time on
  plugin-based analysis; confirm by running `bin/farchive`/`bin/fdisk`-style magic checks
  against the same file first.
- Volatility available and returns an OS/profile guess -> record the exact command and output
  in `logs/commands.md`/`commands.jsonl` via `bin/log-command`, since profile selection is
  itself a finding that must be reproducible.

## 5. Stop conditions

- Do not attempt every Volatility plugin against every process; start from a specific
  hypothesis (a suspicious process name/parent relationship/open handle/network connection)
  before dumping.
- Cap process/file dumps to what is directly implicated by an observation -- dumping every
  process's memory "to be thorough" has no natural stop condition and will exhaust workspace
  disk space on a large image.

## 6. Exact commands

```bash
bin/fmemory cases/<case>/evidence/<file> --json
bin/tool-inventory --json   # confirm whether vol.py/vol/volatility is present before relying on it
```

If Volatility is confirmed present via `bin/tool-inventory`:

```bash
bin/log-command <case> -- vol.py -f cases/<case>/evidence/<file> imageinfo
bin/log-command <case> -- vol.py -f cases/<case>/evidence/<file> --profile=<profile> pslist
bin/log-command <case> -- vol.py -f cases/<case>/evidence/<file> --profile=<profile> procdump -p <pid> -D cases/<case>/workspace/dumps
```

## 7. Workspace output location

Every dumped process, file, or extracted object goes under `cases/<case>/workspace/dumps/`.

## 8. Artifact hash recording

```bash
bin/record-artifact <case> cases/<case>/workspace/dumps/<pid>.exe --log-id <log-id>
```

## 9. Flag evidence and minimal reproduction

Tie a candidate to a specific process/PID, address/object, and the plugin invocation that
extracted it:

```bash
bin/add-candidate <case> --flag <flag> --evidence cases/<case>/workspace/dumps/<pid>.exe \
  --locator '{"pid": 1234, "plugin": "procdump"}' --transformation "Volatility procdump" --log-id <log-id>
```

## 10. Failure fallback

If no known container magic is found and Volatility is unavailable locally, escalate to the
remote `forensic` server for full plugin-based analysis rather than guessing an OS profile
manually. If sample entropy suggests the image is itself compressed/encrypted, first pursue
`ARCHIVE.md`/password-recovery leads before returning to memory analysis.
