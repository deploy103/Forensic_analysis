# Forensic CTF Autonomous Solver baseline

This repository is a file-based working environment for analyzing authorized CTF and wargame forensic artifacts. It provides durable evidence-handling rules, isolated cases, structured command logging, focused triage helpers, final-result gates, and SSH access conventions. It does not install a forensic server or heavy tools.

All helpers can be invoked directly or through the discoverable `bin/forensic <command>` dispatcher. Run `bin/forensic help` for the command list.

## Solve (the fast path for CTF use)

For competition use, `bin/solve` is the only command you need. It creates a case, ingests the file, records its SHA-256, runs format-specific triage, recursively extracts and re-analyzes nested archives/compressed streams, scans everything for `FLAG{...}`/`DH{...}`/`CTF{...}`-shaped strings, ranks the candidates, and prints the result -- ending with a prominent `[FLAG]` block if one was found. All case bookkeeping is fully automatic; you never need to run `bin/new-case`, `bin/add-evidence`, `bin/triage-case`, `bin/flag-scan`, or `bin/case-report` yourself (they remain available for internal/debugging use).

```bash
bin/solve path/to/challenge.zip   # analyze a specific file
bin/solve                         # auto-pick the newest analyzable file in the current directory
bin/solve --latest                # auto-pick the newest file in ~/Downloads
```

`bin/solve` also makes (and logs) an execution-environment decision via `bin/nodes-status`'s discovery layer. With no configured remote nodes it executes locally; the ranking of any node an operator configures is still computed and recorded, but nothing is fabricated or claimed to run somewhere it did not.

## Quick start

Create a case and copy evidence into its write-protected evidence area:

```bash
bin/new-case challenge-01 /path/to/disk.img /path/to/capture.pcap
```

Case names use letters, digits, dots, underscores, and hyphens, and must begin with a letter or digit.

Add the problem statement to `cases/challenge-01/notes/case.md`. Run important commands through the logger:

```bash
bin/log-command challenge-01 -- file cases/challenge-01/evidence/disk.img
bin/log-command challenge-01 -- bin/ftriage cases/challenge-01/evidence/disk.img
```

Outputs go to `cases/<name>/logs/`; extracted artifacts, scripts, and dumps belong under `workspace/`. Track candidates and the final evidence chain in `result/`.

For independent work, give each analyst or automation process a bounded evidence path and a separate workspace output. An independent reviewer check is required before a final flag.

## Case layout

```text
cases/<name>/
├── evidence/                 # copied originals; never analyze by modifying in place
├── workspace/
│   ├── extracted/
│   ├── scripts/
│   └── dumps/
├── logs/                    # command index and combined stdout/stderr files
├── notes/                   # problem statement and evidence.sha256
└── result/                  # candidates, final result, minimal reproduction
```

Evidence payloads, extracted files, dumps, and raw command output are ignored by Git by default. Analyst-authored case scripts, notes, and result Markdown remain trackable.

## Forensic server

No server address or credential is known, so none was invented. Copy the block in `config/ssh_config.example` into your own `~/.ssh/config`, replace all placeholders, and verify it yourself:

```bash
ssh forensic 'uname -a'
bin/remote-exec command -v tshark
scp local-file forensic:/authorized/case/path/
rsync -av -- local-directory/ forensic:/authorized/case/path/
```

`bin/remote-exec` is intentionally a thin SSH wrapper. It shell-quotes the supplied argument vector before OpenSSH sends the remote command, applies batch mode and a timeout, and leaves key management and transfers to explicit helpers.
Use `bin/remote-exec --dry-run ...` to inspect the exact quoted command without connecting.

## Helpers

Solve:

- `bin/solve`: the single competition-facing command (see "Solve" above) -- analyzes a file end to end and prints the flag, if any.

Case lifecycle:

- `bin/new-case`: creates a complete case, copies supplied regular files, and records SHA-256 hashes.
- `bin/add-evidence`: safely adds later evidence without overwriting an existing filename.
- `bin/list-cases`: lists initialized cases for automation.
- `bin/case-status`: summarizes integrity, generated files, command outputs, and final-result state.
- `bin/case-doctor`: read-only diagnostic checks on a case (no mutation).
- `bin/triage-case`: verifies evidence, then runs format-agnostic triage per file and records an initial flag scan.
- `bin/case-report`: emits a portable, non-persisted Markdown report from case notes, manifests, review, result, and reproduction records.
- `bin/result-check`: enforces evidence/artifact integrity, a hash-bound reviewer verdict, tested reproduction, and final metadata before reporting a flag.

Integrity and records:

- `bin/verify-evidence`: checks every copied evidence file against the case manifest.
- `bin/record-artifact`: hashes a generated workspace file into the case artifact manifest.
- `bin/verify-artifacts`: verifies recorded generated files against their manifest.
- `bin/log-command`: runs an argument-safe command, streams its output, stores combined output, and appends both human-readable Markdown and machine-readable JSONL metadata. **The full argv and cwd are stored in `logs/commands.jsonl` in plaintext -- never pass a password, private key, or other secret as a command-line argument to `bin/log-command`.**
- `bin/flag-scan`: streaming, chunked (never mmap'd) flag-pattern search with hard per-file timeouts, reporting exact byte offsets; supports JSONL and custom-regex input, and caps matches by default.

Result gate (candidates -> review -> reproduction -> final):

- `bin/add-candidate`: records a flag candidate together with its evidence path, locator, and originating command-log entry.
- `bin/add-review`: records a reviewer verdict (`verified`/`rejected`/`needs-more-evidence`) over one or more candidates, hash-bound to the current manifests.
- `bin/set-reproduction`: records the minimal reproduction command for a candidate; rejects any command that did not exit zero.
- `bin/set-final`: binds a case's accepted final flag to a reviewed, reproduced candidate.

Focused triage — every wrapper below parses its format natively via the stdlib (no required external binary); optional tools such as `exiftool` or Volatility are only ever layered on top of the native result, never substituted for it:

- `bin/ftriage`: format-agnostic dispatch that tries each specific triage wrapper in turn and returns the first non-mismatch result.
- `bin/farchive`: zip/tar(.gz|.bz2|.xz)/gzip/bzip2/xz triage; flags zip-slip/tar-slip member names and decompression-bomb compression ratios.
- `bin/fpcap`: classic libpcap and pcapng triage via a native `struct`-based header/record walk (packet count, link type, time range, byte totals).
- `bin/fsqlite`: read-only SQLite triage (via the stdlib `sqlite3` module) covering schema inventory, row counts, and `PRAGMA integrity_check`.
- `bin/fstego`: native PNG/JPEG/BMP/GIF structural triage, including trailing-data-after-terminator detection.
- `bin/fmemory`: memory-image container triage (LiME/ELF-core/crash-dump/hibernation/AFF4), with an optional Volatility profile layered on top when installed.
- `bin/fdisk`: MBR/GPT partition-table triage plus bare-filesystem signature detection (ext2/3/4, NTFS, FAT12/16/32, ISO9660).
- `bin/fdocument`: PDF/legacy-OLE(CFBF)/OOXML document triage, including suspicious PDF key and macro-storage heuristics.

Environment and remote server:

- `bin/tool-inventory`: reports which baseline local forensic commands are installed without changing the system.
- `bin/remote-check`: displays non-secret alias resolution details and performs a bounded connectivity check.
- `bin/remote-exec`: runs an argument vector through the `forensic` SSH alias; `--dry-run` renders the exact quoted command without connecting.
- `bin/remote-copy`: performs explicit push/pull transfers with batch-mode SSH and a connection timeout; `--dry-run` renders without connecting.
- `bin/nodes-status`: internal/debugging -- reports every execution environment `bin/solve`'s scheduler currently sees (always at least `local`; any remote node listed in `config/nodes.json` is probed live and reported `UNAVAILABLE` rather than fabricated if it does not answer).

Run the self-contained checks with:

```bash
scripts/verify.sh
```

## Extending the baseline

Add concise tool notes under `knowledge/tools/` and evidence-driven procedures under `knowledge/playbooks/` using `TEMPLATE.md`. Add wrappers only after repeated cases demonstrate a stable need. Keep secrets and real server coordinates outside the repository.

The operational sequence is documented in `docs/case-workflow.md`; remote-host responsibilities are documented in `docs/server-contract.md`.
The stable case files and JSONL fields are documented in `docs/case-schema.md`.
