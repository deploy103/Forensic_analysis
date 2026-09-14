# Case workflow

For ordinary CTF use, `bin/solve [FILE | --latest]` runs steps 1-2 (and a bounded, recursive version of step 3's generic analysis) automatically and prints a ranked flag candidate. The manual workflow below remains the internal/debugging path and is still required to reach the reviewed, reproduced final gate in step 5.

## 1. Intake

```bash
bin/new-case <case> <evidence...>
bin/verify-evidence <case>
```

Copy the authorized problem statement into `notes/case.md`. If evidence arrives later, use `bin/add-evidence`; do not place or overwrite files manually. Record relevant acquisition/source context without committing secrets.

## 2. Initial triage

```bash
bin/triage-case <case>
bin/case-status <case>
```

Review detected types, bounded strings, initial flag matches, and optional format-specific summaries. A match is only a candidate until its exact source and transformations are validated.

## 3. Specialist analysis

Delegate independent work only when it materially helps. Each task should name the case, evidence file, question, expected output, and workspace ownership. Use `bin/log-command` for important commands and `bin/record-artifact` for material outputs.

```bash
bin/log-command <case> -- <tool> <arguments...>
bin/record-artifact <case> cases/<case>/workspace/extracted/<file>
```

`bin/log-command` stores the full argv and cwd in `logs/commands.jsonl` in plaintext -- never
pass a password, decryption key, or other secret as a command-line argument.

For unavailable heavy tooling, configure the personal `forensic` SSH alias and use the bounded remote helpers. Keep remote destinations inside the authorized case directory.

## 4. Candidate and review

Record each candidate with its evidence path, byte locator, transformation, and the `log-command` entry that produced it -- never hand-edit `result/candidates.jsonl` itself:

```bash
bin/add-candidate <case> --flag <flag> --evidence <path> --locator '<json-object>' \
  --transformation <description> --log-id <log-id>
```

`--locator` must be a JSON *object* (e.g. `'{"offset": 42}'`), not a bare string or number -- it is parsed and stored as a structured value, not free text.

Ask an independent reviewer to reproduce the chain and record their own verdict rather than merely agreeing:

```bash
bin/add-review <case> --reviewer <name> --verdict verified --candidate <candidate-id>
```

A review's hash binding to the evidence/artifact manifests and `candidates.jsonl` is snapshotted at review time; any of those three files changing afterward makes `bin/result-check` report the review as stale, so run review after the evidence chain and candidate list are settled.

## 5. Final gate

Record the minimal, actually-executed reproduction (rejected unless the referenced logged command exited zero), then bind the final flag to the reviewed candidate:

```bash
bin/set-reproduction <case> --candidate <candidate-id> --log-id <log-id> --summary <summary>
bin/set-final <case> --candidate <candidate-id>
bin/verify-evidence <case>
bin/verify-artifacts <case>
bin/result-check <case>
```

To keep a report snapshot, redirect it outside the case tree (`bin/case-report` never writes into the case itself, and never save one under `cases/<case>/result/` -- a later report generation would fold the previous report back into itself):

```bash
bin/case-report <case> > /tmp/<case>-report.md
```

Do not report a final flag when the gate fails. Preserve the failed candidate and explain what evidence remains missing.
