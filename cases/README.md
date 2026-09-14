# Cases

Create cases with `bin/new-case`; do not copy `.template` manually. Each case owns its evidence, workspace, logs, notes, and result records.

The repository intentionally ignores evidence payloads, extracted files, dumps, and raw `.log` output. This prevents accidental Git commits but is not a backup or access-control mechanism. Analyst-authored workspace scripts, manifests, JSONL command metadata, notes, and result Markdown remain trackable.

Never place unrelated or unauthorized material here. Use `bin/verify-evidence` before analysis and before final reporting.

