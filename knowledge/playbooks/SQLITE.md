# Playbook: SQLite/WAL

## 1. Scope and input identification

Applies to files starting with the 16-byte magic `SQLite format 3\x00`. `bin/fsqlite`
(`lib/pyforensic/triage/sqlite.py`) uses Python's stdlib `sqlite3` module (which links the
same C library the absent `sqlite3` CLI would) -- never a shelled-out binary.

## 2. Evidence read-only principle

`bin/fsqlite` always opens the database via the URI `file:<path>?mode=ro&immutable=1`.
`immutable=1` tells SQLite the file will not change underneath it, so SQLite skips the
locking/journal machinery entirely and never creates a `-journal`/`-wal`/`-shm` file next to
the evidence copy. Never open the evidence database with a plain read-write connection, and
never run `PRAGMA journal_mode=...`/`VACUUM`/any `UPDATE`/`INSERT` against it.

## 3. Initial observations

1. `sha256sum` the `.sqlite`/`.db` file *and* any sibling `-wal`/`-shm`/`-journal` file, and
   record all of them as evidence (`bin/add-evidence`) -- a `-wal` file can contain committed-
   looking rows that are not yet visible in the main file's own pages.
2. `bin/fsqlite cases/<case>/evidence/<file> --json` -- reports page size, every
   table/view name, per-table row counts, `PRAGMA integrity_check(100)` results, and a warning
   if a sibling `-wal` file is present.
3. Treat any `integrity_check` result other than `["ok"]` as a signal, not noise -- it often
   points at exactly the page/table that was tampered with.

## 4. Hypothesis branching

- Sibling `-wal` present -> copy the main file and the `-wal` (and `-shm` if present) together
  into `workspace/` under their original relative names before querying, since SQLite needs
  them alongside each other to see WAL-only rows; querying the main file alone silently misses
  them.
- `integrity_check` reports issues -> look for a table with an unusually low row count relative
  to its schema, or freelist/page-count anomalies in `PRAGMA freelist_count`/`PRAGMA page_count`.
- A table's data looks encoded (base64/hex/binary blobs) -> that is a normal SQLite `BLOB`
  column; decode with a script, do not assume file corruption.

## 5. Stop conditions

- Do not attempt raw page-by-page carving of freelist/unallocated pages unless
  `integrity_check` or a row-count mismatch specifically motivates it -- carving every page of
  a large database "just in case" is unbounded work with no stop condition; instead carve only
  the specific pages implicated by an observation.
- Cap exploratory `SELECT` output at a bounded row count (e.g. `LIMIT 1000`) before deciding
  whether a table is relevant.

## 6. Exact commands

```bash
bin/fsqlite cases/<case>/evidence/<file>.sqlite --json
bin/log-command <case> -- python3 -c "
import sqlite3
conn = sqlite3.connect('file:cases/<case>/evidence/<file>.sqlite?mode=ro&immutable=1', uri=True)
for row in conn.execute('SELECT * FROM <table> LIMIT 1000'):
    print(row)
"
```

## 7. Workspace output location

Copies used for WAL-inclusive querying, and any exported query result, go under
`cases/<case>/workspace/extracted/`.

## 8. Artifact hash recording

```bash
bin/record-artifact <case> cases/<case>/workspace/extracted/<export>.csv --log-id <log-id>
```

## 9. Flag evidence and minimal reproduction

Tie a candidate to an exact table, rowid/primary key, and column, plus the exact query used:

```bash
bin/add-candidate <case> --flag <flag> --evidence cases/<case>/evidence/<file>.sqlite \
  --locator '{"table": "<name>", "rowid": 42, "column": "<name>"}' \
  --transformation "sqlite3 SELECT via immutable read-only URI" --log-id <log-id>
```

## 10. Failure fallback

If schema/data alone show nothing, re-run `bin/fsqlite` after copying the `-wal` file alongside
the main database (step 4 above) before concluding the database is clean. If deleted rows are
suspected, that requires page-level freelist carving beyond this project's stdlib scope --
escalate to the remote server for a dedicated SQLite forensics tool rather than hand-rolling an
unbounded page walker.
