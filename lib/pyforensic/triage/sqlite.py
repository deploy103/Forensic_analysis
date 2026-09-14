"""SQLite triage using the stdlib :mod:`sqlite3` module.

The ``sqlite3`` *CLI binary* is confirmed absent on the reference host,
but Python's stdlib ``sqlite3`` module links the same C library and is
always available, so this wrapper never reports ``tool_missing`` --
every SQLite triage capability is native.

The database is always opened with ``mode=ro&immutable=1`` in the
connection URI: ``immutable=1`` tells SQLite the file will not change
underneath it, so it skips the locking/journal machinery entirely and
never attempts to create a ``-journal``/``-wal``/``-shm`` file next to a
read-only evidence file (which would otherwise fail loudly, or -- worse,
if the evidence directory were ever briefly writable -- would mutate
state next to evidence).
"""

from __future__ import annotations

import os
import sqlite3

from . import common

MAGIC = b"SQLite format 3\x00"


def _check_sibling_wal(path: str) -> str | None:
    wal_path = path + "-wal"
    try:
        fd, st = common.open_input_safely(wal_path)
    except OSError:
        return None
    try:
        return f"WAL file present ({st.st_size} bytes) -- may contain uncommitted rows not visible in the main file"
    finally:
        os.close(fd)


def inspect(path: str) -> common.TriageResult:
    fd, st = common.open_input_safely(path)
    try:
        prefix = common.read_prefix(fd, 100)
    finally:
        os.close(fd)

    if not prefix.startswith(MAGIC):
        return common.TriageResult(
            outcome="input_mismatch", tool="sqlite3-native",
            summary="input does not start with the SQLite format 3 magic header",
        )

    import struct
    page_size, = struct.unpack_from(">H", prefix, 16)
    if page_size == 1:
        page_size = 65536  # header stores 1 to mean 65536 (value doesn't fit in u16)

    warnings = []
    uri = f"file:{path}?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.Error as exc:
        return common.TriageResult(
            outcome="parser_failure", tool="sqlite3-native",
            summary=f"failed to open as SQLite database: {exc}",
        )

    try:
        try:
            cursor = conn.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view')")
            objects = [{"name": name, "type": kind} for name, kind in cursor.fetchall()]
        except sqlite3.DatabaseError as exc:
            return common.TriageResult(
                outcome="parser_failure", tool="sqlite3-native",
                summary=f"could not read sqlite_master: {exc}",
                details={"page_size": page_size, "file_size": st.st_size},
            )

        table_counts = {}
        for obj in objects:
            if obj["type"] != "table":
                continue
            try:
                # obj["name"] comes from sqlite_master inside a possibly
                # adversarial evidence file, not from a trusted schema --
                # a table name containing a literal '"' could otherwise
                # break out of the quoted identifier (e.g. via a
                # same-statement UNION SELECT, since a single '"'.execute()'
                # call cannot stack a second ';'-separated statement) and
                # return a misleading count sourced from other tables.
                # Doubling embedded quotes is the standard SQL identifier
                # escape and closes that off.
                quoted_name = obj["name"].replace('"', '""')
                (count,) = conn.execute(f'SELECT COUNT(*) FROM "{quoted_name}"').fetchone()
                table_counts[obj["name"]] = count
            except sqlite3.DatabaseError as exc:
                warnings.append(f"could not count rows in table {obj['name']!r}: {exc}")

        try:
            integrity_rows = conn.execute("PRAGMA integrity_check(100)").fetchall()
            integrity_messages = [row[0] for row in integrity_rows]
        except sqlite3.DatabaseError as exc:
            integrity_messages = [f"integrity_check failed to run: {exc}"]

        if integrity_messages and integrity_messages != ["ok"]:
            warnings.append(f"integrity_check reported {len(integrity_messages)} issue(s)")
    finally:
        conn.close()

    wal_note = _check_sibling_wal(path)
    if wal_note:
        warnings.append(wal_note)

    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="sqlite3-native",
        summary=f"SQLite database, {len(objects)} table/view(s), page_size={page_size}",
        details={
            "page_size": page_size,
            "file_size": st.st_size,
            "objects": objects,
            "table_row_counts": table_counts,
            "integrity_check": integrity_messages,
        },
        warnings=warnings,
    )
