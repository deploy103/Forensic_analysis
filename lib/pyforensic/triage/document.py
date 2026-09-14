"""Document triage: PDF / legacy OLE (CFBF) / OOXML zip, stdlib-only.

``olevba`` is confirmed absent on the reference host. Every check in
this module uses only literal ``bytes.find``/``in`` substring search
(never a regex) precisely so it carries none of the catastrophic-
backtracking risk that motivated the bounded, timeout-protected engine
in :mod:`pyforensic.flagscan` -- a document triage wrapper has no
business running arbitrary patterns against attacker-supplied bytes.
"""

from __future__ import annotations

import os
import zipfile

from . import common

PDF_MAGIC = b"%PDF-"
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PDF_SUSPICIOUS_KEYS = (b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/EmbeddedFile", b"/RichMedia")


def _inspect_pdf(data: bytes) -> common.TriageResult:
    warnings = []
    version = data[len(PDF_MAGIC):len(PDF_MAGIC) + 4].split(b"\r")[0].split(b"\n")[0].decode("ascii", errors="replace")

    obj_count = 0
    search_from = 0
    while True:
        idx = data.find(b" obj", search_from)
        if idx == -1:
            break
        obj_count += 1
        search_from = idx + 4

    eof_count = data.count(b"%%EOF")
    if eof_count > 1:
        warnings.append(f"{eof_count} '%%EOF' markers found (incremental updates / possible appended edits)")

    found_keys = [key.decode() for key in PDF_SUSPICIOUS_KEYS if key in data]
    if found_keys:
        warnings.append(f"suspicious/active-content keys present: {found_keys}")

    encrypted = b"/Encrypt" in data
    if encrypted:
        warnings.append("document declares an /Encrypt dictionary (password protected)")

    trailing = None
    last_eof = data.rfind(b"%%EOF")
    if last_eof != -1:
        after = data[last_eof + len(b"%%EOF"):]
        stripped = after.strip(b"\r\n\x00 ")
        if stripped:
            trailing = len(after)
            warnings.append(f"{trailing} byte(s) of non-whitespace data after the final %%EOF")

    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="pdf-native",
        summary=f"PDF version {version}, ~{obj_count} object(s)",
        details={
            "version": version, "approx_object_count": obj_count, "eof_marker_count": eof_count,
            "suspicious_keys": found_keys, "encrypted": encrypted, "trailing_bytes": trailing,
        },
        warnings=warnings,
    )


def _inspect_ole(data: bytes) -> common.TriageResult:
    warnings = []
    if len(data) < 512:
        return common.TriageResult(outcome="parser_failure", tool="ole-native", summary="file too short for a CFBF header")
    minor, major = int.from_bytes(data[24:26], "little"), int.from_bytes(data[26:28], "little")
    sector_shift = int.from_bytes(data[30:32], "little")
    mini_sector_shift = int.from_bytes(data[32:34], "little")

    # Heuristic, not authoritative: real macro detection requires walking
    # the CFBF FAT/directory chain to decompress the VBA storage, which
    # needs olevba (absent here). A literal-substring check on the "Macros"
    # / "VBA" directory-entry names (stored as UTF-16LE) still reliably
    # flags most macro-enabled legacy Office files without that walk.
    macro_hint = b"M\x00a\x00c\x00r\x00o\x00s\x00" in data or b"V\x00B\x00A\x00" in data
    if macro_hint:
        warnings.append("literal-substring heuristic suggests a VBA/Macros storage may be present (unconfirmed without a full CFBF walk)")

    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="ole-native",
        summary=f"legacy OLE/CFBF document, version {major}.{minor}, sector_size={1 << sector_shift}",
        details={
            "major_version": major, "minor_version": minor,
            "sector_size": 1 << sector_shift, "mini_sector_size": 1 << mini_sector_shift,
            "macro_heuristic_hit": macro_hint,
        },
        warnings=warnings,
    )


def _inspect_ooxml(path: str) -> common.TriageResult:
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile as exc:
        return common.TriageResult(outcome="parser_failure", tool="ooxml-native", summary=f"failed to parse as OOXML zip: {exc}")

    if "[Content_Types].xml" not in names:
        # [Content_Types].xml is the one file every OOXML package (docx/
        # xlsx/pptx) is required to have. Its absence means this is just a
        # generic zip that happens to share the PK magic, not an OOXML
        # document -- report input_mismatch so dispatch.py falls through
        # to archive.py, which is the module that actually checks
        # compression-ratio bombs and covers zip-slip with the full
        # archive-triage warning set (this module only screens member
        # names, not bomb ratio). Returning partial_success here instead
        # would make every non-OOXML zip get silently swallowed by this
        # wrapper before archive.py ever saw it, since document.py is
        # tried first in dispatch order.
        return common.TriageResult(
            outcome="input_mismatch", tool="document-dispatch",
            summary="zip does not contain [Content_Types].xml; not an OOXML package",
        )

    warnings = []
    macro_parts = [n for n in names if n.endswith("vbaProject.bin")]
    if macro_parts:
        warnings.append(f"macro-enabled: {macro_parts}")
    unsafe = [n for n in names if common.safe_member_components(n) is None]
    if unsafe:
        warnings.append(f"{len(unsafe)} member path(s) with unsafe/traversal-style names: {unsafe[:5]}")

    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="ooxml-native",
        summary=f"OOXML zip package, {len(names)} member(s)" + (", macro-enabled" if macro_parts else ""),
        details={"members": names, "macro_parts": macro_parts},
        warnings=warnings,
    )


def inspect(path: str) -> common.TriageResult:
    fd, st = common.open_input_safely(path)
    try:
        prefix = common.read_prefix(fd, 8)
        is_zip = prefix.startswith(b"PK\x03\x04") or prefix.startswith(b"PK\x05\x06")
        if not is_zip and not prefix.startswith(PDF_MAGIC) and not prefix.startswith(OLE_MAGIC):
            return common.TriageResult(
                outcome="input_mismatch", tool="document-dispatch",
                summary="input does not match PDF, OLE/CFBF, or zip (OOXML) magic bytes",
            )
        if prefix.startswith(PDF_MAGIC):
            data = os.pread(fd, st.st_size, 0)
        else:
            data = None
    finally:
        os.close(fd)

    if data is not None:
        return _inspect_pdf(data)
    if is_zip:
        return _inspect_ooxml(path)

    fd, st = common.open_input_safely(path)
    try:
        ole_data = os.pread(fd, st.st_size, 0)
    finally:
        os.close(fd)
    return _inspect_ole(ole_data)
