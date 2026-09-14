"""Archive triage: zip / tar(.gz|.bz2|.xz) / gzip / bzip2 / xz, stdlib-only.

``7z``, ``unzip -l``-quality tooling beyond the stdlib, and similar are not
assumed to be installed (confirmed absent on the reference host except for
``unzip``/``tar``/``gzip``/``bzip2``/``xz`` themselves, which this module
does not even shell out to -- Python's ``zipfile``/``tarfile``/``gzip``/
``bz2``/``lzma`` modules parse every format natively, so there is nothing
here that can report ``tool_missing``).
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import os
import secrets
import tarfile
import zipfile

from . import common

MAGIC_ZIP_PREFIXES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
MAGIC_GZIP = b"\x1f\x8b"
MAGIC_BZ2 = b"BZh"
MAGIC_XZ = b"\xfd7zXZ\x00"
TAR_MAGIC_OFFSET = 257
TAR_MAGICS = (b"ustar\x00", b"ustar  \x00")


def detect_format(prefix: bytes) -> str | None:
    if prefix.startswith(MAGIC_GZIP):
        return "gzip"
    if prefix.startswith(MAGIC_BZ2):
        return "bzip2"
    if prefix.startswith(MAGIC_XZ):
        return "xz"
    for zip_magic in MAGIC_ZIP_PREFIXES:
        if prefix.startswith(zip_magic):
            return "zip"
    if len(prefix) >= TAR_MAGIC_OFFSET + 8 and prefix[TAR_MAGIC_OFFSET:TAR_MAGIC_OFFSET + 6] in TAR_MAGICS:
        return "tar"
    return None


def _inspect_zip(path: str) -> common.TriageResult:
    warnings: list[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            bad = zf.testzip()
            if bad is not None:
                warnings.append(f"CRC check failed for member: {bad}")
            entries = []
            total_uncompressed = 0
            total_compressed = 0
            unsafe_members = []
            for info in zf.infolist():
                if common.safe_member_components(info.filename) is None and not info.is_dir():
                    unsafe_members.append(info.filename)
                entries.append({
                    "name": info.filename,
                    "is_dir": info.is_dir(),
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "encrypted": bool(info.flag_bits & 0x1),
                })
                total_uncompressed += info.file_size
                total_compressed += info.compress_size
            if unsafe_members:
                warnings.append(
                    f"{len(unsafe_members)} member path(s) rejected as path-traversal attempts "
                    f"(zip-slip): {unsafe_members[:5]}"
                )
            if total_compressed > 0 and total_uncompressed / max(total_compressed, 1) > common.BOMB_RATIO_WARNING:
                warnings.append(
                    f"suspicious compression ratio {total_uncompressed / max(total_compressed, 1):.0f}:1 "
                    "(possible zip bomb)"
                )
    except zipfile.BadZipFile as exc:
        return common.TriageResult(
            outcome="parser_failure", tool="zipfile",
            summary=f"failed to parse as ZIP: {exc}",
        )
    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="zipfile",
        summary=f"ZIP archive with {len(entries)} entr(y/ies), {total_uncompressed} bytes uncompressed",
        details={"entries": entries, "total_uncompressed": total_uncompressed, "total_compressed": total_compressed},
        warnings=warnings,
    )


def _inspect_tar(path: str) -> common.TriageResult:
    warnings: list[str] = []
    entries = []
    unsafe_members = []
    try:
        with tarfile.open(path, mode="r:*") as tf:
            for member in tf.getmembers():
                if common.safe_member_components(member.name) is None:
                    unsafe_members.append(member.name)
                if member.issym() or member.islnk():
                    target_components = common.safe_member_components(member.linkname)
                    if target_components is None:
                        unsafe_members.append(f"{member.name} -> {member.linkname}")
                entries.append({
                    "name": member.name,
                    "type": member.type.decode() if isinstance(member.type, bytes) else str(member.type),
                    "size": member.size,
                    "is_dev_or_special": member.isdev() if hasattr(member, "isdev") else False,
                })
        if unsafe_members:
            warnings.append(
                f"{len(unsafe_members)} member path(s) rejected as path-traversal/unsafe-link "
                f"attempts (tar-slip): {unsafe_members[:5]}"
            )
    except tarfile.TarError as exc:
        return common.TriageResult(
            outcome="parser_failure", tool="tarfile",
            summary=f"failed to parse as tar: {exc}",
        )
    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="tarfile",
        summary=f"tar archive with {len(entries)} entr(y/ies)",
        details={"entries": entries},
        warnings=warnings,
    )


_SINGLE_STREAM_OPENERS = {"gzip": gzip.open, "bzip2": bz2.open, "xz": lzma.open}
_PROBE_BYTES = 4 * 1024 * 1024  # bounded sniff of decompressed content; never fully inflate a bomb


def _inspect_single_stream(path: str, fmt: str) -> common.TriageResult:
    opener = _SINGLE_STREAM_OPENERS[fmt]
    try:
        with opener(path, "rb") as handle:
            probe = handle.read(_PROBE_BYTES)
            truncated = len(probe) == _PROBE_BYTES
    except (OSError, EOFError) as exc:
        return common.TriageResult(
            outcome="parser_failure", tool=fmt,
            summary=f"failed to decompress {fmt} stream: {exc}",
        )
    inner_format = detect_format(probe) or "unknown"
    warnings = []
    if truncated:
        warnings.append(
            f"decompressed content exceeds {_PROBE_BYTES} byte probe cap; only a prefix was inspected "
            "(bomb-safety limit, not a full decompression)"
        )
    return common.TriageResult(
        outcome="partial_success" if truncated else "full_success", tool=fmt,
        summary=f"{fmt} single-stream compressed data; inner content looks like: {inner_format}",
        details={"probed_bytes": len(probe), "inner_format": inner_format, "compressed_size": os.path.getsize(path)},
        warnings=warnings,
    )


def inspect(path: str) -> common.TriageResult:
    fd, st = common.open_input_safely(path)
    try:
        prefix = common.read_prefix(fd, TAR_MAGIC_OFFSET + 8)
    finally:
        os.close(fd)

    fmt = detect_format(prefix)
    if fmt is None:
        return common.TriageResult(
            outcome="input_mismatch", tool="archive-dispatch",
            summary="input does not match any recognized archive/compression magic bytes",
        )
    if fmt == "zip":
        return _inspect_zip(path)
    if fmt == "tar":
        return _inspect_tar(path)
    return _inspect_single_stream(path, fmt)


def extract(path: str, dest_dir: str, *, max_total_bytes: int = common.MAX_EXTRACT_TOTAL_BYTES) -> common.TriageResult:
    """Extract a zip/tar archive into ``dest_dir`` (must already exist).

    Refuses to extract single-stream gzip/bzip2/xz (no member list to
    validate against traversal -- callers should decompress those to a
    single named artifact instead) and enforces ``max_total_bytes`` as a
    hard cap against decompression bombs, aborting (partial extraction
    left in place, reported in ``details``) rather than silently
    truncating.
    """
    fd, _ = common.open_input_safely(path)
    try:
        prefix = common.read_prefix(fd, TAR_MAGIC_OFFSET + 8)
    finally:
        os.close(fd)
    fmt = detect_format(prefix)
    if fmt not in ("zip", "tar"):
        return common.TriageResult(
            outcome="input_mismatch", tool="archive-extract",
            summary=f"cannot extract format {fmt!r} as a member archive",
        )

    extracted: list[str] = []
    skipped: list[str] = []
    total = 0
    try:
        if fmt == "zip":
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    components = common.safe_member_components(info.filename)
                    if components is None:
                        skipped.append(info.filename)
                        continue
                    total += info.file_size
                    if total > max_total_bytes:
                        return common.TriageResult(
                            outcome="partial_success", tool="archive-extract",
                            summary=f"aborted extraction: total size exceeds {max_total_bytes} byte cap",
                            details={"extracted": extracted, "skipped_unsafe": skipped},
                            warnings=["possible decompression bomb; extraction stopped early"],
                        )
                    common.safe_extract_bytes(dest_dir, components, zf.read(info))
                    extracted.append("/".join(components))
        else:
            with tarfile.open(path, mode="r:*") as tf:
                for member in tf.getmembers():
                    if not member.isreg():
                        if member.name:
                            skipped.append(member.name)
                        continue
                    components = common.safe_member_components(member.name)
                    if components is None:
                        skipped.append(member.name)
                        continue
                    total += member.size
                    if total > max_total_bytes:
                        return common.TriageResult(
                            outcome="partial_success", tool="archive-extract",
                            summary=f"aborted extraction: total size exceeds {max_total_bytes} byte cap",
                            details={"extracted": extracted, "skipped_unsafe": skipped},
                            warnings=["possible decompression bomb; extraction stopped early"],
                        )
                    reader = tf.extractfile(member)
                    data = reader.read() if reader is not None else b""
                    common.safe_extract_bytes(dest_dir, components, data)
                    extracted.append("/".join(components))
    except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
        return common.TriageResult(
            outcome="parser_failure", tool="archive-extract",
            summary=f"extraction failed: {exc}",
            details={"extracted": extracted, "skipped_unsafe": skipped},
        )

    outcome = "partial_success" if skipped else "full_success"
    warnings = [f"{len(skipped)} unsafe/non-regular member(s) skipped: {skipped[:5]}"] if skipped else []
    return common.TriageResult(
        outcome=outcome, tool="archive-extract",
        summary=f"extracted {len(extracted)} file(s) to {dest_dir}",
        details={"extracted": extracted, "skipped_unsafe": skipped},
        warnings=warnings,
    )


_KNOWN_SUFFIXES = {"gzip": ".gz", "bzip2": ".bz2", "xz": ".xz"}


def _strip_known_suffix(basename: str, fmt: str) -> str:
    suffix = _KNOWN_SUFFIXES.get(fmt, "")
    if suffix and basename.lower().endswith(suffix):
        stripped = basename[: -len(suffix)]
        return stripped or f"decompressed{suffix}"
    return f"{basename}.decompressed"


def decompress_single_stream(
    path: str, dest_dir: str, *, max_bytes: int = common.MAX_EXTRACT_TOTAL_BYTES
) -> common.TriageResult:
    """Fully decompress a gzip/bzip2/xz single-stream file into ``dest_dir``.

    Unlike :func:`extract`, there is no member list to validate against
    traversal -- the format carries exactly one anonymous data stream --
    so this picks the output filename itself (the source basename with its
    compression suffix stripped, or the literal name plus
    ``.decompressed`` if no known suffix matches) and writes it the same
    symlink-safe way archive members are extracted. Bounded by
    ``max_bytes`` against decompression bombs, same as :func:`extract`;
    output is truncated (not aborted) so a partial artifact is still left
    for recursive analysis.
    """
    fd, _ = common.open_input_safely(path)
    try:
        prefix = common.read_prefix(fd, TAR_MAGIC_OFFSET + 8)
    finally:
        os.close(fd)
    fmt = detect_format(prefix)
    if fmt not in _SINGLE_STREAM_OPENERS:
        return common.TriageResult(
            outcome="input_mismatch", tool="archive-decompress",
            summary=f"cannot decompress format {fmt!r} as a single stream",
        )

    opener = _SINGLE_STREAM_OPENERS[fmt]
    truncated = False
    chunks: list[bytes] = []
    total = 0
    try:
        with opener(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    chunks.append(chunk[: max_bytes - (total - len(chunk))])
                    truncated = True
                    break
                chunks.append(chunk)
    except (OSError, EOFError) as exc:
        return common.TriageResult(
            outcome="parser_failure", tool=fmt,
            summary=f"failed to decompress {fmt} stream: {exc}",
        )

    data = b"".join(chunks)
    dest_name = _strip_known_suffix(os.path.basename(path), fmt)
    try:
        common.safe_extract_bytes(dest_dir, [dest_name], data)
    except FileExistsError:
        dest_name = f"{dest_name}.{secrets.token_hex(3)}"
        common.safe_extract_bytes(dest_dir, [dest_name], data)

    warnings = []
    if truncated:
        warnings.append(f"decompressed content exceeds {max_bytes} byte cap; output truncated (bomb-safety limit)")
    return common.TriageResult(
        outcome="partial_success" if truncated else "full_success", tool=fmt,
        summary=f"decompressed {fmt} stream to {dest_name} ({len(data)} bytes)",
        details={"dest_name": dest_name, "decompressed_bytes": len(data)},
        warnings=warnings,
    )
