"""Image/steganography triage: native PNG/JPEG/BMP structure walk, stdlib-only.

No image library (Pillow etc.) is a project dependency -- this project
installs nothing beyond the stdlib -- so parsing is done directly against
each format's documented byte layout via :mod:`struct`. ``exiftool`` and
``binwalk`` are confirmed absent on the reference host; when present
(detected via ``PATH``, exercised in tests through a shim) they are run
as an *additional* metadata source layered on top of the native
structural result, never as the only source, so this wrapper degrades to
``partial_success`` rather than ``tool_missing`` when they are absent --
the native parser's most important finding (trailing data appended after
the format's own logical end-of-file marker, a classic CTF hiding spot)
never depends on them.
"""

from __future__ import annotations

import os
import struct

from . import common

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC = b"\xff\xd8"
BMP_MAGIC = b"BM"
GIF_MAGICS = (b"GIF87a", b"GIF89a")


def _inspect_png(data: bytes) -> common.TriageResult:
    warnings = []
    chunks = []
    offset = len(PNG_MAGIC)
    ihdr = None
    iend_end = None
    while offset + 8 <= len(data):
        (length,) = struct.unpack_from(">I", data, offset)
        chunk_type = data[offset + 4:offset + 8].decode("latin-1")
        chunk_start = offset
        offset += 8
        if offset + length + 4 > len(data):
            warnings.append(f"chunk {chunk_type!r} at offset {chunk_start} is truncated")
            break
        chunk_data = data[offset:offset + length]
        offset += length + 4  # skip data + CRC
        chunks.append({"type": chunk_type, "length": length})
        if chunk_type == "IHDR" and ihdr is None:
            width, height, bit_depth, color_type = struct.unpack_from(">IIBB", chunk_data, 0)
            ihdr = {"width": width, "height": height, "bit_depth": bit_depth, "color_type": color_type}
        if chunk_type == "IEND":
            iend_end = offset
            break

    if ihdr is None:
        return common.TriageResult(
            outcome="parser_failure", tool="png-native",
            summary="no IHDR chunk found; not a well-formed PNG",
            details={"chunks": chunks},
        )

    trailing = len(data) - iend_end if iend_end is not None else None
    if iend_end is None:
        warnings.append("no IEND chunk found; file is truncated or not a well-formed PNG")
    elif trailing:
        warnings.append(f"{trailing} byte(s) of data appended after IEND (possible hidden/appended payload)")

    text_chunks = [c["type"] for c in chunks if c["type"] in ("tEXt", "zTXt", "iTXt")]
    if text_chunks:
        warnings.append(f"text metadata chunk(s) present: {text_chunks}")

    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="png-native",
        summary=f"PNG {ihdr['width']}x{ihdr['height']}, {len(chunks)} chunk(s)"
                + (f", {trailing} trailing byte(s)" if trailing else ""),
        details={"ihdr": ihdr, "chunks": chunks, "trailing_bytes": trailing},
        warnings=warnings,
    )


_JPEG_MARKERS_WITHOUT_LENGTH = {0xD8, 0xD9} | set(range(0xD0, 0xD8))  # SOI, EOI, RSTn have no length field


def _inspect_jpeg(data: bytes) -> common.TriageResult:
    warnings = []
    segments = []
    offset = 2  # past SOI
    eoi_end = None
    while offset + 1 < len(data):
        if data[offset] != 0xFF:
            # Entropy-coded scan data between SOS and the next marker is not
            # itself marker-framed; resync by scanning for the next 0xFF
            # that isn't a stuffing byte (0xFF00) or a restart marker.
            next_marker = data.find(b"\xff", offset)
            if next_marker == -1:
                warnings.append("no EOI marker found; file is truncated or not a well-formed JPEG")
                break
            offset = next_marker
            continue
        marker = data[offset + 1]
        if marker == 0x00 or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        if marker == 0xD9:  # EOI
            eoi_end = offset + 2
            break
        if offset + 4 > len(data):
            warnings.append(f"marker 0xFF{marker:02X} at offset {offset} is truncated")
            break
        (seg_len,) = struct.unpack_from(">H", data, offset + 2)
        segments.append({"marker": f"0xFF{marker:02X}", "length": seg_len})
        offset += 2 + seg_len

    if eoi_end is None:
        return common.TriageResult(
            outcome="partial_success", tool="jpeg-native",
            summary=f"JPEG with {len(segments)} segment(s), no EOI found (truncated)",
            details={"segments": segments},
            warnings=warnings or ["no EOI marker found"],
        )

    trailing = len(data) - eoi_end
    if trailing:
        warnings.append(f"{trailing} byte(s) of data appended after EOI (possible hidden/appended payload)")

    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="jpeg-native",
        summary=f"JPEG with {len(segments)} segment(s)" + (f", {trailing} trailing byte(s)" if trailing else ""),
        details={"segments": segments, "trailing_bytes": trailing},
        warnings=warnings,
    )


def _inspect_bmp(data: bytes) -> common.TriageResult:
    if len(data) < 26:
        return common.TriageResult(outcome="parser_failure", tool="bmp-native", summary="file too short for a BMP header")
    file_size_field, reserved, pixel_offset = struct.unpack_from("<III", data, 2)
    dib_header_size, width, height = struct.unpack_from("<Iii", data, 14)
    warnings = []
    if file_size_field != len(data):
        warnings.append(f"BMP header file-size field ({file_size_field}) does not match actual file size ({len(data)})")
    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="bmp-native",
        summary=f"BMP, header claims {width}x{height}",
        details={
            "header_file_size": file_size_field,
            "actual_file_size": len(data),
            "pixel_data_offset": pixel_offset,
            "dib_header_size": dib_header_size,
        },
        warnings=warnings,
    )


def _inspect_gif(data: bytes) -> common.TriageResult:
    trailing = None
    trailer_pos = data.rfind(b"\x3b")
    if trailer_pos != -1 and trailer_pos < len(data) - 1:
        trailing = len(data) - trailer_pos - 1
    warnings = [f"{trailing} byte(s) found after the GIF trailer (0x3B)"] if trailing else []
    return common.TriageResult(
        outcome="partial_success" if warnings else "full_success", tool="gif-native",
        summary=f"GIF, {len(data)} bytes" + (f", {trailing} trailing byte(s)" if trailing else ""),
        details={"trailing_bytes": trailing},
        warnings=warnings,
    )


def _augment_with_external_tools(result: common.TriageResult, path: str) -> common.TriageResult:
    for tool in ("exiftool", "binwalk"):
        if not common.tool_available(tool):
            continue
        try:
            argv = [tool, "-j", path] if tool == "exiftool" else [tool, path]
            proc = common.run_tool(argv, timeout=30)
        except Exception as exc:  # external tool failures never override the native result
            result.warnings.append(f"{tool} failed to run: {exc}")
            continue
        if proc is not None and proc.returncode == 0:
            result.details[f"{tool}_output"] = proc.stdout.decode("utf-8", errors="replace")
    return result


def inspect(path: str) -> common.TriageResult:
    fd, st = common.open_input_safely(path)
    try:
        data = os.pread(fd, st.st_size, 0)
    finally:
        os.close(fd)

    if data.startswith(PNG_MAGIC):
        result = _inspect_png(data)
    elif data.startswith(JPEG_MAGIC):
        result = _inspect_jpeg(data)
    elif data.startswith(BMP_MAGIC):
        result = _inspect_bmp(data)
    elif any(data.startswith(m) for m in GIF_MAGICS):
        result = _inspect_gif(data)
    else:
        return common.TriageResult(
            outcome="input_mismatch", tool="image-dispatch",
            summary="input does not match any recognized image magic bytes (PNG/JPEG/BMP/GIF)",
        )
    return _augment_with_external_tools(result, path)
