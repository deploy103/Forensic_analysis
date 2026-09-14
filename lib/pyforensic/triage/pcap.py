"""PCAP / PCAPNG triage: native struct-based header/record walk, stdlib-only.

``tshark`` and ``tcpdump`` are confirmed absent on the reference host, so
this wrapper does not shell out to either -- it parses both the classic
``libpcap`` file format and ``pcapng`` directly with :mod:`struct`,
producing a capinfos-style summary (packet count, link type, time range,
byte totals) without a protocol dissector. Anything beyond "how many
packets, what link type, what time range, does the file look intact" is
out of scope for a triage tool and belongs in a real dissector.
"""

from __future__ import annotations

import os
import struct

from . import common

MAGIC_PCAP_LE = 0xA1B2C3D4
MAGIC_PCAP_LE_NS = 0xA1B23C4D
MAGIC_PCAP_BE = 0xD4C3B2A1
MAGIC_PCAP_BE_NS = 0x4D3CB2A1
MAGIC_PCAPNG_SHB = 0x0A0D0D0A

GLOBAL_HEADER_LEN = 24
RECORD_HEADER_LEN = 16


def _classify_pcap_magic(magic: int) -> tuple[str, bool, bool] | None:
    """Return (endianness, nanosecond_resolution) or None if not a pcap magic."""
    if magic == MAGIC_PCAP_LE:
        return ("<", False)
    if magic == MAGIC_PCAP_LE_NS:
        return ("<", True)
    if magic == MAGIC_PCAP_BE:
        return (">", False)
    if magic == MAGIC_PCAP_BE_NS:
        return (">", True)
    return None


def _inspect_classic_pcap(fd: int, size: int) -> common.TriageResult:
    header = os.pread(fd, GLOBAL_HEADER_LEN, 0)
    if len(header) < GLOBAL_HEADER_LEN:
        return common.TriageResult(
            outcome="parser_failure", tool="pcap-native",
            summary=f"file is only {len(header)} bytes; too short for a pcap global header",
        )
    (magic,) = struct.unpack_from("<I", header, 0)
    classified = _classify_pcap_magic(magic)
    if classified is None:
        (magic_be,) = struct.unpack_from(">I", header, 0)
        classified = _classify_pcap_magic(magic_be)
    endian, nanosecond = classified
    version_major, version_minor, thiszone, sigfigs, snaplen, linktype = struct.unpack_from(
        endian + "HHiIII", header, 4)

    warnings = []
    packets = []
    offset = GLOBAL_HEADER_LEN
    total_captured = 0
    truncated = False
    while offset + RECORD_HEADER_LEN <= size:
        rec_header = os.pread(fd, RECORD_HEADER_LEN, offset)
        if len(rec_header) < RECORD_HEADER_LEN:
            truncated = True
            break
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from(endian + "IIII", rec_header, 0)
        offset += RECORD_HEADER_LEN
        if offset + incl_len > size:
            warnings.append(
                f"packet record at offset {offset - RECORD_HEADER_LEN} claims {incl_len} captured "
                f"bytes but only {size - offset} remain in the file (truncated capture)"
            )
            truncated = True
            break
        timestamp = ts_sec + (ts_frac / 1_000_000_000 if nanosecond else ts_frac / 1_000_000)
        packets.append({"timestamp": timestamp, "captured_len": incl_len, "original_len": orig_len})
        total_captured += incl_len
        offset += incl_len

    outcome = "partial_success" if (warnings or truncated) else "full_success"
    summary = (
        f"classic pcap, linktype={linktype}, snaplen={snaplen}, "
        f"{len(packets)} packet(s) parsed"
        + (" (truncated)" if truncated else "")
    )
    details = {
        "format": "pcap",
        "version": f"{version_major}.{version_minor}",
        "linktype": linktype,
        "snaplen": snaplen,
        "nanosecond_resolution": nanosecond,
        "packet_count": len(packets),
        "total_captured_bytes": total_captured,
        "first_timestamp": packets[0]["timestamp"] if packets else None,
        "last_timestamp": packets[-1]["timestamp"] if packets else None,
    }
    return common.TriageResult(outcome=outcome, tool="pcap-native", summary=summary, details=details, warnings=warnings)


_PCAPNG_BLOCK_NAMES = {
    0x0A0D0D0A: "section_header",
    0x00000001: "interface_description",
    0x00000002: "obsolete_packet",
    0x00000003: "simple_packet",
    0x00000004: "name_resolution",
    0x00000005: "interface_statistics",
    0x00000006: "enhanced_packet",
    0x00000009: "decryption_secrets",
}
_PACKET_BLOCK_TYPES = {0x00000002, 0x00000003, 0x00000006}


def _inspect_pcapng(fd: int, size: int) -> common.TriageResult:
    # Byte-order magic lives inside the Section Header Block body, 8 bytes
    # after the block starts (after block_type + block_total_length).
    probe = os.pread(fd, 12, 0)
    if len(probe) < 12:
        return common.TriageResult(
            outcome="parser_failure", tool="pcapng-native",
            summary=f"file is only {len(probe)} bytes; too short for a pcapng section header block",
        )
    (byte_order_magic,) = struct.unpack_from("<I", probe, 8)
    if byte_order_magic == 0x1A2B3C4D:
        endian = "<"
    else:
        (byte_order_magic_be,) = struct.unpack_from(">I", probe, 8)
        if byte_order_magic_be != 0x1A2B3C4D:
            return common.TriageResult(
                outcome="parser_failure", tool="pcapng-native",
                summary="section header block has an unrecognized byte-order magic",
            )
        endian = ">"

    warnings = []
    block_counts: dict[str, int] = {}
    linktypes: set[int] = set()
    offset = 0
    truncated = False
    while offset + 12 <= size:
        block_header = os.pread(fd, 12, offset)
        if len(block_header) < 12:
            truncated = True
            break
        block_type, block_total_length = struct.unpack_from(endian + "II", block_header, 0)
        if block_total_length < 12 or offset + block_total_length > size:
            warnings.append(f"block at offset {offset} has an invalid/truncated length {block_total_length}")
            truncated = True
            break
        name = _PCAPNG_BLOCK_NAMES.get(block_type, f"unknown(0x{block_type:08x})")
        block_counts[name] = block_counts.get(name, 0) + 1
        if block_type == 0x00000001:  # interface description block: linktype is first 2 bytes of body
            body = os.pread(fd, 2, offset + 8)
            if len(body) == 2:
                (linktype,) = struct.unpack_from(endian + "H", body, 0)
                linktypes.add(linktype)
        offset += block_total_length

    if offset < size and not truncated:
        warnings.append(
            f"{size - offset} trailing byte(s) after the last complete pcapng block "
            f"(offset {offset}); too short to form another block header"
        )
        truncated = True

    packet_count = sum(block_counts.get(name, 0) for t, name in _PCAPNG_BLOCK_NAMES.items() if t in _PACKET_BLOCK_TYPES)
    outcome = "partial_success" if (warnings or truncated) else "full_success"
    summary = f"pcapng, {packet_count} packet block(s), {sum(block_counts.values())} total block(s)"
    if truncated:
        summary += " (truncated)"
    details = {
        "format": "pcapng",
        "block_counts": block_counts,
        "packet_count": packet_count,
        "linktypes": sorted(linktypes),
    }
    return common.TriageResult(outcome=outcome, tool="pcapng-native", summary=summary, details=details, warnings=warnings)


def inspect(path: str) -> common.TriageResult:
    fd, st = common.open_input_safely(path)
    try:
        prefix = common.read_prefix(fd, 12)
        if len(prefix) < 4:
            return common.TriageResult(
                outcome="input_mismatch", tool="pcap-dispatch",
                summary="file too short to contain a pcap/pcapng magic number",
            )
        (magic_le,) = struct.unpack_from("<I", prefix, 0)
        if magic_le == MAGIC_PCAPNG_SHB:
            return _inspect_pcapng(fd, st.st_size)
        if _classify_pcap_magic(magic_le) is not None:
            return _inspect_classic_pcap(fd, st.st_size)
        (magic_be,) = struct.unpack_from(">I", prefix, 0)
        if _classify_pcap_magic(magic_be) is not None:
            return _inspect_classic_pcap(fd, st.st_size)
        return common.TriageResult(
            outcome="input_mismatch", tool="pcap-dispatch",
            summary="input does not match any recognized pcap/pcapng magic bytes",
        )
    finally:
        os.close(fd)
