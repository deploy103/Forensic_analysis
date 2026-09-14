"""Disk/filesystem-image triage: native MBR/GPT/filesystem-signature walk.

``mmls``, ``fls``, and ``testdisk`` (The Sleuth Kit / TestDisk) are
confirmed absent on the reference host, so partition-table parsing is
done natively against the documented MBR and GPT on-disk layouts via
:mod:`struct`. This does not replace a real filesystem parser (no NTFS
MFT walk, no ext inode walk) -- it identifies *what* is present
(partition table type, partition types/offsets/sizes, or a bare
filesystem's own signature for un-partitioned images) so an analyst
knows where to point more specific tools next.
"""

from __future__ import annotations

import os
import struct

from . import common

SECTOR_SIZE_ASSUMED = 512
MBR_SIGNATURE = b"\x55\xaa"
GPT_SIGNATURE = b"EFI PART"

MBR_PARTITION_TYPES = {
    0x00: "empty", 0x05: "extended", 0x0B: "FAT32", 0x0C: "FAT32 LBA",
    0x07: "NTFS/exFAT", 0x82: "Linux swap", 0x83: "Linux", 0x8E: "Linux LVM",
    0xEE: "GPT protective", 0xEF: "EFI system",
}


def _parse_mbr_partitions(sector0: bytes) -> list[dict]:
    partitions = []
    for i in range(4):
        entry = sector0[446 + i * 16: 446 + (i + 1) * 16]
        status, ptype = entry[0], entry[4]
        start_lba, num_sectors = struct.unpack_from("<II", entry, 8)
        if ptype == 0x00 and start_lba == 0 and num_sectors == 0:
            continue
        partitions.append({
            "index": i,
            "bootable": status == 0x80,
            "type_byte": f"0x{ptype:02X}",
            "type_name": MBR_PARTITION_TYPES.get(ptype, "unknown"),
            "start_lba": start_lba,
            "sector_count": num_sectors,
            "approx_bytes": num_sectors * SECTOR_SIZE_ASSUMED,
        })
    return partitions


def _parse_gpt(fd: int, size: int) -> dict | None:
    header = os.pread(fd, 92, 512)
    if len(header) < 92 or header[:8] != GPT_SIGNATURE:
        return None
    (revision, header_size, _crc, _reserved, current_lba, backup_lba, first_usable, last_usable) = \
        struct.unpack_from("<IIIIQQQQ", header, 8)
    disk_guid = header[56:72].hex()
    part_entry_lba, num_entries, entry_size, _entries_crc = struct.unpack_from("<QIII", header, 72)

    partitions = []
    entries_bytes = num_entries * entry_size
    if part_entry_lba * SECTOR_SIZE_ASSUMED + entries_bytes <= size:
        raw = os.pread(fd, entries_bytes, part_entry_lba * SECTOR_SIZE_ASSUMED)
        for i in range(num_entries):
            entry = raw[i * entry_size:(i + 1) * entry_size]
            if len(entry) < 56 or entry[:16] == b"\x00" * 16:
                continue
            type_guid = entry[0:16].hex()
            start_lba, end_lba = struct.unpack_from("<QQ", entry, 32)
            name_utf16 = entry[56:56 + 72]
            name = name_utf16.decode("utf-16-le", errors="replace").rstrip("\x00")
            partitions.append({
                "index": i,
                "type_guid": type_guid,
                "start_lba": start_lba,
                "end_lba": end_lba,
                "sector_count": end_lba - start_lba + 1 if end_lba >= start_lba else 0,
                "name": name,
            })
    return {
        "revision": revision,
        "disk_guid": disk_guid,
        "current_lba": current_lba,
        "backup_lba": backup_lba,
        "usable_lba_range": [first_usable, last_usable],
        "partitions": partitions,
    }


def _detect_bare_filesystem(fd: int, size: int) -> dict | None:
    if size >= 1080 + 2:
        superblock = os.pread(fd, 2, 1024 + 56)
        if superblock == b"\x53\xef":
            return {"filesystem": "ext2/3/4", "detail": "ext superblock magic found at offset 1080"}
    boot = os.pread(fd, 90, 0)
    if len(boot) >= 90:
        if boot[3:11] == b"NTFS    ":
            return {"filesystem": "NTFS", "detail": "NTFS OEM ID found in boot sector"}
        for off in (54, 82):
            if boot[off:off + 8].startswith((b"FAT12", b"FAT16", b"FAT32")):
                return {"filesystem": "FAT", "detail": f"FAT type string found at boot-sector offset {off}"}
    if size >= 0x8001 + 5:
        iso = os.pread(fd, 5, 0x8001)
        if iso == b"CD001":
            return {"filesystem": "ISO9660", "detail": "CD001 standard identifier found at sector 16"}
    return None


def inspect(path: str) -> common.TriageResult:
    fd, st = common.open_input_safely(path)
    try:
        if st.st_size < 512:
            return common.TriageResult(
                outcome="input_mismatch", tool="disk-native",
                summary=f"file is only {st.st_size} bytes; too small to contain a boot sector",
            )
        sector0 = os.pread(fd, 512, 0)
        warnings: list[str] = []

        if sector0[510:512] == MBR_SIGNATURE:
            partitions = _parse_mbr_partitions(sector0)
            has_protective = any(p["type_byte"] == "0xEE" for p in partitions)
            details = {"table": "mbr", "partitions": partitions,
                       "sector_size_assumed": SECTOR_SIZE_ASSUMED}
            if has_protective:
                gpt = _parse_gpt(fd, st.st_size)
                if gpt is not None:
                    details["table"] = "gpt"
                    details["gpt"] = gpt
                else:
                    warnings.append("MBR indicates a GPT protective partition but no valid GPT header was found at LBA1")
            outcome = "partial_success" if warnings else "full_success"
            table_kind = details["table"].upper()
            count = len(details.get("gpt", {}).get("partitions", partitions))
            return common.TriageResult(
                outcome=outcome, tool="disk-native",
                summary=f"{table_kind} partition table, {count} partition(s)",
                details=details, warnings=warnings,
            )

        bare_fs = _detect_bare_filesystem(fd, st.st_size)
        if bare_fs is not None:
            return common.TriageResult(
                outcome="full_success", tool="disk-native",
                summary=f"no partition table; bare {bare_fs['filesystem']} filesystem image",
                details=bare_fs,
            )

        return common.TriageResult(
            outcome="input_mismatch", tool="disk-native",
            summary="no MBR/GPT signature and no recognized bare-filesystem signature found",
        )
    finally:
        os.close(fd)
