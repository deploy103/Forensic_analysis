# Playbook: Disk image/partition/filesystem/NTFS

## 1. Scope and input identification

Applies to raw disk/partition images at least 512 bytes long. `bin/fdisk`
(`lib/pyforensic/triage/disk.py`) natively parses:

- an MBR (sector 0 ends `\x55\xaa`) and its 4 partition-table entries, including detecting an
  `0xEE` "GPT protective" entry and then parsing the real GPT header (`EFI PART` magic) at LBA1;
- a bare (un-partitioned) filesystem signature: ext2/3/4 superblock magic `\x53\xef` at offset
  1080, an `NTFS    ` OEM ID in the boot sector, `FAT12`/`FAT16`/`FAT32` type strings, or an
  ISO9660 `CD001` identifier at sector 16.

This is signature/layout identification only -- it does **not** walk an NTFS MFT or an ext
inode table (`fls`/`mmls`/`testdisk` can do that work when available). Its job is to tell you
*what* is present and *where*, so you know what
heavier tool to point at which offset next.

## 2. Evidence read-only principle

`bin/fdisk` only ever `os.pread`s the evidence image through a read-only fd -- it never mounts
anything. **Never mount a disk image read-write, and never mount it read-only without an
explicit `,ro,noexec,noload` (or filesystem-appropriate read-only) option and a loop offset
computed from the partition table** -- an accidental read-write or auto-journal-replay mount
is an in-place evidence write and is forbidden. Extract files from a filesystem by reading them
with a purpose-built read-only parser or by asking the remote server to mount a read-only copy;
never write into the evidence file itself.

## 3. Initial observations

1. `sha256sum` the image; record its declared size vs. actual file size.
2. `bin/fdisk cases/<case>/evidence/<file>.img --json` -- reports `mbr`/`gpt` table type and
   every partition's type/start LBA/sector count, or a bare-filesystem identification with no
   partition table.
3. For each partition reported, compute its byte offset (`start_lba * 512`, or the GPT LBA
   times its own sector size if non-512) -- that offset is what a byte-range copy or a
   loop-mount `offset=` option needs.

## 4. Hypothesis branching

- MBR reports a `0x0B`/`0x0C` (FAT32) or `0x07` (NTFS/exFAT) partition -> extract that byte
  range and run `bin/fdisk` again against the extracted range to confirm the bare-filesystem
  signature lines up with the partition-table claim.
- `0xEE` protective entry but no valid GPT header found at LBA1 -> the GPT header itself may be
  corrupted/wiped; check for a backup GPT header near the end of the image (GPT stores one at
  both ends) before concluding the partition table is unrecoverable.
- Bare NTFS/FAT/ext signature with no partition table -> this is a single-filesystem image, not
  a full-disk image; skip partition-table analysis and go straight to filesystem-level tooling.
- Partition `sector_count` claims more bytes than remain in the file -> the image is truncated;
  note the exact missing range before assuming file corruption elsewhere.

## 5. Stop conditions

- Do not attempt a manual byte-by-byte NTFS MFT walk or ext inode walk in this project's own
  code -- that duplicates `fls`/`the sleuthkit`, which is confirmed absent locally; escalate to
  the remote server instead of hand-rolling a partial filesystem parser under time pressure.
- Cap any raw string/carving pass over a multi-gigabyte disk image with `bin/flag-scan`'s own
  per-file timeout; do not attempt an unbounded full-image `strings`-equivalent pass without a
  narrower byte range once a partition of interest is identified.

## 6. Exact commands

```bash
bin/fdisk cases/<case>/evidence/<file>.img --json
```

Extracting a specific partition's byte range for further inspection (never in place):

```bash
bin/log-command <case> -- python3 -c "
import sys
with open('cases/<case>/evidence/<file>.img', 'rb') as f:
    f.seek(<start_lba> * 512)
    data = f.read(<sector_count> * 512)
open('cases/<case>/workspace/extracted/partition-<index>.img', 'wb').write(data)
"
bin/fdisk cases/<case>/workspace/extracted/partition-<index>.img --json
```

If `fls`/`mmls`/`testdisk` are confirmed present via `bin/tool-inventory` (absent locally):

```bash
bin/log-command <case> -- mmls cases/<case>/evidence/<file>.img
bin/log-command <case> -- fls -o <start_lba> cases/<case>/evidence/<file>.img
```

## 7. Workspace output location

Extracted partition byte ranges and any file recovered from a filesystem go under
`cases/<case>/workspace/extracted/`.

## 8. Artifact hash recording

```bash
bin/record-artifact <case> cases/<case>/workspace/extracted/partition-<index>.img --log-id <log-id>
```

## 9. Flag evidence and minimal reproduction

Tie a candidate to the exact partition index/byte offset and filesystem path (once a real
filesystem parser locates the file):

```bash
bin/add-candidate <case> --flag <flag> --evidence cases/<case>/workspace/extracted/partition-<index>.img \
  --locator '{"partition_index": 0, "filesystem_path": "/path/in/fs"}' \
  --transformation "MBR partition byte-range extraction" --log-id <log-id>
```

## 10. Failure fallback

If `bin/fdisk` reports neither a recognizable partition table nor a bare-filesystem signature,
re-check with `xxd` at sector 0 for a non-standard/damaged boot sector before assuming the image
is not a filesystem at all -- it may need `CARVING.md`'s generic approach instead. For any real
file-level recovery (deleted files, MFT/inode walks), escalate to the remote `forensic` server
where `fls`/`mmls`/`testdisk` are expected to be available, since installing them locally is out
of scope for this baseline.
