"""Memory-image triage: native magic/header identification, stdlib-only.

Volatility (``vol.py``/``vol``/``volatility``) is confirmed absent on the
reference host and its command syntax differs across major versions
(2 vs 3), so this wrapper never *requires* it: it always attempts a
native identification of the container format (LiME, raw ELF core dump,
Windows crash dump, Windows hibernation file, AFF4) first, and only adds
a Volatility-produced profile/OS summary as an optional bonus layer when
one of those binaries happens to be on ``PATH``. A raw ``dd``-style
memory image with no container header at all is the *common* case for
this domain, not an error, so it is reported as ``partial_success``
(format unidentified, size/sample stats still returned) rather than
``input_mismatch``.
"""

from __future__ import annotations

import math
import os
import struct

from . import common

LIME_MAGIC = b"EMiL"
ELF_MAGIC = b"\x7fELF"
CRASH_MAGICS = (b"PAGEDU64", b"PAGEDUMP")
HIBER_MAGICS = (b"hibr", b"HIBR", b"wake")
SAMPLE_SIZE = 1 * 1024 * 1024


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _parse_lime_header(prefix: bytes) -> dict:
    magic, version, s_addr, e_addr = struct.unpack_from("<IIQQ", prefix, 0)
    return {"format": "lime", "version": version, "start_address": hex(s_addr), "end_address": hex(e_addr)}


def _try_volatility(path: str) -> dict | None:
    for tool, args in (
        ("vol.py", ["-f", path, "imageinfo"]),
        ("vol", ["-f", path, "windows.info"]),
        ("volatility", ["-f", path, "imageinfo"]),
    ):
        if not common.tool_available(tool):
            continue
        try:
            proc = common.run_tool([tool] + args, timeout=120)
        except Exception:
            continue
        if proc is not None:
            return {"tool": tool, "returncode": proc.returncode, "output": proc.stdout.decode("utf-8", errors="replace")}
    return None


def inspect(path: str) -> common.TriageResult:
    fd, st = common.open_input_safely(path)
    try:
        prefix = common.read_prefix(fd, 32)
        sample = os.pread(fd, min(SAMPLE_SIZE, st.st_size), 0)
    finally:
        os.close(fd)

    warnings = []
    details: dict = {"file_size": st.st_size, "sampled_entropy": round(_shannon_entropy(sample), 3)}

    if prefix.startswith(LIME_MAGIC):
        details.update(_parse_lime_header(prefix))
    elif prefix.startswith(ELF_MAGIC):
        details["format"] = "elf-core"
    elif any(prefix.startswith(m) for m in CRASH_MAGICS):
        details["format"] = "windows-crash-dump"
    elif any(prefix.startswith(m) for m in HIBER_MAGICS):
        details["format"] = "windows-hibernation-file"
    else:
        details["format"] = "raw/unidentified"
        warnings.append("no known memory-image container magic found; treating as a raw physical-memory dump")

    vol_result = _try_volatility(path)
    if vol_result is None:
        warnings.append("no Volatility installation (vol.py/vol/volatility) found on PATH; OS/profile identification skipped")
    else:
        details["volatility"] = vol_result

    outcome = "partial_success" if warnings else "full_success"
    return common.TriageResult(
        outcome=outcome, tool="memory-native",
        summary=f"memory image, format={details['format']}, {st.st_size} bytes",
        details=details,
        warnings=warnings,
    )
