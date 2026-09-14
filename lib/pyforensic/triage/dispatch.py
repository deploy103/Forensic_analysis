"""Format-agnostic triage entry point: try each specific wrapper in turn.

Used by ``ftriage``/``triage-case`` when the analyst has not already
named a specific format. Each wrapper module reports ``input_mismatch``
when the bytes don't look like its format, so dispatch is simply "try
wrappers in priority order, keep the first one that doesn't say
mismatch". :mod:`memory` is tried last because it treats an
unrecognized-but-parseable file as a *valid* (if unidentified) raw
memory image rather than a mismatch -- placed anywhere earlier it would
swallow inputs that a more specific wrapper further down the list would
have identified correctly.
"""

from __future__ import annotations

from . import archive, common, disk, document, image, memory, pcap, sqlite

_ORDERED_MODULES = (
    ("pcap", pcap),
    ("sqlite", sqlite),
    ("image", image),
    ("document", document),
    ("archive", archive),
    ("disk", disk),
    ("memory", memory),
)


def detect_and_inspect(path: str) -> common.TriageResult:
    attempted = []
    for name, module in _ORDERED_MODULES:
        result = module.inspect(path)
        attempted.append(name)
        if result.outcome != "input_mismatch":
            result.details.setdefault("detected_as", name)
            return result
    return common.TriageResult(
        outcome="input_mismatch", tool="dispatch",
        summary=f"input did not match any known format after trying: {attempted}",
        details={"attempted": attempted},
    )
