"""Process exit-code contracts.

Every CLI entry point documents which of these codes it uses so that
automation (and the test suite) can depend on exact semantics instead of
grepping human-readable text. Codes are grouped by the class of tool that
uses them; a given script only ever returns codes from its own group.

Case engine (new-case, add-evidence, verify-evidence, record-artifact,
verify-artifacts, list-cases, case-status, case-report, case-doctor):
    OK, GENERIC_FAILURE, USAGE_ERROR
"""

OK = 0
GENERIC_FAILURE = 1
USAGE_ERROR = 2

# bin/log-command passes through the child's own exit status. When the
# wrapper itself cannot even start the child, it reports these instead
# (matching shell exec-failure conventions so downstream tooling that
# already expects 126/127 keeps working).
COMMAND_NOT_FOUND = 127
COMMAND_NOT_EXECUTABLE = 126

# bin/flag-scan: matches found vs. no matches vs. bad input are distinct
# so automation can tell "the scan ran cleanly and found nothing" apart
# from "some input could not be scanned at all".
FLAG_SCAN_MATCHES_FOUND = 0
FLAG_SCAN_NO_MATCHES = 1
FLAG_SCAN_USAGE_ERROR = 2
FLAG_SCAN_INVALID_PATH = 3

# Triage wrappers (ftriage/farchive/fpcap/fsqlite/fstego/fmemory/fdisk/
# fdocument): these distinguish "ran fine" from three different partial
# states instead of collapsing everything to a bare 0/1.
TRIAGE_OK = 0
TRIAGE_PARTIAL_SUCCESS = 3
TRIAGE_TOOL_MISSING = 4
TRIAGE_INPUT_MISMATCH = 5
TRIAGE_PARSER_FAILURE = 6

# result-check / reviewer gate.
GATE_PASS = 0
GATE_FAIL = 1
GATE_USAGE_ERROR = 2

# bin/solve: the single competition-facing command. A flag being found or
# not found are both "the tool ran correctly", so they get distinct codes
# rather than collapsing to a bare 0/1 like a plain success/failure tool.
SOLVE_FLAG_FOUND = 0
SOLVE_NO_FLAG_FOUND = 1
SOLVE_USAGE_ERROR = 2
SOLVE_NO_CANDIDATE_FILE = 3
