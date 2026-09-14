# Playbook: <FORMAT>

Every playbook in this directory follows this ten-section shape. A playbook that only lists
tool names without exact commands, stop conditions, and output locations is insufficient --
fill in every section with something an analyst could follow without guessing.

## 1. Scope and input identification

State exactly which magic bytes/headers/extensions this playbook applies to, and which sibling
playbook to switch to when the input turns out to be something else.

## 2. Evidence read-only principle

Evidence under `cases/<case>/evidence/` is never opened for writing, never mounted read-write,
and never has its database/filesystem/archive state mutated in place. State the specific
read-only mechanism this format uses (e.g. an immutable connection URI, `os.pread` on a
read-only fd, extraction only into `workspace/`).

## 3. Initial observations

The bounded, cheap checks to run first, before any specialized or slow tooling: format
identification, structural integrity, size, and any "end of logical structure" check that
reveals appended/hidden trailing data.

## 4. Hypothesis branching

For each initial-observation outcome, which hypothesis it suggests and which follow-up test
confirms or refutes it.

## 5. Stop conditions

Explicit conditions under which to stop searching a given angle rather than brute-forcing
indefinitely (e.g. a byte/offset/key-space bound, a timeout, a maximum recursion depth, or "no
new leads after N reasonable tool passes").

## 6. Exact commands

Copy-pasteable commands (this project's own `bin/f*` wrappers plus any confirmed-available
system tool), each with what it is expected to reveal.

## 7. Workspace output location

Exactly which `cases/<case>/workspace/...` subdirectory extracted/derived files belong in.

## 8. Artifact hash recording

The `bin/record-artifact` invocation(s) needed to hash and register anything produced above.

## 9. Flag evidence and minimal reproduction

What a flag candidate must be tied to (exact offset/table/packet/chunk) and the minimal
`bin/add-candidate` / `bin/log-command` chain that reproduces it independently of memory.

## 10. Failure fallback

The next alternative technique or tool to try when the primary approach in this playbook does
not produce a lead, including when `bin/tool-inventory` indicates that heavier tooling requires
the remote `forensic` server.
