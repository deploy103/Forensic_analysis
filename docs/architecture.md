# Architecture and operating model

## Control flow

```text
operator or automation
  -> bin/solve fast path or manual case helpers
     -> local case workspace
     -> optional SSH alias `forensic`
  -> independent reviewer evidence-chain verdict
  -> result-check final gate
```

The operator owns scoping, task selection, reconciliation, and the final answer. Independent analysts receive bounded case paths and return evidence-backed findings. The remote server is only a tool host; it does not own orchestration or case truth.

## Data boundaries

- `evidence/`: copied originals, SHA-256 manifest, never edited in place
- `workspace/`: extraction, scripts, dumps, and disposable analysis products
- `logs/`: combined command output and command metadata
- `notes/`: problem statement plus evidence/artifact manifests
- `result/`: candidates, reviewer decision, final flag, tested reproduction

Git ignores evidence payloads, workspace contents, and raw command logs to reduce accidental commits. Notes and result records remain reviewable. This is a convenience boundary, not access control.

## Trust boundaries

- Evidence can be malicious. Prefer parsers in the configured sandbox or forensic server and do not execute recovered binaries.
- SSH configuration and credentials remain in the operator's home directory, not the project.
- Remote commands use batch mode and a connection timeout. Host-key and key provisioning remain explicit operator responsibilities.
- Analyst statements are hypotheses until commands, offsets, hashes, and reviewer reproduction connect them to evidence.

## Extension rule

Add a wrapper or playbook after it has a clear forensic input, bounded/read-only default behavior, explicit output location, and a verification path. Avoid services and registries until case evidence demonstrates that file/CLI coordination is insufficient.
