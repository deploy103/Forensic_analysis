# Forensic server contract

The server is a replaceable command-line toolbox, not an AI service or source of truth.

## Operator-provided configuration

- SSH host alias: `forensic`
- verified host-key fingerprint
- non-root account and least-privilege key
- authorized base directory for transferred case material
- retention and deletion policy

These values are intentionally absent from the repository. `config/ssh_config.example` is the only provided template.

## Expected behavior

- `bin/remote-check` must succeed non-interactively before autonomous use.
- Remote tools should write only beneath the authorized case directory.
- Tool names/versions and remote commands must be captured in the local case log.
- Evidence transferred to the server must be hash-checked before analysis and after retrieval.
- Extracted outputs returned locally belong in `workspace/` and must be recorded with `bin/record-artifact`.

## Minimum bootstrap validation

After credentials are provisioned, run `bin/remote-check`, compare `sha256sum` across a harmless test transfer, and inventory only the tools needed by the current case. Do not enable password automation, agent forwarding, root login, or broad shared directories as a shortcut.

