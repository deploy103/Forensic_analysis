# Configuration

- `ssh_config.example` is a placeholder-only personal SSH configuration fragment. Never commit substituted infrastructure values or private keys.
- `toolset.txt` is the executable-name baseline consumed by `bin/tool-inventory`. Add a command only when its absence/presence is operationally useful; installation policy belongs outside this list.
No configuration file in this repository should contain passwords, access tokens, private-key contents, real server addresses, or challenge secrets.
