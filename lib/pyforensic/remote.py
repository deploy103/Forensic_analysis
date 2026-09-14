"""SSH/SCP remote helpers: pure argv builders plus thin execution wrappers.

This project never invents or stores real server credentials -- the SSH
alias (``forensic`` by default, see ``config/ssh_config.example``) must
already be configured by the analyst in their own ``~/.ssh/config``. What
this module hardens is everything *around* that trust boundary:

* every remote command runs as an explicit ``argv`` array executed via
  ``subprocess.run`` (never ``shell=True``) -- the only string-building
  that happens is rendering the *remote* command with ``shlex.join`` (SSH
  always hands a single command string to the remote shell; that is a
  protocol-level fact, not a choice this code makes), so no local shell
  ever sees unsanitized input;
* every ``ssh``/``scp`` invocation passes ``--`` before positional
  arguments and rejects any path or alias beginning with ``-``, so a
  crafted filename or alias cannot be misinterpreted as another CLI flag;
* ``BatchMode=yes`` is always set so a misconfigured or unreachable host
  fails fast with a clear error instead of hanging on an interactive
  password/passphrase prompt.

The argv-builder functions are pure and unit-testable without any network
access or real server; see ``tests/`` for coverage using a ``PATH`` shim
that replaces ``ssh``/``scp`` with a script that records its invocation.
"""

from __future__ import annotations

import shlex
import subprocess

DEFAULT_ALIAS = "forensic"
DEFAULT_CONNECT_TIMEOUT = 8

# Hardening options applied to every ssh/scp invocation: refuse to become an
# agent-forwarding or port-forwarding relay, never run a local command on
# behalf of the remote side, and never allocate a TTY (which would let an
# interactive prompt hang a supposedly-scripted call). Host-key checking is
# deliberately left at its configured default -- this module never adds
# StrictHostKeyChecking=no or UserKnownHostsFile=/dev/null.
_HARDENING_OPTIONS = [
    "-o", "ForwardAgent=no",
    "-o", "ClearAllForwardings=yes",
    "-o", "PermitLocalCommand=no",
]
_SSH_ONLY_HARDENING_OPTIONS = ["-o", "RequestTTY=no"]

_CONTROL_CHARS = ("\n", "\r", "\x00")


class RemoteError(Exception):
    pass


def _validate_alias(alias: str) -> None:
    if not alias or alias.startswith("-") or any(c in alias for c in _CONTROL_CHARS):
        raise RemoteError(f"invalid SSH alias: {alias!r}")


def _validate_path_arg(path: str, *, label: str) -> None:
    if not path or path.startswith("-") or any(c in path for c in _CONTROL_CHARS):
        raise RemoteError(f"{label} must not be empty, start with '-', or contain control characters: {path!r}")


def _disambiguate_local_path(path: str) -> str:
    """Force scp to parse ``path`` as local, never as an implicit ``host:path``.

    ``scp`` (and legacy OpenSSH before the SFTP-protocol rewrite) treats any
    operand containing ``:`` before the first ``/`` as a remote spec. Without
    this, a local path an analyst didn't fully control (e.g. built from a
    case-relative filename) containing a colon could silently turn into an
    unintended remote-to-remote copy. Prefixing with ``./`` is the standard,
    unambiguous fix and is a no-op for paths that were already unambiguous.
    """
    if path.startswith("/") or path.startswith("./") or path.startswith("../"):
        return path
    return f"./{path}"


def render_remote_command(argv: list[str]) -> str:
    if not argv:
        raise RemoteError("remote command argv must not be empty")
    for arg in argv:
        if any(c in arg for c in ("\n", "\r", "\x00")):
            raise RemoteError(f"remote command argument must not contain control characters: {arg!r}")
    return shlex.join(argv)


def ssh_argv(
    argv: list[str],
    *,
    alias: str = DEFAULT_ALIAS,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> list[str]:
    _validate_alias(alias)
    remote_command = render_remote_command(argv)
    return [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
        *_HARDENING_OPTIONS,
        *_SSH_ONLY_HARDENING_OPTIONS,
        "--",
        alias,
        remote_command,
    ]


def ssh_check_argv(*, alias: str = DEFAULT_ALIAS, connect_timeout: int = DEFAULT_CONNECT_TIMEOUT) -> list[str]:
    return ssh_argv(["printf", "connected\\n"], alias=alias, connect_timeout=connect_timeout)


def ssh_resolve_config_argv(*, alias: str = DEFAULT_ALIAS) -> list[str]:
    _validate_alias(alias)
    return ["ssh", "-G", "--", alias]


def scp_push_argv(
    local_path: str,
    remote_path: str,
    *,
    alias: str = DEFAULT_ALIAS,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> list[str]:
    _validate_alias(alias)
    _validate_path_arg(local_path, label="local path")
    _validate_path_arg(remote_path, label="remote path")
    source = _disambiguate_local_path(local_path)
    destination = f"{alias}:{remote_path}"
    return [
        "scp", "-p",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
        *_HARDENING_OPTIONS,
        "--",
        source,
        destination,
    ]


def scp_pull_argv(
    remote_path: str,
    local_path: str,
    *,
    alias: str = DEFAULT_ALIAS,
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT,
) -> list[str]:
    _validate_alias(alias)
    _validate_path_arg(remote_path, label="remote path")
    _validate_path_arg(local_path, label="local path")
    source = f"{alias}:{remote_path}"
    destination = _disambiguate_local_path(local_path)
    return [
        "scp", "-p",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={connect_timeout}",
        *_HARDENING_OPTIONS,
        "--",
        source,
        destination,
    ]


def run(argv: list[str], *, timeout: float | None = 30) -> subprocess.CompletedProcess:
    return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
