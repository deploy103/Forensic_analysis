"""Shared fixture utilities for the adversarial test suite.

Every test that needs a cases root must get its own throwaway directory via
:func:`make_cases_root` (backed by ``tempfile.mkdtemp``) -- never the
repository's real ``cases/`` tree, and never a fixed shared path that two
tests (or two processes running the same test) could collide on.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB_DIR = os.path.join(PROJECT_ROOT, "lib")
BIN_DIR = os.path.join(PROJECT_ROOT, "bin")

if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)


def make_cases_root() -> str:
    return tempfile.mkdtemp(prefix="pyforensic-test-cases-")


def make_workdir() -> str:
    return tempfile.mkdtemp(prefix="pyforensic-test-work-")


def write_file(path: str, data: bytes) -> str:
    with open(path, "wb") as handle:
        handle.write(data)
    return path


def run_bin(name: str, args: list[str], *, cases_root: str, timeout: float = 30, input_bytes: bytes | None = None,
            env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Invoke a real ``bin/<name>`` executable as a subprocess.

    Used for end-to-end scenarios that need to observe real stdout bytes,
    real process exit codes, or real argv-boundary behavior -- exactly what
    ships to an analyst, as opposed to calling the Python API directly.
    """
    env = dict(os.environ)
    env["FORENSIC_SOLVER_CASES_DIR"] = cases_root
    env.pop("PYTHONPATH", None)
    if env_extra:
        env.update(env_extra)
    exe = os.path.join(BIN_DIR, name)
    return subprocess.run(
        [exe, *args],
        cwd=cases_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        input=input_bytes,
        timeout=timeout,
    )


def rmtree_force(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)


def read_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()
