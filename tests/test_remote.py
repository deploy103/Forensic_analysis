"""Adversarial tests for SSH/SCP remote helpers and CLI dry-run (15.6)."""

from __future__ import annotations

import contextlib
import io
import os
import stat
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

from pyforensic import cli, errors, remote  # noqa: E402


class TestArgvValidation(unittest.TestCase):
    def test_empty_alias_rejected(self):
        with self.assertRaises(remote.RemoteError):
            remote.ssh_argv(["echo", "hi"], alias="")

    def test_alias_starting_with_dash_rejected(self):
        with self.assertRaises(remote.RemoteError):
            remote.ssh_argv(["echo", "hi"], alias="-oProxyCommand=evil")

    def test_alias_with_control_char_rejected(self):
        with self.assertRaises(remote.RemoteError):
            remote.ssh_argv(["echo", "hi"], alias="host\nEvilLine")

    def test_empty_remote_argv_rejected(self):
        with self.assertRaises(remote.RemoteError):
            remote.ssh_argv([])

    def test_remote_argv_with_embedded_newline_rejected(self):
        with self.assertRaises(remote.RemoteError):
            remote.ssh_argv(["echo", "line1\nrm -rf /"])

    def test_local_or_remote_path_starting_with_dash_rejected(self):
        with self.assertRaises(remote.RemoteError):
            remote.scp_push_argv("-oProxyCommand=evil", "/tmp/dest")
        with self.assertRaises(remote.RemoteError):
            remote.scp_push_argv("/tmp/src", "-oProxyCommand=evil")

    def test_empty_path_rejected(self):
        with self.assertRaises(remote.RemoteError):
            remote.scp_pull_argv("", "/tmp/dest")


class TestDangerousOptionsNeverEmitted(unittest.TestCase):
    """Negative assertions: this module must never weaken host-key checking.

    ssh_argv/scp_push_argv/scp_pull_argv deliberately leave
    StrictHostKeyChecking and UserKnownHostsFile at their configured
    defaults (see remote.py's module docstring) -- a future edit that
    "helps" by adding StrictHostKeyChecking=no to silence a host-key
    prompt would silently disable MITM protection for every remote call.
    """

    def _assert_no_dangerous_options(self, argv):
        rendered = " ".join(argv)
        for dangerous in (
            "StrictHostKeyChecking=no",
            "StrictHostKeyChecking no",
            "UserKnownHostsFile=/dev/null",
            "UserKnownHostsFile /dev/null",
        ):
            self.assertNotIn(dangerous, rendered, argv)

    def test_ssh_argv_never_disables_host_key_checking(self):
        self._assert_no_dangerous_options(remote.ssh_argv(["id"], alias="myhost"))

    def test_scp_push_argv_never_disables_host_key_checking(self):
        self._assert_no_dangerous_options(remote.scp_push_argv("a.bin", "b.bin", alias="myhost"))

    def test_scp_pull_argv_never_disables_host_key_checking(self):
        self._assert_no_dangerous_options(remote.scp_pull_argv("a.bin", "b.bin", alias="myhost"))


class TestSshArgvShape(unittest.TestCase):
    def test_ssh_argv_contains_hardening_and_batchmode(self):
        argv = remote.ssh_argv(["id"], alias="myhost")
        self.assertIn("ssh", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("ForwardAgent=no", argv)
        self.assertIn("ClearAllForwardings=yes", argv)
        self.assertIn("PermitLocalCommand=no", argv)
        self.assertIn("RequestTTY=no", argv)
        self.assertIn("--", argv)
        # -- must precede the alias/command, so a crafted alias/command
        # starting with '-' cannot be parsed as another ssh flag.
        dashdash_idx = argv.index("--")
        self.assertEqual(argv[dashdash_idx + 1], "myhost")
        self.assertEqual(argv[-1], "id")

    def test_ssh_argv_joins_multi_word_remote_command_as_one_string(self):
        argv = remote.ssh_argv(["ls", "-la", "/tmp"])
        self.assertEqual(argv[-1], "ls -la /tmp")

    def test_ssh_argv_shell_metacharacters_in_remote_arg_are_quoted_not_interpreted(self):
        # shlex.join must quote a hostile argument so that, when the remote
        # shell parses the resulting single string, it is still treated as
        # one literal argument to the first command -- not as a semicolon-
        # separated second command.
        argv = remote.ssh_argv(["printf", "%s", "; rm -rf /tmp/should-not-run; "])
        rendered = argv[-1]
        import shlex
        parsed_back = shlex.split(rendered)
        self.assertEqual(parsed_back, ["printf", "%s", "; rm -rf /tmp/should-not-run; "])


class TestScpArgvShape(unittest.TestCase):
    def test_scp_push_argv_shape_and_destination(self):
        argv = remote.scp_push_argv("evidence.bin", "case1/evidence.bin", alias="myhost")
        self.assertIn("scp", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("--", argv)
        self.assertEqual(argv[-1], "myhost:case1/evidence.bin")
        self.assertEqual(argv[-2], "./evidence.bin")

    def test_scp_pull_argv_shape_and_source(self):
        argv = remote.scp_pull_argv("case1/evidence.bin", "./local.bin", alias="myhost")
        self.assertEqual(argv[-2], "myhost:case1/evidence.bin")
        self.assertEqual(argv[-1], "./local.bin")

    def test_ambiguous_colon_in_local_path_is_disambiguated(self):
        # scp treats any operand containing ':' before the first '/' as a
        # remote host:path spec. A case-relative filename containing a
        # literal colon (e.g. a Windows-style timestamp in a filename)
        # must not silently become an unintended remote-to-remote copy.
        argv = remote.scp_push_argv("notes:10:30.txt", "dest.txt", alias="myhost")
        source = argv[-2]
        self.assertTrue(source.startswith("./"), source)
        self.assertEqual(source, "./notes:10:30.txt")

    def test_already_unambiguous_absolute_path_left_untouched(self):
        argv = remote.scp_push_argv("/abs/path/evidence.bin", "dest.bin", alias="myhost")
        self.assertEqual(argv[-2], "/abs/path/evidence.bin")

    def test_path_with_control_char_rejected(self):
        with self.assertRaises(remote.RemoteError):
            remote.scp_push_argv("evil\x00.bin", "dest.bin")

    def test_local_path_that_looks_like_a_third_host_spec_is_disambiguated_not_rejected(self):
        # There is no reachable code path where a caller hands scp_push_argv/
        # scp_pull_argv a single ambiguous "host:path" string for the local
        # side and expects outright rejection: both functions always build
        # the *remote* operand themselves (f"{alias}:{remote_path}"), and
        # _disambiguate_local_path unconditionally prefixes every local path
        # with "./" unless it already starts with "/", "./", or "../" -- so
        # a local path that happens to look like "otherhost:evil/path" can
        # never be sent to scp as a bare, ambiguous operand; it is always
        # neutralized into "./otherhost:evil/path" first. This test pins
        # that guarantee for a local-looking "host:path" string with no
        # leading path separator at all (the most ambiguous shape possible),
        # rather than adding a rejection path that would have no caller.
        argv = remote.scp_push_argv("otherhost:evil/path", "dest.bin", alias="myhost")
        source = argv[-2]
        self.assertTrue(source.startswith("./"), source)
        self.assertEqual(source, "./otherhost:evil/path")
        # scp must never be given two ambiguous host:path-shaped operands.
        self.assertEqual(argv[-1], "myhost:dest.bin")


class TestRenderRemoteCommand(unittest.TestCase):
    def test_render_rejects_control_characters(self):
        with self.assertRaises(remote.RemoteError):
            remote.render_remote_command(["echo", "line1\r\nline2"])

    def test_render_rejects_empty_argv(self):
        with self.assertRaises(remote.RemoteError):
            remote.render_remote_command([])

    def test_render_quotes_arguments_with_spaces(self):
        rendered = remote.render_remote_command(["echo", "hello world"])
        self.assertEqual(rendered, "echo 'hello world'")


class TestCliDryRun(unittest.TestCase):
    """Exercise the actual bin/forensic dry-run path with no real ssh/scp on PATH."""

    def setUp(self):
        self.cases_root = helpers.make_cases_root()
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.shim_dir = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.shim_dir)
        self.sentinel = os.path.join(self.shim_dir, "ssh-or-scp-was-invoked")
        # Fake ssh/scp that would prove (via the sentinel) if the dry-run
        # short-circuit were ever skipped and a real network tool invoked.
        # Placed ahead of the real PATH so they would be found first.
        for name in ("ssh", "scp"):
            shim = os.path.join(self.shim_dir, name)
            helpers.write_file(
                shim, f"#!/bin/sh\ntouch {self.sentinel}\nexit 1\n".encode()
            )
            os.chmod(shim, os.stat(shim).st_mode | stat.S_IEXEC)

    def _run_with_shimmed_ssh(self, args):
        env = dict(os.environ)
        env["FORENSIC_SOLVER_CASES_DIR"] = self.cases_root
        env.pop("PYTHONPATH", None)
        env["PATH"] = self.shim_dir + os.pathsep + env.get("PATH", "")
        import subprocess

        exe = os.path.join(helpers.BIN_DIR, "forensic")
        return subprocess.run(
            [exe, *args], cwd=self.cases_root, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )

    def _run_with_no_ssh_on_path(self, args):
        proc = self._run_with_shimmed_ssh(args)
        self.assertFalse(
            os.path.exists(self.sentinel),
            "dry-run must never actually invoke ssh/scp",
        )
        return proc

    def test_remote_exec_dry_run_never_shells_out(self):
        proc = self._run_with_no_ssh_on_path(["remote-exec", "--dry-run", "ls", "-la", "/tmp"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.decode().strip(), "ls -la /tmp")

    def test_remote_copy_dry_run_never_shells_out(self):
        proc = self._run_with_no_ssh_on_path(
            ["remote-copy", "--dry-run", "push", "evidence.bin", "case1/evidence.bin"]
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        rendered = proc.stdout.decode().strip()
        self.assertIn("./evidence.bin", rendered)
        self.assertIn("forensic:case1/evidence.bin", rendered)

    def test_remote_copy_missing_args_is_usage_error(self):
        proc = self._run_with_no_ssh_on_path(["remote-copy", "--dry-run", "push", "onlyone"])
        self.assertNotEqual(proc.returncode, 0)

    def test_remote_copy_invalid_direction_is_usage_error(self):
        proc = self._run_with_no_ssh_on_path(
            ["remote-copy", "--dry-run", "sideways", "a.bin", "b.bin"]
        )
        self.assertNotEqual(proc.returncode, 0)


class TestRemoteRunNeverUsesShell(unittest.TestCase):
    def test_run_executes_argv_directly_without_shell_interpretation(self):
        work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, work)
        fake_ssh = os.path.join(work, "fake-ssh")
        helpers.write_file(
            fake_ssh,
            b"#!/bin/sh\nprintf '%s\\n' \"$@\"\n",
        )
        os.chmod(fake_ssh, os.stat(fake_ssh).st_mode | stat.S_IEXEC)

        payload = "$(touch /tmp/should-not-be-created-by-remote-test); `id`"
        proc = remote.run([fake_ssh, "--", "host", payload])
        output_lines = proc.stdout.decode().splitlines()
        self.assertIn(payload, output_lines)
        self.assertFalse(os.path.exists("/tmp/should-not-be-created-by-remote-test"))


class TestRemoteCliTimeoutAndFailureHandling(unittest.TestCase):
    """cmd_remote_exec/cmd_remote_copy must degrade to a clean CLI error, not
    an unhandled traceback, when the underlying ssh/scp call times out or the
    binary is missing -- a real remote host can always hang or vanish.
    """

    def test_remote_exec_timeout_returns_clean_failure_not_traceback(self):
        with mock.patch.object(
            remote, "run",
            side_effect=subprocess.TimeoutExpired(cmd=["ssh"], timeout=120),
        ):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = cli.cmd_remote_exec(["id"])
        self.assertEqual(rc, errors.GENERIC_FAILURE)
        self.assertIn("remote-exec failed", stderr.getvalue())

    def test_remote_copy_timeout_returns_clean_failure_not_traceback(self):
        with mock.patch.object(
            remote, "run",
            side_effect=subprocess.TimeoutExpired(cmd=["scp"], timeout=300),
        ):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = cli.cmd_remote_copy(["push", "local.bin", "remote.bin"])
        self.assertEqual(rc, errors.GENERIC_FAILURE)
        self.assertIn("remote-copy failed", stderr.getvalue())

    def test_remote_exec_missing_ssh_binary_returns_clean_failure_not_traceback(self):
        with mock.patch.object(
            remote, "run", side_effect=FileNotFoundError("ssh: no such file or directory"),
        ):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                rc = cli.cmd_remote_exec(["id"])
        self.assertEqual(rc, errors.GENERIC_FAILURE)
        self.assertIn("remote-exec failed", stderr.getvalue())

    def test_remote_exec_nonzero_remote_exit_status_is_propagated_not_swallowed(self):
        fake_completed = subprocess.CompletedProcess(args=["ssh"], returncode=17, stdout=b"remote command failed\n")
        with mock.patch.object(remote, "run", return_value=fake_completed):
            rc = cli.cmd_remote_exec(["false"])
        self.assertEqual(rc, 17)

    def test_remote_copy_nonzero_remote_exit_status_is_propagated_not_swallowed(self):
        fake_completed = subprocess.CompletedProcess(args=["scp"], returncode=42, stdout=b"")
        with mock.patch.object(remote, "run", return_value=fake_completed):
            rc = cli.cmd_remote_copy(["push", "local.bin", "remote.bin"])
        self.assertEqual(rc, 42)


if __name__ == "__main__":
    unittest.main()
