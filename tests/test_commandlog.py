"""Adversarial tests for reproducible command execution/logging (15.3)."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

from pyforensic import case, caselayout, commandlog  # noqa: E402


class TestCommandLogBase(unittest.TestCase):
    def setUp(self):
        self.cases_root = helpers.make_cases_root()
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.case_dir = case.create_case(self.cases_root, "cmdcase", [])

    def read_records(self):
        return commandlog.read_command_log(self.case_dir)


class TestRunAndLog(TestCommandLogBase):
    def test_normal_command_recorded(self):
        result = commandlog.run_and_log(self.cases_root, "cmdcase", ["printf", "%s", "hello"])
        self.assertEqual(result.exit_status, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.truncated)

        output_path = os.path.join(self.case_dir, result.output_relative)
        data = helpers.read_bytes(output_path)
        self.assertEqual(data, b"hello")
        self.assertEqual(result.output_sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(result.output_size, len(data))

        records = self.read_records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["log_id"], result.log_id)
        self.assertEqual(records[0]["exit_status"], 0)

        commands_md = os.path.join(self.case_dir, caselayout.COMMANDS_MD)
        md_text = helpers.read_bytes(commands_md).decode("utf-8")
        self.assertIn(result.log_id, md_text)

    def test_nonzero_exit_status_recorded_accurately(self):
        result = commandlog.run_and_log(self.cases_root, "cmdcase", ["sh", "-c", "exit 7"])
        self.assertEqual(result.exit_status, 7)
        records = self.read_records()
        self.assertEqual(records[-1]["exit_status"], 7)

    def test_nonexistent_executable_maps_to_127(self):
        result = commandlog.run_and_log(
            self.cases_root, "cmdcase", ["/nonexistent/binary/does-not-exist-xyz"]
        )
        self.assertEqual(result.exit_status, commandlog.EXIT_NOT_FOUND)
        self.assertEqual(result.exit_status, 127)

    def test_non_executable_file_maps_to_126(self):
        work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, work)
        not_exec = helpers.write_file(os.path.join(work, "notexec.sh"), b"#!/bin/sh\necho hi\n")
        os.chmod(not_exec, 0o644)
        result = commandlog.run_and_log(self.cases_root, "cmdcase", [not_exec])
        self.assertEqual(result.exit_status, commandlog.EXIT_NOT_EXECUTABLE)
        self.assertEqual(result.exit_status, 126)

    def test_timeout_kills_process_group_and_reports_124(self):
        # A backgrounded grandchild that ignores SIGTERM/normal wait would
        # survive a naive proc.kill(); killpg on the whole session-leader
        # group must reap it too, or this test would hang past its own
        # timeout instead of returning quickly.
        script = (
            "trap '' TERM; "
            "sh -c 'sleep 30' & "
            "wait"
        )
        result = commandlog.run_and_log(
            self.cases_root, "cmdcase", ["sh", "-c", script], timeout_seconds=1
        )
        self.assertTrue(result.timed_out)
        self.assertEqual(result.exit_status, commandlog.EXIT_TIMED_OUT)
        self.assertEqual(result.exit_status, 124)

    def test_output_capped_and_truncated_flag_set(self):
        cap = 4096
        result = commandlog.run_and_log(
            self.cases_root,
            "cmdcase",
            ["sh", "-c", "yes A | head -c 1000000"],
            max_output_bytes=cap,
        )
        self.assertTrue(result.truncated)
        self.assertLessEqual(result.output_size, cap)
        output_path = os.path.join(self.case_dir, result.output_relative)
        actual_size = os.path.getsize(output_path)
        self.assertEqual(actual_size, result.output_size)
        self.assertEqual(result.output_sha256, hashlib.sha256(helpers.read_bytes(output_path)).hexdigest())

    def test_unknown_case_rejected(self):
        with self.assertRaises(case.UnknownCase):
            commandlog.run_and_log(self.cases_root, "no-such-case", ["echo", "hi"])

    def test_empty_argv_rejected(self):
        with self.assertRaises(commandlog.CommandLogError):
            commandlog.run_and_log(self.cases_root, "cmdcase", [])

    def test_argv_with_shell_metacharacters_not_interpreted_by_shell(self):
        # subprocess.Popen with a list argv never invokes a shell, so this
        # string is passed to `printf` as one literal argument, not expanded.
        payload = "$(rm -rf /tmp/should-not-run); `id`; ;&|"
        result = commandlog.run_and_log(self.cases_root, "cmdcase", ["printf", "%s", payload])
        output_path = os.path.join(self.case_dir, result.output_relative)
        self.assertEqual(helpers.read_bytes(output_path).decode(), payload)

    def test_command_output_log_path_preplanted_symlink_rejected_not_crashed(self):
        original_new_log_id = commandlog.new_log_id
        commandlog.new_log_id = lambda: "FIXEDPROBEID"
        self.addCleanup(setattr, commandlog, "new_log_id", original_new_log_id)

        logs_dir = os.path.join(self.case_dir, caselayout.LOGS_DIR)
        target = os.path.join(logs_dir, "FIXEDPROBEID.log")
        os.symlink("/etc/passwd", target)

        with self.assertRaises(commandlog.CommandLogError):
            commandlog.run_and_log(self.cases_root, "cmdcase", ["echo", "hi"])

        # The symlink must be untouched -- no write attempted through it.
        self.assertTrue(os.path.islink(target))
        self.assertEqual(os.readlink(target), "/etc/passwd")
        # No spurious command record should have been appended for a run
        # that never actually produced a safe output log.
        self.assertEqual(self.read_records(), [])

    def test_two_runs_get_distinct_unpredictable_log_ids(self):
        r1 = commandlog.run_and_log(self.cases_root, "cmdcase", ["echo", "one"])
        r2 = commandlog.run_and_log(self.cases_root, "cmdcase", ["echo", "two"])
        self.assertNotEqual(r1.log_id, r2.log_id)
        records = self.read_records()
        self.assertEqual(len(records), 2)

    def test_jsonl_line_is_valid_json_per_line(self):
        commandlog.run_and_log(self.cases_root, "cmdcase", ["echo", "x"])
        commandlog.run_and_log(self.cases_root, "cmdcase", ["echo", "y"])
        jsonl_path = os.path.join(self.case_dir, caselayout.COMMANDS_JSONL)
        with open(jsonl_path, "r", encoding="utf-8") as handle:
            lines = [line for line in handle if line.strip()]
        self.assertEqual(len(lines), 2)
        for line in lines:
            json.loads(line)  # must not raise

    def test_explicit_shell_pipeline_exit_status_is_not_reinterpreted(self):
        # commandlog never adds its own shell layer: an analyst who wants a
        # pipeline must spell out ["sh", "-c", ...] explicitly, and the
        # recorded exit_status is exactly what that explicit script
        # produces (POSIX sh reports the *last* pipeline stage's status,
        # not a pipefail-style aggregate) -- commandlog must not silently
        # "fix" or reinterpret this, only faithfully record it.
        result = commandlog.run_and_log(
            self.cases_root, "cmdcase", ["sh", "-c", "false | true"]
        )
        self.assertEqual(result.exit_status, 0)
        result2 = commandlog.run_and_log(
            self.cases_root, "cmdcase", ["sh", "-c", "true | false"]
        )
        self.assertEqual(result2.exit_status, 1)

    def test_combined_output_preserves_interleaved_stdout_and_stderr(self):
        script = (
            "python3 -c \"import sys,time\n"
            "sys.stdout.write('OUT1\\n'); sys.stdout.flush()\n"
            "sys.stderr.write('ERR1\\n'); sys.stderr.flush()\n"
            "sys.stdout.write('OUT2\\n'); sys.stdout.flush()\n\""
        )
        result = commandlog.run_and_log(self.cases_root, "cmdcase", ["sh", "-c", script])
        output_path = os.path.join(self.case_dir, result.output_relative)
        text = helpers.read_bytes(output_path).decode()
        self.assertIn("OUT1", text)
        self.assertIn("ERR1", text)
        self.assertIn("OUT2", text)
        # stdout+stderr are merged (subprocess.STDOUT), so both streams'
        # lines must appear in their actual emission order, not grouped by
        # stream.
        self.assertEqual(
            [line for line in text.splitlines() if line], ["OUT1", "ERR1", "OUT2"]
        )

    def test_argv_field_round_trips_exactly_including_unicode_and_control_bytes(self):
        tricky = ["", "  leading/trailing space  ", 'has "quotes"', "line\nbreak", "유니코드"]
        result = commandlog.run_and_log(self.cases_root, "cmdcase", ["printf", "%s", *tricky])
        records = self.read_records()
        stored = records[-1]["command"]
        self.assertEqual(stored, ["printf", "%s", *tricky])
        self.assertEqual(result.argv, ["printf", "%s", *tricky])

    def test_concurrent_run_and_log_calls_all_recorded_without_corruption(self):
        def run(i):
            return commandlog.run_and_log(self.cases_root, "cmdcase", ["echo", f"run-{i}"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(run, range(8)))

        records = self.read_records()
        self.assertEqual(len(records), 8)
        log_ids = {r.log_id for r in results}
        self.assertEqual(len(log_ids), 8)
        recorded_ids = {rec["log_id"] for rec in records}
        self.assertEqual(recorded_ids, log_ids)


if __name__ == "__main__":
    unittest.main()
