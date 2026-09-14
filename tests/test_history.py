"""Tests for the cross-case execution-history store (history.py)."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

import unittest

from pyforensic import history


class TestExecutionHistory(unittest.TestCase):
    def setUp(self):
        self.state_dir = helpers.make_workdir()
        os.environ["FORENSIC_SOLVER_STATE_DIR"] = self.state_dir
        self.addCleanup(helpers.rmtree_force, self.state_dir)
        self.addCleanup(os.environ.pop, "FORENSIC_SOLVER_STATE_DIR", None)

    def test_state_dir_env_override_is_created_and_used(self):
        path = history.state_dir()
        self.assertEqual(path, self.state_dir)
        self.assertTrue(os.path.isdir(path))

    def test_record_and_read_round_trips(self):
        history.record_execution("ftriage", "local", "success", 0.5)
        records = history.read_history()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["tool"], "ftriage")
        self.assertEqual(records[0]["node_alias"], "local")
        self.assertEqual(records[0]["outcome"], "success")

    def test_read_history_empty_when_no_file_yet(self):
        self.assertEqual(history.read_history(), [])

    def test_success_rate_computed_correctly(self):
        history.record_execution("flag-scan", "local", "success", 0.1)
        history.record_execution("flag-scan", "local", "success", 0.1)
        history.record_execution("flag-scan", "local", "failure", 0.1)
        rate = history.success_rate("flag-scan", "local")
        self.assertAlmostEqual(rate, 2 / 3)

    def test_success_rate_zero_for_unknown_tool_or_node(self):
        self.assertEqual(history.success_rate("never-run-tool", "local"), 0.0)

    def test_make_history_lookup_matches_success_rate(self):
        history.record_execution("ftriage", "nodeA", "success", 0.2)
        lookup = history.make_history_lookup()
        self.assertEqual(lookup("ftriage", "nodeA"), history.success_rate("ftriage", "nodeA"))

    def test_record_execution_never_raises_even_if_state_dir_unwritable(self):
        os.environ["FORENSIC_SOLVER_STATE_DIR"] = "/proc/definitely-not-writable/xyz"
        try:
            history.record_execution("ftriage", "local", "success", 0.1)
        except OSError:
            self.fail("record_execution must be best-effort and never raise")


if __name__ == "__main__":
    unittest.main()
