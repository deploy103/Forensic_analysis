"""Tests for the plan-only tool installer (toolinstall.py).

Per explicit user decision, tool installation is plan-only: this module must
never itself invoke a package manager. These tests check the returned
candidates are inert data (argv lists), and separately prove nothing in the
module actually calls subprocess/os.system.
"""

from __future__ import annotations

import ast
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

import unittest

from pyforensic import toolinstall


class TestPlanInstall(unittest.TestCase):
    def test_known_tool_returns_curated_candidates(self):
        candidates = toolinstall.plan_install("exiftool")
        self.assertTrue(candidates)
        self.assertEqual(candidates[0].manager, "apt")
        self.assertEqual(candidates[0].package, "libimage-exiftool-perl")
        self.assertIn("apt-get", candidates[0].argv)

    def test_tool_with_multiple_package_managers_returns_all_candidates(self):
        candidates = toolinstall.plan_install("binwalk")
        managers = {c.manager for c in candidates}
        self.assertEqual(managers, {"apt", "pip"})

    def test_unknown_tool_falls_back_to_generic_apt_guess(self):
        candidates = toolinstall.plan_install("some-random-unlisted-tool")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].manager, "apt")
        self.assertEqual(candidates[0].package, "some-random-unlisted-tool")

    def test_every_candidate_has_a_rationale(self):
        for tool in ("exiftool", "yara", "some-random-unlisted-tool"):
            for candidate in toolinstall.plan_install(tool):
                self.assertTrue(candidate.rationale.strip())

    def test_plan_installs_maps_each_tool_name_to_its_own_candidate_list(self):
        result = toolinstall.plan_installs(["exiftool", "foremost"])
        self.assertEqual(set(result.keys()), {"exiftool", "foremost"})
        self.assertTrue(result["exiftool"])
        self.assertTrue(result["foremost"])


class TestPlanOnlyGuarantee(unittest.TestCase):
    def test_module_source_never_calls_subprocess_or_os_system(self):
        source_path = os.path.join(helpers.LIB_DIR, "pyforensic", "toolinstall.py")
        with open(source_path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=source_path)
        forbidden_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                dotted = ast.dump(func)
                if "subprocess" in dotted or "os.system" in dotted or (
                    isinstance(func, ast.Attribute) and func.attr in ("system", "run", "Popen", "call")
                ):
                    forbidden_calls.append(dotted)
        self.assertEqual(forbidden_calls, [])

    def test_plan_install_argv_is_plain_data_not_executed(self):
        candidates = toolinstall.plan_install("tshark")
        for candidate in candidates:
            self.assertIsInstance(candidate.argv, list)
            self.assertTrue(all(isinstance(part, str) for part in candidate.argv))


if __name__ == "__main__":
    unittest.main()
