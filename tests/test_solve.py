"""End-to-end tests for `bin/solve`, the single competition-facing command.

These invoke the real ``bin/solve`` executable (never the Python API
directly) so the assertions cover exactly what a competitor sees: exit
codes, the terminal ``[FLAG]`` block, and ``--json`` shape.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

import unittest

from pyforensic import errors  # noqa: E402


def _solve(args, *, cases_root, cwd=None, env_extra=None):
    env = dict(os.environ)
    env["FORENSIC_SOLVER_CASES_DIR"] = cases_root
    env.pop("PYTHONPATH", None)
    if env_extra:
        env.update(env_extra)
    import subprocess

    exe = os.path.join(helpers.BIN_DIR, "solve")
    return subprocess.run(
        [exe, *args], cwd=cwd or cases_root, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
    )


class TestSolveExplicitFile(unittest.TestCase):
    def setUp(self):
        self.cases_root = helpers.make_cases_root()
        self.work = helpers.make_workdir()
        state_dir = helpers.make_workdir()
        self.env_extra = {"FORENSIC_SOLVER_STATE_DIR": state_dir}
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.addCleanup(helpers.rmtree_force, self.work)
        self.addCleanup(helpers.rmtree_force, state_dir)

    def test_direct_flag_found_and_reported_last(self):
        data = b"noise before\nFLAG{direct_hit}\nnoise after\n"
        path = helpers.write_file(os.path.join(self.work, "evidence.bin"), data)
        proc = _solve([path], cases_root=self.cases_root, env_extra=self.env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_FLAG_FOUND)
        stdout = proc.stdout.decode("utf-8")
        lines = stdout.rstrip("\n").splitlines()
        self.assertEqual(lines[-2], "[FLAG]")
        self.assertEqual(lines[-1], "FLAG{direct_hit}")

    def test_evidence_sha256_matches_source_file(self):
        data = b"CTF{sha_check}\n"
        path = helpers.write_file(os.path.join(self.work, "f.txt"), data)
        proc = _solve([path, "--json"], cases_root=self.cases_root, env_extra=self.env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_FLAG_FOUND)
        result = json.loads(proc.stdout)
        expected_sha256 = hashlib.sha256(data).hexdigest()
        self.assertEqual(result["evidence_sha256"], expected_sha256)
        self.assertEqual(result["evidence_path"], "f.txt")

    def test_no_flag_found_reports_exit_code_and_message(self):
        path = helpers.write_file(os.path.join(self.work, "boring.txt"), b"nothing interesting here\n")
        proc = _solve([path], cases_root=self.cases_root, env_extra=self.env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_NO_FLAG_FOUND)
        self.assertIn("[NO FLAG FOUND]", proc.stdout.decode("utf-8"))

    def test_json_output_shape(self):
        path = helpers.write_file(os.path.join(self.work, "f.txt"), b"HTB{json_shape}\n")
        proc = _solve([path, "--json"], cases_root=self.cases_root, env_extra=self.env_extra)
        result = json.loads(proc.stdout)
        for key in ("case_name", "case_dir", "source_path", "evidence_path", "evidence_sha256",
                    "triage", "extracted_files", "candidates", "best", "execution_plan"):
            self.assertIn(key, result)
        self.assertEqual(result["best"]["flag"], "HTB{json_shape}")

    def test_candidate_recorded_in_gate_with_required_fields(self):
        path = helpers.write_file(os.path.join(self.work, "f.txt"), b"picoCTF{gate_check}\n")
        proc = _solve([path, "--json"], cases_root=self.cases_root, env_extra=self.env_extra)
        result = json.loads(proc.stdout)
        case_dir = result["case_dir"]
        candidates_path = os.path.join(case_dir, "result", "candidates.jsonl")
        with open(candidates_path, "r", encoding="utf-8") as handle:
            records = [json.loads(line) for line in handle if line.strip()]
        self.assertEqual(len(records), 1)
        record = records[0]
        for field in ("candidate_id", "flag", "evidence_path", "locator", "transformation", "log_id"):
            self.assertIn(field, record)
        self.assertEqual(record["flag"], "picoCTF{gate_check}")
        self.assertEqual(record["evidence_path"], "f.txt")

    def test_usage_error_on_too_many_arguments(self):
        proc = _solve(["a", "b"], cases_root=self.cases_root, env_extra=self.env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_USAGE_ERROR)

    def test_usage_error_on_file_and_latest_together(self):
        path = helpers.write_file(os.path.join(self.work, "f.txt"), b"irrelevant\n")
        proc = _solve([path, "--latest"], cases_root=self.cases_root, env_extra=self.env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_USAGE_ERROR)

    def test_no_candidate_file_for_nonexistent_explicit_path(self):
        proc = _solve(["/nonexistent/path/xyz"], cases_root=self.cases_root, env_extra=self.env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_NO_CANDIDATE_FILE)


class TestSolveRecursiveExtraction(unittest.TestCase):
    def setUp(self):
        self.cases_root = helpers.make_cases_root()
        self.work = helpers.make_workdir()
        state_dir = helpers.make_workdir()
        self.env_extra = {"FORENSIC_SOLVER_STATE_DIR": state_dir}
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.addCleanup(helpers.rmtree_force, self.work)
        self.addCleanup(helpers.rmtree_force, state_dir)

    def test_flag_inside_doubly_nested_zip_is_found(self):
        inner_txt = os.path.join(self.work, "secret.txt")
        helpers.write_file(inner_txt, b"DH{nested_two_levels_deep}\n")
        inner_zip = os.path.join(self.work, "inner.zip")
        with zipfile.ZipFile(inner_zip, "w") as zf:
            zf.write(inner_txt, arcname="secret.txt")
        outer_zip = os.path.join(self.work, "outer.zip")
        with zipfile.ZipFile(outer_zip, "w") as zf:
            zf.write(inner_zip, arcname="inner.zip")

        proc = _solve([outer_zip, "--json"], cases_root=self.cases_root, env_extra=self.env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_FLAG_FOUND)
        result = json.loads(proc.stdout)
        self.assertEqual(result["best"]["flag"], "DH{nested_two_levels_deep}")
        self.assertGreaterEqual(len(result["extracted_files"]), 2)
        self.assertEqual(result["best"]["source"], "extracted")

    def test_flag_directly_in_evidence_no_extraction_needed(self):
        path = helpers.write_file(os.path.join(self.work, "plain.txt"), b"CTF{no_extraction_needed}\n")
        proc = _solve([path, "--json"], cases_root=self.cases_root, env_extra=self.env_extra)
        result = json.loads(proc.stdout)
        self.assertEqual(result["best"]["flag"], "CTF{no_extraction_needed}")
        self.assertEqual(result["best"]["source"], "evidence")
        self.assertEqual(result["extracted_files"], [])


class TestSolveFileSelection(unittest.TestCase):
    def setUp(self):
        self.cases_root = helpers.make_cases_root()
        state_dir = helpers.make_workdir()
        self.env_extra = {"FORENSIC_SOLVER_STATE_DIR": state_dir}
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.addCleanup(helpers.rmtree_force, state_dir)

    def test_auto_pick_selects_most_recently_modified_file_in_cwd(self):
        helpers.write_file(os.path.join(self.cases_root, "older.txt"), b"nothing here\n")
        time.sleep(0.05)
        helpers.write_file(os.path.join(self.cases_root, "newer.bin"), b"FLAG{auto_picked_newest}\n")
        proc = _solve([], cases_root=self.cases_root, env_extra=self.env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_FLAG_FOUND)
        self.assertIn(b"FLAG{auto_picked_newest}", proc.stdout)

    def test_no_candidate_file_when_cwd_is_empty(self):
        proc = _solve([], cases_root=self.cases_root, env_extra=self.env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_NO_CANDIDATE_FILE)

    def test_latest_flag_selects_newest_file_in_downloads_override(self):
        downloads = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, downloads)
        helpers.write_file(os.path.join(downloads, "old.txt"), b"not this one\n")
        time.sleep(0.05)
        helpers.write_file(os.path.join(downloads, "new.txt"), b"CTF{from_downloads}\n")
        env_extra = dict(self.env_extra)
        env_extra["FORENSIC_SOLVER_DOWNLOADS_DIR"] = downloads
        proc = _solve(["--latest"], cases_root=self.cases_root, env_extra=env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_FLAG_FOUND)
        self.assertIn(b"CTF{from_downloads}", proc.stdout)

    def test_no_candidate_file_when_downloads_dir_missing(self):
        env_extra = dict(self.env_extra)
        env_extra["FORENSIC_SOLVER_DOWNLOADS_DIR"] = "/nonexistent/downloads/dir"
        proc = _solve(["--latest"], cases_root=self.cases_root, env_extra=env_extra)
        self.assertEqual(proc.returncode, errors.SOLVE_NO_CANDIDATE_FILE)


if __name__ == "__main__":
    unittest.main()
