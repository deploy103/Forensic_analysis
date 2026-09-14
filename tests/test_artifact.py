"""Adversarial tests for generated-artifact recording and verification (15.2)."""

from __future__ import annotations

import concurrent.futures
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

from pyforensic import artifact, case, caselayout, commandlog, manifest  # noqa: E402


class TestArtifactBase(unittest.TestCase):
    def setUp(self):
        self.cases_root = helpers.make_cases_root()
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.case_dir = case.create_case(self.cases_root, "artcase", [])

    def workspace_path(self, *parts) -> str:
        return os.path.join(self.case_dir, caselayout.WORKSPACE_DIR, *parts)


class TestRecordArtifact(TestArtifactBase):
    def test_record_normal_artifact_in_extracted(self):
        path = self.workspace_path("extracted", "member.bin")
        helpers.write_file(path, b"extracted-bytes")
        record = artifact.record_artifact(self.cases_root, "artcase", path)
        self.assertEqual(record["path"], "extracted/member.bin")
        self.assertEqual(record["size"], len(b"extracted-bytes"))
        verification = artifact.verify_artifacts(self.cases_root, "artcase")
        self.assertTrue(verification.ok)

    def test_record_normal_artifact_in_dumps(self):
        path = self.workspace_path("dumps", "dump1.raw")
        helpers.write_file(path, b"dump-bytes")
        record = artifact.record_artifact(self.cases_root, "artcase", path)
        self.assertEqual(record["path"], "dumps/dump1.raw")

    def test_record_artifact_outside_workspace_rejected(self):
        path = os.path.join(self.case_dir, caselayout.NOTES_DIR, "not-workspace.bin")
        helpers.write_file(path, b"x")
        with self.assertRaises(artifact.ArtifactRejected):
            artifact.record_artifact(self.cases_root, "artcase", path)

    def test_record_artifact_dotdot_escape_rejected(self):
        outside = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, outside)
        evil = os.path.join(
            self.case_dir, caselayout.WORKSPACE_DIR, "extracted", "..", "..", "..", "escape.bin"
        )
        with self.assertRaises(artifact.ArtifactRejected):
            artifact.record_artifact(self.cases_root, "artcase", evil)

    def test_record_artifact_absolute_path_outside_case_rejected(self):
        outside_dir = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, outside_dir)
        outside_file = helpers.write_file(os.path.join(outside_dir, "not-mine.bin"), b"x")
        with self.assertRaises(artifact.ArtifactRejected):
            artifact.record_artifact(self.cases_root, "artcase", outside_file)

    def test_record_artifact_nonexistent_rejected(self):
        path = self.workspace_path("extracted", "ghost.bin")
        with self.assertRaises(Exception):
            artifact.record_artifact(self.cases_root, "artcase", path)

    def test_record_artifact_symlink_final_component_rejected(self):
        real = self.workspace_path("dumps", "real.bin")
        helpers.write_file(real, b"real-data")
        link = self.workspace_path("extracted", "linked.bin")
        os.symlink(real, link)
        with self.assertRaises(Exception):
            artifact.record_artifact(self.cases_root, "artcase", link)

    def test_record_artifact_through_symlinked_intermediate_dir_rejected(self):
        outside_dir = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, outside_dir)
        planted = helpers.write_file(os.path.join(outside_dir, "planted.bin"), b"planted-data")

        extracted_dir = self.workspace_path("extracted")
        helpers.rmtree_force(extracted_dir)
        os.symlink(outside_dir, extracted_dir)

        target = os.path.join(extracted_dir, "planted.bin")
        with self.assertRaises(Exception):
            artifact.record_artifact(self.cases_root, "artcase", target)
        # The symlinked directory itself must not have been walked into.
        self.assertTrue(os.path.islink(extracted_dir))
        self.assertEqual(helpers.read_bytes(planted), b"planted-data")

    def test_record_duplicate_artifact_path_rejected(self):
        path = self.workspace_path("extracted", "dup.bin")
        helpers.write_file(path, b"data")
        artifact.record_artifact(self.cases_root, "artcase", path)
        with self.assertRaises(artifact.ArtifactRejected):
            artifact.record_artifact(self.cases_root, "artcase", path)

    def test_record_artifact_with_hardlink_rejected(self):
        path = self.workspace_path("extracted", "hardlinked.bin")
        helpers.write_file(path, b"data")
        alias = self.workspace_path("dumps", "alias.bin")
        os.link(path, alias)
        with self.assertRaises(artifact.ArtifactRejected):
            artifact.record_artifact(self.cases_root, "artcase", path)

    def test_record_artifact_with_unknown_producing_log_id_rejected(self):
        path = self.workspace_path("extracted", "logged.bin")
        helpers.write_file(path, b"data")
        with self.assertRaises(artifact.ArtifactRejected):
            artifact.record_artifact(
                self.cases_root, "artcase", path, producing_log_id="does-not-exist"
            )

    def test_record_artifact_with_valid_producing_log_id(self):
        result = commandlog.run_and_log(self.cases_root, "artcase", ["echo", "hi"])
        path = self.workspace_path("extracted", "logged-ok.bin")
        helpers.write_file(path, b"data")
        record = artifact.record_artifact(
            self.cases_root, "artcase", path, producing_log_id=result.log_id
        )
        self.assertEqual(record["producing_log_id"], result.log_id)

    def test_record_artifact_with_unknown_parent_artifact_rejected(self):
        path = self.workspace_path("extracted", "child.bin")
        helpers.write_file(path, b"data")
        with self.assertRaises(artifact.ArtifactRejected):
            artifact.record_artifact(
                self.cases_root, "artcase", path, parent_artifact="never-recorded.bin"
            )

    def test_record_artifact_with_valid_parent_artifact(self):
        parent_path = self.workspace_path("extracted", "parent.bin")
        helpers.write_file(parent_path, b"parent-data")
        artifact.record_artifact(self.cases_root, "artcase", parent_path)

        child_path = self.workspace_path("extracted", "child2.bin")
        helpers.write_file(child_path, b"child-data")
        record = artifact.record_artifact(
            self.cases_root, "artcase", child_path, parent_artifact="extracted/parent.bin"
        )
        self.assertEqual(record["parent_artifact"], "extracted/parent.bin")


class TestArtifactSpecialFilenames(TestArtifactBase):
    def test_special_character_filename_round_trips(self):
        name = "weird name with spaces, 'quotes', \"dquotes\", and 유니코드.bin"
        path = self.workspace_path("extracted", name)
        helpers.write_file(path, b"special-bytes")
        record = artifact.record_artifact(self.cases_root, "artcase", path)
        self.assertEqual(record["path"], f"extracted/{name}")
        verification = artifact.verify_artifacts(self.cases_root, "artcase")
        self.assertTrue(verification.ok)


class TestVerifyArtifacts(TestArtifactBase):
    def test_artifact_replaced_by_symlink_detected(self):
        path = self.workspace_path("extracted", "swap.bin")
        helpers.write_file(path, b"data")
        artifact.record_artifact(self.cases_root, "artcase", path)
        os.chmod(path, 0o644)
        os.unlink(path)
        os.symlink("/etc/passwd", path)
        verification = artifact.verify_artifacts(self.cases_root, "artcase")
        self.assertFalse(verification.ok)
        combined = verification.directory.missing + verification.directory.extra
        self.assertTrue(any("swap.bin" in item for item in combined))

    def test_artifact_manifest_absolute_path_entry_rejected(self):
        manifest_path = os.path.join(self.case_dir, caselayout.ARTIFACT_MANIFEST)
        with open(manifest_path, "a", encoding="utf-8") as handle:
            handle.write(
                '{"path": "/etc/passwd", "sha256": "%s", "size": 0, '
                '"recorded_utc": "2026-01-01T00:00:00Z", "producing_log_id": null, '
                '"parent_artifact": null}\n' % ("0" * 64)
            )
        with self.assertRaises(manifest.ManifestError):
            artifact.verify_artifacts(self.cases_root, "artcase")

    def test_artifact_manifest_dotdot_path_entry_rejected(self):
        manifest_path = os.path.join(self.case_dir, caselayout.ARTIFACT_MANIFEST)
        with open(manifest_path, "a", encoding="utf-8") as handle:
            handle.write(
                '{"path": "extracted/../../escape.bin", "sha256": "%s", "size": 0, '
                '"recorded_utc": "2026-01-01T00:00:00Z", "producing_log_id": null, '
                '"parent_artifact": null}\n' % ("0" * 64)
            )
        with self.assertRaises(manifest.ManifestError):
            artifact.verify_artifacts(self.cases_root, "artcase")

    def test_artifact_manifest_duplicate_record_rejected(self):
        manifest_path = os.path.join(self.case_dir, caselayout.ARTIFACT_MANIFEST)
        line = (
            '{"path": "extracted/dup.bin", "sha256": "%s", "size": 0, '
            '"recorded_utc": "2026-01-01T00:00:00Z", "producing_log_id": null, '
            '"parent_artifact": null}\n' % ("0" * 64)
        )
        with open(manifest_path, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write(line)
        with self.assertRaises(manifest.ManifestError):
            artifact.verify_artifacts(self.cases_root, "artcase")

    def test_artifact_manifest_malformed_line_rejected(self):
        manifest_path = os.path.join(self.case_dir, caselayout.ARTIFACT_MANIFEST)
        with open(manifest_path, "a", encoding="utf-8") as handle:
            handle.write("{not-json\n")
        with self.assertRaises(manifest.ManifestError):
            artifact.verify_artifacts(self.cases_root, "artcase")

    def test_tampered_artifact_detected(self):
        path = self.workspace_path("extracted", "tamper.bin")
        helpers.write_file(path, b"original")
        artifact.record_artifact(self.cases_root, "artcase", path)
        with open(path, "wb") as handle:
            handle.write(b"tampered!")
        verification = artifact.verify_artifacts(self.cases_root, "artcase")
        self.assertFalse(verification.ok)
        mismatched_paths = [p for p, _r in verification.directory.mismatched]
        self.assertIn("extracted/tamper.bin", mismatched_paths)

    def test_missing_artifact_detected(self):
        path = self.workspace_path("extracted", "removed.bin")
        helpers.write_file(path, b"data")
        artifact.record_artifact(self.cases_root, "artcase", path)
        os.unlink(path)
        verification = artifact.verify_artifacts(self.cases_root, "artcase")
        self.assertFalse(verification.ok)
        self.assertIn("extracted/removed.bin", verification.directory.missing)

    def test_unrecorded_scratch_file_is_not_a_hard_failure(self):
        # Extraction tools produce many incidental files; per artifact.py's
        # own documented design, unrecorded-but-present files are reported
        # as "extra" but do not flip verification.ok to False.
        recorded = self.workspace_path("extracted", "recorded.bin")
        helpers.write_file(recorded, b"data")
        artifact.record_artifact(self.cases_root, "artcase", recorded)

        scratch = self.workspace_path("scripts", "scratch.py")
        helpers.write_file(scratch, b"# scratch\n")

        verification = artifact.verify_artifacts(self.cases_root, "artcase")
        self.assertTrue(verification.ok)
        self.assertIn("scripts/scratch.py", verification.directory.extra)


class TestArtifactConcurrency(TestArtifactBase):
    def test_concurrent_record_same_artifact_exactly_one_wins(self):
        path = self.workspace_path("extracted", "raced-artifact.bin")
        helpers.write_file(path, b"raced-data")

        results = []
        lock = threading.Lock()

        def attempt(_i):
            try:
                artifact.record_artifact(self.cases_root, "artcase", path)
                with lock:
                    results.append("ok")
            except artifact.ArtifactRejected:
                with lock:
                    results.append("rejected")

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(attempt, range(8)))

        self.assertEqual(results.count("ok"), 1, results)
        manifest_path = os.path.join(self.case_dir, caselayout.ARTIFACT_MANIFEST)
        records = manifest.load_artifact_manifest(manifest_path)
        matching = [r for r in records if r["path"] == "extracted/raced-artifact.bin"]
        self.assertEqual(len(matching), 1)


if __name__ == "__main__":
    unittest.main()
