"""Adversarial tests for case creation and evidence intake (requirements 15.1).

Every scenario gets its own tempfile.mkdtemp() cases root. A sentinel file
placed outside the case tree is checked byte-identical before/after every
attack scenario that could plausibly escape the intended root.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import os
import stat
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402  (adds lib/ to sys.path as a side effect)

from pyforensic import case, caselayout, manifest, pathsafety  # noqa: E402


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class SentinelMixin:
    """Places a sentinel file outside the cases root and asserts it survives untouched."""

    def setUp(self):
        super().setUp()
        self._sentinel_dir = helpers.make_workdir()
        self._sentinel_path = os.path.join(self._sentinel_dir, "sentinel.bin")
        helpers.write_file(self._sentinel_path, b"do-not-touch-sentinel-payload")
        self._sentinel_sha = _sha256_bytes(helpers.read_bytes(self._sentinel_path))
        self.addCleanup(helpers.rmtree_force, self._sentinel_dir)
        # Every test using this mixin gets the sentinel checked automatically
        # on teardown, not just the tests that call assert_sentinel_untouched()
        # explicitly -- a scenario could escape the case root without any
        # single test remembering to check for it.
        self.addCleanup(self.assert_sentinel_untouched)

    def assert_sentinel_untouched(self):
        self.assertTrue(os.path.isfile(self._sentinel_path))
        actual = _sha256_bytes(helpers.read_bytes(self._sentinel_path))
        self.assertEqual(actual, self._sentinel_sha, "sentinel file outside the case tree was modified")


class TestCreateCaseBasic(SentinelMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.cases_root = helpers.make_cases_root()
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_normal_case_with_evidence(self):
        src = helpers.write_file(os.path.join(self.work, "photo.png"), b"\x89PNG-fake-data")
        case_dir = case.create_case(self.cases_root, "case001", [src])
        self.assertTrue(os.path.isdir(case_dir))
        for sub in caselayout.ALL_SUBDIRS:
            self.assertTrue(os.path.isdir(os.path.join(case_dir, *sub.split("/"))), sub)
        records = manifest.load_evidence_manifest(os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["path"], "photo.png")
        self.assertEqual(records[0]["sha256"], _sha256_bytes(b"\x89PNG-fake-data"))
        verification = case.verify_evidence(self.cases_root, "case001")
        self.assertTrue(verification.ok)
        self.assert_sentinel_untouched()

    def test_empty_evidence_case(self):
        case_dir = case.create_case(self.cases_root, "case-empty", [])
        records = manifest.load_evidence_manifest(os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))
        self.assertEqual(records, [])
        verification = case.verify_evidence(self.cases_root, "case-empty")
        self.assertTrue(verification.ok)

    def test_valid_compound_case_names(self):
        for name in ["a", "Case-1", "case_2024.01", "A" * 200, "1abc", "a.b.c"]:
            case_dir = case.create_case(self.cases_root, name, [])
            self.assertTrue(os.path.isdir(case_dir))

    def test_invalid_case_name_matrix(self):
        bad_names = [
            "", ".", "..", ".template", "/etc/passwd", "a/b", "a\\b",
            "a\x00b", "-leading-dash", " leading-space", "trailing-space ",
            "has space", "has'quote", 'has"quote', "unicode-é", "A" * 201,
            "*glob", "?glob", "..hidden",
        ]
        for name in bad_names:
            with self.assertRaises(case.CaseError, msg=repr(name)):
                case.create_case(self.cases_root, name, [])

    def test_duplicate_case_name_rejected(self):
        case.create_case(self.cases_root, "dupcase", [])
        with self.assertRaises(case.CaseAlreadyExists):
            case.create_case(self.cases_root, "dupcase", [])

    def test_name_colliding_with_existing_file(self):
        path = os.path.join(self.cases_root, "fileclash")
        helpers.write_file(path, b"x")
        with self.assertRaises(case.CaseAlreadyExists):
            case.create_case(self.cases_root, "fileclash", [])

    def test_name_colliding_with_existing_plain_directory(self):
        path = os.path.join(self.cases_root, "dirclash")
        os.makedirs(path)
        with self.assertRaises(case.CaseAlreadyExists):
            case.create_case(self.cases_root, "dirclash", [])

    def test_name_colliding_with_dangling_symlink(self):
        path = os.path.join(self.cases_root, "danglingclash")
        os.symlink(os.path.join(self.cases_root, "does-not-exist"), path)
        with self.assertRaises(case.CaseAlreadyExists):
            case.create_case(self.cases_root, "danglingclash", [])
        self.assertTrue(os.path.islink(path))

    def test_duplicate_basename_in_one_call_rejected(self):
        sub_a = os.path.join(self.work, "a")
        sub_b = os.path.join(self.work, "b")
        os.makedirs(sub_a)
        os.makedirs(sub_b)
        src_a = helpers.write_file(os.path.join(sub_a, "dup.bin"), b"aaa")
        src_b = helpers.write_file(os.path.join(sub_b, "dup.bin"), b"bbb")
        with self.assertRaises(case.EvidenceRejected):
            case.create_case(self.cases_root, "dupbasename", [src_a, src_b])
        self.assertFalse(os.path.lexists(os.path.join(self.cases_root, "dupbasename")))

    def test_weird_filenames_round_trip(self):
        names = [
            "with space.bin", "with'apostrophe.bin", 'with"quote.bin',
            "with-dash-lead", "unicode-éè.bin", "glob[1].bin",
            "-leadingdash.bin",
        ]
        sources = []
        for name in names:
            sources.append(helpers.write_file(os.path.join(self.work, name), name.encode("utf-8")))
        case_dir = case.create_case(self.cases_root, "weirdnames", sources)
        records = manifest.load_evidence_manifest(os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))
        recorded_paths = {r["path"] for r in records}
        self.assertEqual(recorded_paths, set(names))
        verification = case.verify_evidence(self.cases_root, "weirdnames")
        self.assertTrue(verification.ok, verification.directory)

    def test_filename_with_newline_and_tab(self):
        name = "weird\tname\nfile.bin"
        src = os.path.join(self.work, "src-for-weird")
        helpers.write_file(src, b"payload")
        target = os.path.join(self.work, name)
        os.rename(src, target)
        case_dir = case.create_case(self.cases_root, "weirdctrl", [target])
        records = manifest.load_evidence_manifest(os.path.join(case_dir, caselayout.EVIDENCE_MANIFEST))
        self.assertEqual(records[0]["path"], name)

    def test_evidence_source_symlink_rejected(self):
        target = helpers.write_file(os.path.join(self.work, "real.bin"), b"data")
        link = os.path.join(self.work, "link.bin")
        os.symlink(target, link)
        with self.assertRaises(case.EvidenceRejected):
            case.create_case(self.cases_root, "symsrc", [link])
        self.assertFalse(os.path.lexists(os.path.join(self.cases_root, "symsrc")))

    def test_evidence_source_fifo_rejected(self):
        fifo = os.path.join(self.work, "myfifo")
        os.mkfifo(fifo)
        with self.assertRaises(case.EvidenceRejected):
            case.create_case(self.cases_root, "fifosrc", [fifo])

    def test_evidence_source_directory_rejected(self):
        d = os.path.join(self.work, "adir")
        os.makedirs(d)
        with self.assertRaises(case.EvidenceRejected):
            case.create_case(self.cases_root, "dirsrc", [d])

    def test_evidence_source_char_device_rejected(self):
        dev_path = os.path.join(self.work, "fakedev")
        try:
            os.mknod(dev_path, mode=0o600 | stat.S_IFCHR, device=os.makedev(1, 3))
        except (PermissionError, OSError) as exc:
            self.skipTest(f"cannot create a char device node in this sandbox: {exc}")
        with self.assertRaises(case.EvidenceRejected):
            case.create_case(self.cases_root, "devsrc", [dev_path])
        self.assertFalse(os.path.lexists(os.path.join(self.cases_root, "devsrc")))

    def test_second_source_copy_failure_rolls_back_whole_case(self):
        good = helpers.write_file(os.path.join(self.work, "good.bin"), b"good-payload")
        unreadable = helpers.write_file(os.path.join(self.work, "unreadable.bin"), b"secret-payload")
        os.chmod(unreadable, 0o000)
        try:
            if os.access(unreadable, os.R_OK):
                self.skipTest("running as a user that ignores file permissions (e.g. root); cannot induce a permission-denied read")
            with self.assertRaises(Exception):
                case.create_case(self.cases_root, "rollbackcase", [good, unreadable])
        finally:
            os.chmod(unreadable, 0o644)
        # Rollback must remove the ENTIRE case directory, not just skip the
        # failing second source and keep a partial case with only "good.bin".
        self.assertFalse(os.path.lexists(os.path.join(self.cases_root, "rollbackcase")))
        leftovers = [n for n in os.listdir(self.cases_root) if n.startswith(".new-")]
        self.assertEqual(leftovers, [])

    def test_evidence_source_deleted_after_check_still_fails_safely(self):
        src = helpers.write_file(os.path.join(self.work, "vanish.bin"), b"data")
        os.unlink(src)
        with self.assertRaises(Exception):
            case.create_case(self.cases_root, "vanishcase", [src])
        self.assertFalse(os.path.lexists(os.path.join(self.cases_root, "vanishcase")))


class TestAddEvidence(SentinelMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.cases_root = helpers.make_cases_root()
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.addCleanup(helpers.rmtree_force, self.work)
        case.create_case(self.cases_root, "basecase", [])

    def test_add_evidence_normal(self):
        src = helpers.write_file(os.path.join(self.work, "added.bin"), b"hello")
        added = case.add_evidence(self.cases_root, "basecase", [src])
        self.assertEqual(added, ["added.bin"])
        verification = case.verify_evidence(self.cases_root, "basecase")
        self.assertTrue(verification.ok)

    def test_add_evidence_duplicate_filename_rejected(self):
        src = helpers.write_file(os.path.join(self.work, "dup.bin"), b"one")
        case.add_evidence(self.cases_root, "basecase", [src])
        dup2_dir = os.path.join(self.work, "dup2")
        os.makedirs(dup2_dir)
        src2 = helpers.write_file(os.path.join(dup2_dir, "dup.bin"), b"two")
        with self.assertRaises(case.EvidenceRejected):
            case.add_evidence(self.cases_root, "basecase", [src2])

    def test_add_evidence_to_unknown_case(self):
        src = helpers.write_file(os.path.join(self.work, "x.bin"), b"x")
        with self.assertRaises(case.UnknownCase):
            case.add_evidence(self.cases_root, "no-such-case", [src])

    def test_add_evidence_case_dir_replaced_by_symlink_rejected(self):
        case_dir = os.path.join(self.cases_root, "basecase")
        elsewhere = os.path.join(self.work, "elsewhere")
        os.makedirs(elsewhere)
        helpers.rmtree_force(case_dir)
        os.symlink(elsewhere, case_dir)
        src = helpers.write_file(os.path.join(self.work, "y.bin"), b"y")
        with self.assertRaises(case.UnknownCase):
            case.add_evidence(self.cases_root, "basecase", [src])
        self.assertEqual(os.listdir(elsewhere), [])

    def test_partial_batch_failure_rolls_back_cleanly(self):
        good = helpers.write_file(os.path.join(self.work, "good.bin"), b"good-data")
        bad_dir = os.path.join(self.work, "baddir")
        os.makedirs(bad_dir)
        evidence_dir = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_DIR)
        before_listing = sorted(os.listdir(evidence_dir))
        with self.assertRaises(case.EvidenceRejected):
            case.add_evidence(self.cases_root, "basecase", [good, bad_dir])
        after_listing = sorted(os.listdir(evidence_dir))
        self.assertEqual(before_listing, after_listing)
        manifest_path = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_MANIFEST)
        self.assertEqual(manifest.load_evidence_manifest(manifest_path), [])

    def test_evidence_becomes_writable_detected(self):
        src = helpers.write_file(os.path.join(self.work, "tamperperm.bin"), b"data")
        case.add_evidence(self.cases_root, "basecase", [src])
        final = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_DIR, "tamperperm.bin")
        os.chmod(final, 0o644)
        verification = case.verify_evidence(self.cases_root, "basecase")
        self.assertFalse(verification.ok)
        self.assertIn("tamperperm.bin", verification.writable_paths)

    def test_evidence_content_tampered_detected(self):
        src = helpers.write_file(os.path.join(self.work, "tamperdata.bin"), b"original-bytes")
        case.add_evidence(self.cases_root, "basecase", [src])
        final = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_DIR, "tamperdata.bin")
        os.chmod(final, 0o644)
        with open(final, "wb") as handle:
            handle.write(b"tampered-bytes!!")
        verification = case.verify_evidence(self.cases_root, "basecase")
        self.assertFalse(verification.ok)
        mismatched_paths = [p for p, _reason in verification.directory.mismatched]
        self.assertIn("tamperdata.bin", mismatched_paths)

    def test_evidence_deleted_detected_as_missing(self):
        src = helpers.write_file(os.path.join(self.work, "gone.bin"), b"data")
        case.add_evidence(self.cases_root, "basecase", [src])
        final = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_DIR, "gone.bin")
        os.chmod(final, 0o644)
        os.unlink(final)
        verification = case.verify_evidence(self.cases_root, "basecase")
        self.assertFalse(verification.ok)
        self.assertIn("gone.bin", verification.directory.missing)

    def test_extra_untracked_file_detected(self):
        evidence_dir = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_DIR)
        helpers.write_file(os.path.join(evidence_dir, "sneaky.bin"), b"not-recorded")
        verification = case.verify_evidence(self.cases_root, "basecase")
        self.assertFalse(verification.ok)
        self.assertIn("sneaky.bin", verification.directory.extra)

    def test_evidence_replaced_by_symlink_detected(self):
        src = helpers.write_file(os.path.join(self.work, "swap.bin"), b"data")
        case.add_evidence(self.cases_root, "basecase", [src])
        final = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_DIR, "swap.bin")
        os.chmod(final, 0o644)
        os.unlink(final)
        os.symlink("/etc/passwd", final)
        verification = case.verify_evidence(self.cases_root, "basecase")
        self.assertFalse(verification.ok)
        combined = verification.directory.missing + verification.directory.extra
        self.assertTrue(any("swap.bin" in item for item in combined))

    def test_evidence_replaced_by_hardlink_detected(self):
        src = helpers.write_file(os.path.join(self.work, "hardswap.bin"), b"data")
        case.add_evidence(self.cases_root, "basecase", [src])
        final = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_DIR, "hardswap.bin")
        elsewhere = os.path.join(self.work, "other-name.bin")
        os.chmod(final, 0o644)
        os.link(final, elsewhere)
        verification = case.verify_evidence(self.cases_root, "basecase")
        self.assertFalse(verification.ok)
        mismatched_paths = [p for p, _reason in verification.directory.mismatched]
        self.assertIn("hardswap.bin", mismatched_paths)

    def test_manifest_absolute_path_entry_rejected(self):
        manifest_path = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_MANIFEST)
        with open(manifest_path, "a", encoding="utf-8") as handle:
            handle.write(
                '{"path": "/etc/passwd", "sha256": "%s", "size": 0, '
                '"original_filename": "x", "recorded_utc": "2026-01-01T00:00:00Z"}\n' % ("0" * 64)
            )
        with self.assertRaises(manifest.ManifestError):
            case.verify_evidence(self.cases_root, "basecase")

    def test_manifest_dotdot_path_entry_rejected(self):
        manifest_path = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_MANIFEST)
        with open(manifest_path, "a", encoding="utf-8") as handle:
            handle.write(
                '{"path": "../escape.bin", "sha256": "%s", "size": 0, '
                '"original_filename": "x", "recorded_utc": "2026-01-01T00:00:00Z"}\n' % ("0" * 64)
            )
        with self.assertRaises(manifest.ManifestError):
            case.verify_evidence(self.cases_root, "basecase")

    def test_manifest_duplicate_record_rejected(self):
        manifest_path = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_MANIFEST)
        line = (
            '{"path": "dup-entry.bin", "sha256": "%s", "size": 0, '
            '"original_filename": "dup-entry.bin", "recorded_utc": "2026-01-01T00:00:00Z"}\n' % ("0" * 64)
        )
        with open(manifest_path, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write(line)
        with self.assertRaises(manifest.ManifestError):
            case.verify_evidence(self.cases_root, "basecase")

    def test_manifest_malformed_line_rejected(self):
        manifest_path = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_MANIFEST)
        with open(manifest_path, "a", encoding="utf-8") as handle:
            handle.write("{not-json\n")
        with self.assertRaises(manifest.ManifestError):
            case.verify_evidence(self.cases_root, "basecase")

    def test_manifest_truncated_file_rejected_or_empty(self):
        src = helpers.write_file(os.path.join(self.work, "trunc.bin"), b"data")
        case.add_evidence(self.cases_root, "basecase", [src])
        manifest_path = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_MANIFEST)
        data = helpers.read_bytes(manifest_path)
        with open(manifest_path, "wb") as handle:
            handle.write(data[: max(0, len(data) - 5)])
        with self.assertRaises(manifest.ManifestError):
            case.verify_evidence(self.cases_root, "basecase")

    def test_manifest_symlink_rejected(self):
        manifest_path = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_MANIFEST)
        os.unlink(manifest_path)
        os.symlink("/etc/passwd", manifest_path)
        with self.assertRaises(pathsafety.PathSafetyError):
            case.verify_evidence(self.cases_root, "basecase")

    def test_manifest_hardlinked_rejected(self):
        src = helpers.write_file(os.path.join(self.work, "hlmanifest.bin"), b"data")
        case.add_evidence(self.cases_root, "basecase", [src])
        manifest_path = os.path.join(self.cases_root, "basecase", caselayout.EVIDENCE_MANIFEST)
        alias = os.path.join(self.work, "manifest-alias.jsonl")
        os.link(manifest_path, alias)
        try:
            with self.assertRaises(manifest.ManifestError):
                case.verify_evidence(self.cases_root, "basecase")
        finally:
            os.unlink(alias)


class TestConcurrency(unittest.TestCase):
    def setUp(self):
        self.cases_root = helpers.make_cases_root()
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_concurrent_create_case_same_name_exactly_one_wins(self):
        results = []
        lock = threading.Lock()

        def attempt(i):
            try:
                case.create_case(self.cases_root, "raced-case", [])
                with lock:
                    results.append(("ok", i))
            except case.CaseAlreadyExists:
                with lock:
                    results.append(("exists", i))

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(attempt, range(8)))

        oks = [r for r in results if r[0] == "ok"]
        self.assertEqual(len(oks), 1, results)
        self.assertTrue(os.path.isdir(os.path.join(self.cases_root, "raced-case")))
        leftovers = [n for n in os.listdir(self.cases_root) if n.startswith(".new-")]
        self.assertEqual(leftovers, [])

    def test_concurrent_add_evidence_same_filename_exactly_one_wins(self):
        case.create_case(self.cases_root, "concase", [])
        sources = []
        for i in range(6):
            d = os.path.join(self.work, f"src{i}")
            os.makedirs(d)
            sources.append(helpers.write_file(os.path.join(d, "shared.bin"), f"payload-{i}".encode()))

        results = []
        lock = threading.Lock()

        def attempt(src):
            try:
                case.add_evidence(self.cases_root, "concase", [src])
                with lock:
                    results.append("ok")
            except case.EvidenceRejected:
                with lock:
                    results.append("rejected")

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(attempt, sources))

        self.assertEqual(results.count("ok"), 1, results)
        verification = case.verify_evidence(self.cases_root, "concase")
        self.assertTrue(verification.ok, verification.directory)


if __name__ == "__main__":
    unittest.main()
