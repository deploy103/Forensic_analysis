"""Tests for the hash-verified, cached artifact transfer manager (transfer.py).

No real remote node is configured in this sandbox, so
push/pull against a real alias cannot succeed here; these tests instead
prove (1) the SHA-256 + caching logic is correct on its own, and (2) an
unreachable alias fails honestly (``ok=False``) rather than fabricating a
transfer.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

import unittest

from pyforensic import transfer


class TestSha256File(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_sha256_file_matches_hashlib(self):
        import hashlib

        data = b"some artifact bytes\n" * 100
        path = helpers.write_file(os.path.join(self.work, "f.bin"), data)
        self.assertEqual(transfer.sha256_file(path), hashlib.sha256(data).hexdigest())


class TestTransferCache(unittest.TestCase):
    def setUp(self):
        self.state_dir = helpers.make_workdir()
        os.environ["FORENSIC_SOLVER_STATE_DIR"] = self.state_dir
        self.addCleanup(helpers.rmtree_force, self.state_dir)
        self.addCleanup(os.environ.pop, "FORENSIC_SOLVER_STATE_DIR", None)
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_not_already_transferred_by_default(self):
        self.assertFalse(transfer._already_transferred("node", "abc123", "/remote/path"))

    def test_record_then_already_transferred_true(self):
        transfer._record_transfer("node", "abc123", "/remote/path", "push")
        self.assertTrue(transfer._already_transferred("node", "abc123", "/remote/path"))

    def test_different_node_or_path_not_considered_transferred(self):
        transfer._record_transfer("node", "abc123", "/remote/path", "push")
        self.assertFalse(transfer._already_transferred("other-node", "abc123", "/remote/path"))
        self.assertFalse(transfer._already_transferred("node", "abc123", "/other/path"))
        self.assertFalse(transfer._already_transferred("node", "different-hash", "/remote/path"))

    def test_push_artifact_skips_network_when_content_already_cached(self):
        data = b"cached content\n"
        path = helpers.write_file(os.path.join(self.work, "f.bin"), data)
        sha256 = transfer.sha256_file(path)
        transfer._record_transfer("cache-test-node", sha256, "/remote/dest", "push")
        result = transfer.push_artifact(path, "cache-test-node", "/remote/dest")
        self.assertTrue(result.ok)
        self.assertTrue(result.skipped_cached)
        self.assertEqual(result.sha256, sha256)

    def test_push_artifact_to_unreachable_alias_fails_honestly(self):
        path = helpers.write_file(os.path.join(self.work, "f.bin"), b"not cached\n")
        result = transfer.push_artifact(path, "definitely-unreachable-test-alias-xyz", "/remote/dest")
        self.assertFalse(result.ok)
        self.assertFalse(result.skipped_cached)

    def test_pull_artifact_from_unreachable_alias_fails_honestly(self):
        dest = os.path.join(self.work, "pulled.bin")
        result = transfer.pull_artifact("/remote/source", dest, "definitely-unreachable-test-alias-xyz")
        self.assertFalse(result.ok)
        self.assertFalse(os.path.exists(dest))


if __name__ == "__main__":
    unittest.main()
