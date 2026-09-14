"""Adversarial tests for the bounded, streaming flag scanner (15.4)."""

from __future__ import annotations

import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

from pyforensic import flagscan  # noqa: E402


class TestBuiltinPatterns(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_flag_braces_found_with_correct_offset(self):
        data = b"prefix junk\nflag{this_is_the_flag}\ntrailing junk"
        path = helpers.write_file(os.path.join(self.work, "f.txt"), data)
        result = flagscan.scan_path(path)
        labels = {m.pattern for m in result.matches}
        self.assertIn("flag_braces", labels)
        flag_match = next(m for m in result.matches if m.pattern == "flag_braces")
        self.assertEqual(flag_match.offset, data.index(b"flag{"))
        self.assertEqual(flag_match.snippet, "flag{this_is_the_flag}")

    def test_htb_and_picoctf_and_generic_patterns(self):
        data = b"HTB{one} picoCTF{two} custom_tag{three} flag{four}"
        path = helpers.write_file(os.path.join(self.work, "multi.txt"), data)
        result = flagscan.scan_path(path)
        labels = {m.pattern for m in result.matches}
        self.assertIn("htb_braces", labels)
        self.assertIn("picoctf_braces", labels)
        self.assertIn("generic_tagged_braces", labels)
        self.assertIn("flag_braces", labels)

    def test_case_insensitive_flag_and_htb(self):
        data = b"FLAG{upper} htb{lower}"
        path = helpers.write_file(os.path.join(self.work, "case.txt"), data)
        result = flagscan.scan_path(path)
        labels = {m.pattern for m in result.matches}
        self.assertIn("flag_braces", labels)
        self.assertIn("htb_braces", labels)

    def test_no_match_in_unrelated_text(self):
        path = helpers.write_file(os.path.join(self.work, "clean.txt"), b"nothing interesting here at all")
        result = flagscan.scan_path(path)
        self.assertEqual(result.matches, [])

    def test_directory_scan_recurses_and_sorts(self):
        os.makedirs(os.path.join(self.work, "sub"))
        helpers.write_file(os.path.join(self.work, "a.txt"), b"flag{top}")
        helpers.write_file(os.path.join(self.work, "sub", "b.txt"), b"flag{nested}")
        result = flagscan.scan_path(self.work)
        found_paths = {m.path for m in result.matches}
        self.assertEqual(found_paths, {"a.txt", "sub/b.txt"})
        self.assertEqual(result.files_scanned, 2)

    def test_symlinked_subdirectory_not_followed(self):
        outside = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, outside)
        helpers.write_file(os.path.join(outside, "secret.txt"), b"flag{should_not_be_found}")
        os.symlink(outside, os.path.join(self.work, "linked"))
        helpers.write_file(os.path.join(self.work, "plain.txt"), b"flag{plain_one}")
        result = flagscan.scan_path(self.work)
        found_paths = {m.path for m in result.matches}
        self.assertEqual(found_paths, {"plain.txt"})

    def test_scan_nonexistent_path_rejected(self):
        with self.assertRaises(flagscan.InvalidScanPath):
            flagscan.scan_path(os.path.join(self.work, "does-not-exist"))

    def test_scan_symlink_path_itself_rejected(self):
        real = helpers.write_file(os.path.join(self.work, "real.txt"), b"flag{x}")
        link = os.path.join(self.work, "link.txt")
        os.symlink(real, link)
        with self.assertRaises(flagscan.InvalidScanPath):
            flagscan.scan_path(link)

    def test_empty_file_scanned_without_error(self):
        path = helpers.write_file(os.path.join(self.work, "empty.txt"), b"")
        result = flagscan.scan_path(path)
        self.assertEqual(result.matches, [])
        self.assertEqual(result.files_scanned, 1)

    def test_unreadable_file_in_directory_scan_skipped_not_crashed(self):
        unreadable = helpers.write_file(os.path.join(self.work, "noperm.txt"), b"flag{hidden}")
        os.chmod(unreadable, 0o000)
        try:
            if os.access(unreadable, os.R_OK):
                self.skipTest("running with privileges that ignore permission bits (e.g. root)")
            helpers.write_file(os.path.join(self.work, "ok.txt"), b"flag{visible}")
            result = flagscan.scan_path(self.work)
            found_paths = {m.path for m in result.matches if m.pattern == "flag_braces"}
            self.assertEqual(found_paths, {"ok.txt"})
            self.assertGreaterEqual(result.files_skipped_nonregular, 1)
        finally:
            os.chmod(unreadable, 0o644)

    def test_fifo_excluded_from_directory_scan(self):
        # The directory walk itself (_walk) only collects S_ISREG entries,
        # so a FIFO never becomes a candidate path at all; it is simply
        # absent from the results, not counted via files_skipped_nonregular
        # (that counter is for a TOCTOU type-change between listing and
        # opening, not for special files excluded during the walk).
        fifo = os.path.join(self.work, "myfifo")
        os.mkfifo(fifo)
        helpers.write_file(os.path.join(self.work, "ok.txt"), b"flag{ok}")
        result = flagscan.scan_path(self.work)
        self.assertEqual(result.files_skipped_nonregular, 0)
        self.assertEqual({m.path for m in result.matches if m.pattern == "flag_braces"}, {"ok.txt"})
        self.assertEqual(result.files_scanned, 1)


class TestChunkingAndCaps(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_match_spanning_chunk_boundary_found_once(self):
        # Force a tiny chunk_size so the flag literal straddles a boundary;
        # the overlap window plus (label, offset) de-dup must yield exactly
        # one match, not zero (missed) and not two (double-counted). Padding
        # uses a non-word character (space) so a genuine \b boundary exists
        # right before "flag" in the *unchunked* ground truth -- padding
        # with word characters (e.g. "x") would merge into one continuous
        # token with no real boundary there even in a whole-file scan, which
        # would not actually test chunk-boundary handling.
        payload = b"flag{spans_the_boundary_of_two_chunks}"
        padding = b" " * 50
        data = padding + payload
        path = helpers.write_file(os.path.join(self.work, "boundary.txt"), data)
        result = flagscan.scan_path(path, chunk_size=60, overlap=20)
        flag_matches = [m for m in result.matches if m.pattern == "flag_braces"]
        self.assertEqual(len(flag_matches), 1, result.matches)
        self.assertEqual(flag_matches[0].offset, len(padding))

    def test_max_matches_per_file_caps_results(self):
        data = b" ".join(f"flag{{n{i}}}".encode() for i in range(50))
        path = helpers.write_file(os.path.join(self.work, "many.txt"), data)
        result = flagscan.scan_path(path, max_matches_per_file=5, max_total_matches=1000)
        flag_matches = [m for m in result.matches if m.pattern == "flag_braces"]
        self.assertLessEqual(len(flag_matches), 5)

    def test_large_sparse_file_scanned_quickly_without_loading_whole_file(self):
        # A naive whole-file mmap/read would still work correctness-wise on
        # a sparse file (the kernel materializes zero pages on demand), but
        # this is the cheapest way to prove the scanner is chunked rather
        # than doing one giant read: a 200 MiB sparse file with the target
        # near the end must scan in a couple of seconds, not balloon
        # memory or wall-clock proportional to a naive full-file approach.
        path = os.path.join(self.work, "sparse.bin")
        size = 200 * 1024 * 1024
        with open(path, "wb") as handle:
            handle.truncate(size)
            handle.seek(size - 100)
            handle.write(b"flag{near_the_end_of_a_sparse_file}")
        started = time.monotonic()
        result = flagscan.scan_path(path, chunk_size=1024 * 1024, overlap=4096)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 10.0, "scan of a sparse file took too long")
        flag_matches = [m for m in result.matches if m.pattern == "flag_braces"]
        self.assertEqual(len(flag_matches), 1)
        self.assertEqual(flag_matches[0].offset, size - 100)

    def test_max_total_matches_sets_capped_flag(self):
        os.makedirs(os.path.join(self.work, "d1"))
        os.makedirs(os.path.join(self.work, "d2"))
        helpers.write_file(os.path.join(self.work, "d1", "one.txt"), b"flag{aaaa} flag{bbbb} flag{cccc}")
        helpers.write_file(os.path.join(self.work, "d2", "two.txt"), b"flag{dddd} flag{eeee} flag{ffff}")
        result = flagscan.scan_path(self.work, max_total_matches=2)
        self.assertTrue(result.capped)
        self.assertLessEqual(len(result.matches), 2)


class TestUserPatterns(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_valid_user_regex_matches(self):
        path = helpers.write_file(os.path.join(self.work, "u.txt"), b"secret-code: ZZZ-1234")
        result = flagscan.scan_path(path, extra_patterns=[r"ZZZ-\d+"])
        user_matches = [m for m in result.matches if m.pattern == "user_0"]
        self.assertEqual(len(user_matches), 1)
        self.assertEqual(user_matches[0].snippet, "ZZZ-1234")

    def test_invalid_user_regex_rejected_before_scanning(self):
        path = helpers.write_file(os.path.join(self.work, "u2.txt"), b"data")
        with self.assertRaises(flagscan.InvalidPattern):
            flagscan.scan_path(path, extra_patterns=["("])  # unbalanced paren

    def test_oversized_user_regex_source_rejected_before_scanning(self):
        # Bounding execution time (the timeout/kill machinery below) does
        # nothing to bound *compile*-time cost of a source string that is
        # itself absurdly large. This must be rejected independently.
        path = helpers.write_file(os.path.join(self.work, "u3.txt"), b"data")
        oversized = "a" * (flagscan._MAX_USER_PATTERN_LENGTH + 1)
        with self.assertRaises(flagscan.InvalidPattern):
            flagscan.scan_path(path, extra_patterns=[oversized])

    def test_user_regex_source_at_exact_limit_accepted(self):
        path = helpers.write_file(os.path.join(self.work, "u4.txt"), b"data")
        at_limit = "a" * flagscan._MAX_USER_PATTERN_LENGTH
        result = flagscan.scan_path(path, extra_patterns=[at_limit])
        self.assertEqual(result.matches, [])

    def test_pathological_user_regex_is_skipped_not_hung(self):
        # Classic catastrophic-backtracking pattern against a string with
        # no trailing terminator: (a+)+$ on "aaaa...!" degrades
        # exponentially in CPython's re engine.
        payload = (b"a" * 40) + b"!"
        path = helpers.write_file(os.path.join(self.work, "redos.txt"), payload)
        result = flagscan.scan_path(
            path,
            extra_patterns=[r"(a+)+$"],
            per_file_timeout=1.0,
            per_pattern_timeout=1.0,
        )
        skipped_labels = {s.pattern for s in result.skipped}
        self.assertIn("user_0", skipped_labels)
        # Other builtin patterns for the same file must still be reported,
        # not silently dropped because one pattern was pathological.
        self.assertEqual(result.files_scanned, 1)

    def test_oversized_match_snippet_truncated_but_length_reports_true_span(self):
        # The snippet is capped at 256 bytes for display, but Match.length
        # must still report the *true* match length so an analyst citing
        # this as flag evidence can carve out [offset, offset+length) for
        # a minimal reproduction without silently truncating the real data.
        full_len = 5000
        payload = b"START" + (b"x" * (full_len - len(b"STARTEND"))) + b"END"
        self.assertEqual(len(payload), full_len)
        path = helpers.write_file(os.path.join(self.work, "oversized.txt"), payload)
        result = flagscan.scan_path(path, extra_patterns=[r"(?s)START.*END"])
        user_matches = [m for m in result.matches if m.pattern == "user_0"]
        self.assertEqual(len(user_matches), 1)
        match = user_matches[0]
        self.assertEqual(match.length, full_len)
        self.assertLessEqual(len(match.snippet.encode("utf-8", "replace")), 256)

    def test_pathological_pattern_does_not_block_other_files(self):
        payload = (b"a" * 40) + b"!"
        helpers.write_file(os.path.join(self.work, "bad.txt"), payload)
        helpers.write_file(os.path.join(self.work, "good.txt"), b"flag{fine}")
        result = flagscan.scan_path(
            self.work,
            extra_patterns=[r"(a+)+$"],
            per_file_timeout=1.0,
            per_pattern_timeout=1.0,
        )
        found_paths = {m.path for m in result.matches if m.pattern == "flag_braces"}
        self.assertIn("good.txt", found_paths)


class TestJsonlOutput(unittest.TestCase):
    def test_matches_to_jsonl_round_trips(self):
        work = helpers.make_workdir()
        try:
            path = helpers.write_file(os.path.join(work, "j.txt"), b"flag{jsonl_check}")
            result = flagscan.scan_path(path)
            rendered = flagscan.matches_to_jsonl(result)
            lines = [line for line in rendered.splitlines() if line.strip()]
            self.assertEqual(len(lines), len(result.matches) + len(result.skipped))
            for line in lines:
                json.loads(line)
        finally:
            helpers.rmtree_force(work)

    def test_matches_to_jsonl_preserves_unicode_and_escape_bytes_byte_for_byte(self):
        work = helpers.make_workdir()
        try:
            # flag_braces excludes \r/\n inside the braces by design, so this
            # payload sticks to other escape-worthy bytes: tab, quote,
            # backslash, and non-ASCII Unicode.
            snippet_body = 'weird\ttab"quote\\backslash_유니코드'
            data = f"flag{{{snippet_body}}}".encode("utf-8")
            path = helpers.write_file(os.path.join(work, "unicode.txt"), data)
            result = flagscan.scan_path(path)
            flag_matches = [m for m in result.matches if m.pattern == "flag_braces"]
            self.assertEqual(len(flag_matches), 1)
            self.assertEqual(flag_matches[0].snippet, f"flag{{{snippet_body}}}")

            rendered = flagscan.matches_to_jsonl(result)
            lines = [line for line in rendered.splitlines() if line.strip()]
            decoded = [json.loads(line) for line in lines]
            snippets = {rec["snippet"] for rec in decoded}
            self.assertIn(f"flag{{{snippet_body}}}", snippets)
        finally:
            helpers.rmtree_force(work)


if __name__ == "__main__":
    unittest.main()
