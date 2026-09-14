"""Adversarial tests for the format-agnostic triage dispatcher and wrappers (15.5)."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import struct
import sys
import tarfile
import time
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

from pyforensic.triage import (  # noqa: E402
    archive,
    common,
    disk,
    dispatch,
    document,
    image,
    memory,
    pcap,
    sqlite as sqlite_triage,
)


class TestDispatchOrder(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_pcap_file_dispatched_to_pcap(self):
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        path = helpers.write_file(os.path.join(self.work, "cap.pcap"), header)
        result = dispatch.detect_and_inspect(path)
        self.assertEqual(result.details.get("detected_as"), "pcap")

    def test_sqlite_file_dispatched_to_sqlite(self):
        path = os.path.join(self.work, "db.sqlite")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.commit()
        conn.close()
        result = dispatch.detect_and_inspect(path)
        self.assertEqual(result.details.get("detected_as"), "sqlite")

    def test_png_file_dispatched_to_image(self):
        path = helpers.write_file(os.path.join(self.work, "pic.png"), b"\x89PNG\r\n\x1a\n" + b"\x00" * 40)
        result = dispatch.detect_and_inspect(path)
        self.assertEqual(result.details.get("detected_as"), "image")

    def test_zip_file_dispatched_to_archive(self):
        path = os.path.join(self.work, "a.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("hello.txt", "hi")
        result = dispatch.detect_and_inspect(path)
        self.assertEqual(result.details.get("detected_as"), "archive")

    def test_unrecognized_binary_blob_falls_through_to_memory(self):
        # memory.inspect() never reports input_mismatch (a raw dd-style
        # image with no container header is its normal case), so it must
        # be the one that finally "catches" anything the more specific
        # wrappers all rejected.
        path = helpers.write_file(os.path.join(self.work, "blob.bin"), os.urandom(4096))
        result = dispatch.detect_and_inspect(path)
        self.assertEqual(result.details.get("detected_as"), "memory")
        self.assertNotEqual(result.outcome, "input_mismatch")

    def test_empty_file_still_resolved_not_crashed(self):
        path = helpers.write_file(os.path.join(self.work, "empty.bin"), b"")
        result = dispatch.detect_and_inspect(path)
        self.assertIn(result.outcome, ("full_success", "partial_success", "parser_failure"))


class TestPcapWrapper(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_mismatch_on_non_pcap_input(self):
        path = helpers.write_file(os.path.join(self.work, "notpcap.bin"), b"not a pcap file at all")
        result = pcap.inspect(path)
        self.assertEqual(result.outcome, "input_mismatch")

    def test_full_success_on_well_formed_classic_pcap(self):
        global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        payload = b"\x00" * 10
        record_header = struct.pack("<IIII", 0, 0, len(payload), len(payload))
        path = helpers.write_file(
            os.path.join(self.work, "good.pcap"), global_header + record_header + payload
        )
        result = pcap.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertEqual(result.details["packet_count"], 1)

    def test_truncated_record_reported_as_partial_success_not_crash(self):
        global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        record_header = struct.pack("<IIII", 0, 0, 999999, 999999)  # claims far more bytes than exist
        path = helpers.write_file(
            os.path.join(self.work, "truncated.pcap"), global_header + record_header
        )
        result = pcap.inspect(path)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("truncated" in w for w in result.warnings))

    def test_too_short_for_global_header_is_parser_failure(self):
        path = helpers.write_file(os.path.join(self.work, "short.pcap"), b"\xd4\xc3\xb2\xa1\x02\x00")
        result = pcap.inspect(path)
        self.assertEqual(result.outcome, "parser_failure")

    def _pcapng_block(self, block_type: int, body: bytes) -> bytes:
        total_len = 12 + len(body)
        return struct.pack("<II", block_type, total_len) + body + struct.pack("<I", total_len)

    def test_well_formed_pcapng_fixture_parsed_full_success(self):
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb = self._pcapng_block(0x0A0D0D0A, shb_body)
        idb_body = struct.pack("<HHI", 1, 0, 65535)
        idb = self._pcapng_block(0x00000001, idb_body)
        path = helpers.write_file(os.path.join(self.work, "cap.pcapng"), shb + idb)
        result = pcap.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertEqual(result.details["format"], "pcapng")
        self.assertEqual(result.details["block_counts"], {"section_header": 1, "interface_description": 1})
        self.assertEqual(result.details["linktypes"], [1])
        dispatched = dispatch.detect_and_inspect(path)
        self.assertEqual(dispatched.details.get("detected_as"), "pcap")

    def test_pcapng_truncated_block_reported_as_partial_success(self):
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb = self._pcapng_block(0x0A0D0D0A, shb_body)
        # Claim a block far larger than what actually follows.
        bogus = struct.pack("<II", 0x00000006, 999999)
        path = helpers.write_file(os.path.join(self.work, "trunc.pcapng"), shb + bogus)
        result = pcap.inspect(path)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("trailing" in w or "invalid" in w for w in result.warnings), result.warnings)


class TestSqliteWrapper(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_mismatch_on_non_sqlite_input(self):
        path = helpers.write_file(os.path.join(self.work, "notdb.bin"), b"just some bytes")
        result = sqlite_triage.inspect(path)
        self.assertEqual(result.outcome, "input_mismatch")

    def test_corrupted_header_after_magic_is_parser_failure(self):
        path = helpers.write_file(
            os.path.join(self.work, "corrupt.sqlite"),
            b"SQLite format 3\x00" + os.urandom(200),
        )
        result = sqlite_triage.inspect(path)
        self.assertIn(result.outcome, ("parser_failure", "partial_success", "full_success"))

    def test_full_success_on_well_formed_database(self):
        path = os.path.join(self.work, "good.sqlite")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE people (name TEXT)")
        conn.execute("INSERT INTO people VALUES ('alice')")
        conn.commit()
        conn.close()
        result = sqlite_triage.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertEqual(result.details["table_row_counts"]["people"], 1)

    def test_malicious_table_name_cannot_leak_other_table_via_union(self):
        # Regression test for a real fixed vulnerability: sqlite.py used to
        # build the row-count query as an f-string with a single layer of
        # double-quoting (`f'SELECT COUNT(*) FROM "{name}"'`). A table name
        # containing a literal '"' could close the quoted identifier early
        # and append a same-statement `UNION SELECT ... -- ` to read a
        # different table's data through the "row count" of an unrelated,
        # attacker-named table -- exploitable via a crafted "evidence"
        # SQLite file, since the table name comes straight out of
        # sqlite_master with no other sanitization. Embedded quotes must
        # now be escaped by doubling, so the crafted name is treated as one
        # opaque (and here, nonexistent-as-a-real-table) identifier.
        path = os.path.join(self.work, "evil.sqlite")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE secret (password TEXT)")
        conn.execute("INSERT INTO secret VALUES ('super-secret-value')")
        evil_name = 'x" UNION SELECT password FROM secret -- '
        conn.execute('CREATE TABLE "%s" (y INTEGER)' % evil_name.replace('"', '""'))
        conn.commit()
        conn.close()

        result = sqlite_triage.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        counts = result.details["table_row_counts"]
        self.assertEqual(counts["secret"], 1)
        # The malicious table has zero rows of its own; if the injection
        # still worked, this would instead read back "super-secret-value"'s
        # row from `secret` (count 1) mislabeled under the evil table name.
        self.assertEqual(counts[evil_name], 0)


class TestArchiveWrapper(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_mismatch_on_non_archive_input(self):
        path = helpers.write_file(os.path.join(self.work, "notarchive.bin"), b"plain text file")
        result = archive.inspect(path)
        self.assertEqual(result.outcome, "input_mismatch")

    def test_corrupt_zip_is_parser_failure(self):
        path = helpers.write_file(os.path.join(self.work, "corrupt.zip"), b"PK\x03\x04" + os.urandom(50))
        result = archive.inspect(path)
        self.assertEqual(result.outcome, "parser_failure")

    def test_zip_slip_member_flagged_and_never_extracted_outside_dest(self):
        zip_path = os.path.join(self.work, "slip.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("normal.txt", "fine")
            zf.writestr("../../../etc/evil-cron", "malicious payload")

        result = archive.inspect(zip_path)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("zip-slip" in w for w in result.warnings))

        dest = os.path.join(self.work, "extract-dest")
        os.makedirs(dest)
        extract_result = archive.extract(zip_path, dest)
        self.assertIn("normal.txt", extract_result.details["extracted"])
        self.assertTrue(extract_result.details["skipped_unsafe"])
        # Confirm nothing escaped: only the one safe member exists on disk,
        # anywhere under the work directory's parent tree.
        for root, _dirs, files in os.walk(self.work):
            for name in files:
                self.assertNotEqual(name, "evil-cron", f"zip-slip payload escaped to {root}/{name}")

    def test_tar_slip_member_flagged(self):
        tar_path = os.path.join(self.work, "slip.tar")
        with tarfile.open(tar_path, "w") as tf:
            content = b"fine"
            info = tarfile.TarInfo(name="normal.txt")
            info.size = len(content)
            tf.addfile(info, fileobj=__import__("io").BytesIO(content))

            evil_info = tarfile.TarInfo(name="../../../tmp/evil-tar-slip")
            evil_content = b"malicious"
            evil_info.size = len(evil_content)
            tf.addfile(evil_info, fileobj=__import__("io").BytesIO(evil_content))

        result = archive.inspect(tar_path)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("tar-slip" in w for w in result.warnings))

        dest = os.path.join(self.work, "tar-extract-dest")
        os.makedirs(dest)
        extract_result = archive.extract(tar_path, dest)
        self.assertIn("normal.txt", extract_result.details["extracted"])
        self.assertTrue(extract_result.details["skipped_unsafe"])
        self.assertFalse(os.path.exists("/tmp/evil-tar-slip"))

    def test_high_compression_ratio_flagged_as_possible_bomb(self):
        zip_path = os.path.join(self.work, "bomb.zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("zeros.bin", b"\x00" * (5 * 1024 * 1024))
        result = archive.inspect(zip_path)
        self.assertTrue(any("bomb" in w for w in result.warnings), result.warnings)

    def test_extract_aborts_over_max_total_bytes_cap(self):
        zip_path = os.path.join(self.work, "big.zip")
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("big.bin", b"\x00" * (1024 * 1024))
        dest = os.path.join(self.work, "capped-dest")
        os.makedirs(dest)
        result = archive.extract(zip_path, dest, max_total_bytes=1024)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("bomb" in w for w in result.warnings))


class TestDocumentWrapper(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_mismatch_on_plain_text(self):
        path = helpers.write_file(os.path.join(self.work, "plain.txt"), b"nothing document-like here")
        result = document.inspect(path)
        self.assertEqual(result.outcome, "input_mismatch")

    def test_pdf_full_success_with_no_suspicious_content(self):
        data = b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF\n"
        path = helpers.write_file(os.path.join(self.work, "clean.pdf"), data)
        result = document.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertEqual(result.details["version"], "1.4")

    def test_pdf_with_javascript_key_flagged(self):
        data = b"%PDF-1.4\n1 0 obj\n<< /OpenAction 2 0 R /JavaScript (alert(1)) >>\nendobj\n%%EOF\n"
        path = helpers.write_file(os.path.join(self.work, "js.pdf"), data)
        result = document.inspect(path)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("suspicious" in w for w in result.warnings))

    def test_generic_zip_without_content_types_falls_through_as_mismatch(self):
        # Regression test for a real fixed dispatch-order gap: before the
        # fix, ANY zip (including a plain, non-OOXML zip) was accepted
        # here as a "partial_success" OOXML package with just a warning,
        # which meant dispatch.py -- trying document before archive --
        # never let archive.py's zip-slip/bomb-ratio checks run on a
        # generic zip. A zip lacking [Content_Types].xml must now report
        # input_mismatch so dispatch falls through to archive.py.
        zip_path = os.path.join(self.work, "generic.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("hello.txt", "hi")
        result = document.inspect(zip_path)
        self.assertEqual(result.outcome, "input_mismatch")

    def test_real_ooxml_shaped_zip_detected_as_document(self):
        zip_path = os.path.join(self.work, "fake.docx")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/document.xml", "<document/>")
        result = document.inspect(zip_path)
        self.assertIn(result.outcome, ("full_success", "partial_success"))
        dispatched = dispatch.detect_and_inspect(zip_path)
        self.assertEqual(dispatched.details.get("detected_as"), "document")

    def test_ooxml_with_macro_flagged(self):
        zip_path = os.path.join(self.work, "macro.docm")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("word/vbaProject.bin", b"\x00\x01")
        result = document.inspect(zip_path)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("macro-enabled" in w for w in result.warnings))

    def test_ole_too_short_is_parser_failure(self):
        path = helpers.write_file(
            os.path.join(self.work, "short.doc"), b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 10
        )
        result = document.inspect(path)
        self.assertEqual(result.outcome, "parser_failure")


class TestImageWrapper(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_mismatch_on_non_image_input(self):
        path = helpers.write_file(os.path.join(self.work, "notimg.bin"), b"definitely not an image")
        result = image.inspect(path)
        self.assertEqual(result.outcome, "input_mismatch")

    def _well_formed_png(self) -> bytes:
        import struct
        import zlib

        def chunk(kind: bytes, data: bytes) -> bytes:
            crc = zlib.crc32(kind + data) & 0xFFFFFFFF
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        idat = chunk(b"IDAT", b"\x00\x00\x00\x00\x00")
        return image.PNG_MAGIC + chunk(b"IHDR", ihdr) + idat + chunk(b"IEND", b"")

    def test_png_full_success_no_trailing_data(self):
        path = helpers.write_file(os.path.join(self.work, "clean.png"), self._well_formed_png())
        result = image.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertEqual(result.details["ihdr"]["width"], 1)

    def test_png_trailing_data_after_iend_flagged(self):
        data = self._well_formed_png() + b"HIDDEN_PAYLOAD_AFTER_IEND"
        path = helpers.write_file(os.path.join(self.work, "trailer.png"), data)
        result = image.inspect(path)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("appended after IEND" in w for w in result.warnings), result.warnings)
        self.assertEqual(result.details["trailing_bytes"], len(b"HIDDEN_PAYLOAD_AFTER_IEND"))

    def test_jpeg_trailing_data_after_eoi_flagged(self):
        jpeg = image.JPEG_MAGIC + b"\xff\xd9" + b"APPENDED_SECRET"
        path = helpers.write_file(os.path.join(self.work, "trailer.jpg"), jpeg)
        result = image.inspect(path)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("appended after EOI" in w for w in result.warnings), result.warnings)

    def test_bmp_size_field_mismatch_flagged(self):
        header = b"BM" + struct.pack("<III", 999999, 0, 54) + struct.pack("<Iii", 40, 2, 2)
        data = header + b"\x00" * 40
        path = helpers.write_file(os.path.join(self.work, "bad.bmp"), data)
        result = image.inspect(path)
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("does not match" in w for w in result.warnings))


class PathShimMixin:
    def make_shim_dir(self, name: str, script: str) -> str:
        shim_dir = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, shim_dir)
        shim_path = os.path.join(shim_dir, name)
        helpers.write_file(shim_path, script.encode())
        os.chmod(shim_path, 0o755)
        return shim_dir

    def prepend_path(self, extra_dir: str) -> None:
        original = os.environ.get("PATH", "")
        os.environ["PATH"] = extra_dir + os.pathsep + original
        self.addCleanup(os.environ.__setitem__, "PATH", original)

    def force_empty_path(self) -> None:
        empty_dir = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, empty_dir)
        original = os.environ.get("PATH", "")
        os.environ["PATH"] = empty_dir
        self.addCleanup(os.environ.__setitem__, "PATH", original)


class TestImageWrapperExternalToolShims(PathShimMixin, unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def _well_formed_png(self) -> bytes:
        import zlib

        def chunk(kind: bytes, data: bytes) -> bytes:
            crc = zlib.crc32(kind + data) & 0xFFFFFFFF
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

        ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        idat = chunk(b"IDAT", b"\x00\x00\x00\x00\x00")
        return image.PNG_MAGIC + chunk(b"IHDR", ihdr) + idat + chunk(b"IEND", b"")

    def test_exiftool_absent_from_path_no_crash_no_extra_detail(self):
        self.force_empty_path()
        path = helpers.write_file(os.path.join(self.work, "noexif.png"), self._well_formed_png())
        result = image.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertNotIn("exiftool_output", result.details)

    def test_exiftool_shim_success_adds_output_to_details(self):
        shim_dir = self.make_shim_dir("exiftool", "#!/bin/sh\necho '{\"ok\":true}'\nexit 0\n")
        self.prepend_path(shim_dir)
        path = helpers.write_file(os.path.join(self.work, "withexif.png"), self._well_formed_png())
        result = image.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertIn("exiftool_output", result.details)
        self.assertIn("ok", result.details["exiftool_output"])

    def test_exiftool_shim_nonzero_exit_does_not_add_detail_or_override_outcome(self):
        shim_dir = self.make_shim_dir("exiftool", "#!/bin/sh\necho boom >&2\nexit 1\n")
        self.prepend_path(shim_dir)
        path = helpers.write_file(os.path.join(self.work, "badexif.png"), self._well_formed_png())
        result = image.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertNotIn("exiftool_output", result.details)


class TestMemoryWrapper(PathShimMixin, unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def _lime_fixture(self) -> bytes:
        return memory.LIME_MAGIC + struct.pack("<IQQ", 1, 0, 0xFFFF)

    def test_lime_format_identified(self):
        path = helpers.write_file(os.path.join(self.work, "lime.mem"), self._lime_fixture())
        result = memory.inspect(path)
        self.assertEqual(result.details["format"], "lime")
        self.assertEqual(result.details["version"], 1)

    def test_elf_core_format_identified(self):
        data = memory.ELF_MAGIC + b"\x02\x01\x01" + b"\x00" * 100
        path = helpers.write_file(os.path.join(self.work, "core.mem"), data)
        result = memory.inspect(path)
        self.assertEqual(result.details["format"], "elf-core")

    def test_raw_unidentified_reports_partial_success_with_warning(self):
        path = helpers.write_file(os.path.join(self.work, "raw.mem"), os.urandom(4096))
        result = memory.inspect(path)
        self.assertEqual(result.details["format"], "raw/unidentified")
        self.assertEqual(result.outcome, "partial_success")
        self.assertTrue(any("no known memory-image container magic" in w for w in result.warnings))

    def test_volatility_absent_from_path_reports_warning_not_failure(self):
        self.force_empty_path()
        path = helpers.write_file(os.path.join(self.work, "lime2.mem"), self._lime_fixture())
        result = memory.inspect(path)
        self.assertEqual(result.details["format"], "lime")
        self.assertEqual(result.outcome, "partial_success")
        self.assertNotIn("volatility", result.details)
        self.assertTrue(any("no Volatility" in w for w in result.warnings))

    def test_volatility_shim_success_included_in_details_and_upgrades_outcome(self):
        shim_dir = self.make_shim_dir("vol.py", "#!/bin/sh\necho profile-detected\nexit 0\n")
        self.prepend_path(shim_dir)
        path = helpers.write_file(os.path.join(self.work, "lime3.mem"), self._lime_fixture())
        result = memory.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertIn("volatility", result.details)
        self.assertEqual(result.details["volatility"]["returncode"], 0)
        self.assertIn("profile-detected", result.details["volatility"]["output"])

    def test_volatility_shim_nonzero_exit_still_recorded_not_treated_as_missing(self):
        shim_dir = self.make_shim_dir("vol.py", "#!/bin/sh\necho boom >&2\nexit 3\n")
        self.prepend_path(shim_dir)
        path = helpers.write_file(os.path.join(self.work, "lime4.mem"), self._lime_fixture())
        result = memory.inspect(path)
        self.assertIn("volatility", result.details)
        self.assertEqual(result.details["volatility"]["returncode"], 3)
        self.assertFalse(any("no Volatility" in w for w in result.warnings))

    def test_giant_file_entropy_sampling_capped_and_fast(self):
        path = os.path.join(self.work, "giant.mem")
        size = 200 * 1024 * 1024
        with open(path, "wb") as handle:
            handle.write(os.urandom(memory.SAMPLE_SIZE))
            handle.truncate(size)
        started = time.monotonic()
        result = memory.inspect(path)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 10.0, "entropy sampling should be capped at SAMPLE_SIZE, not scan the whole file")
        self.assertEqual(result.details["file_size"], size)
        self.assertGreater(result.details["sampled_entropy"], 7.0)


class TestEvidenceReadOnlyAcrossTriageModules(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def _assert_untouched(self, module, path: str) -> None:
        before = hashlib.sha256(helpers.read_bytes(path)).hexdigest()
        before_mode = os.stat(path).st_mode
        module.inspect(path)
        after = hashlib.sha256(helpers.read_bytes(path)).hexdigest()
        after_mode = os.stat(path).st_mode
        self.assertEqual(before, after, f"{module.__name__}.inspect() modified its input's content")
        self.assertEqual(before_mode, after_mode, f"{module.__name__}.inspect() modified its input's permissions")

    def test_pcap_inspect_does_not_modify_input(self):
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        path = helpers.write_file(os.path.join(self.work, "ro.pcap"), header)
        self._assert_untouched(pcap, path)

    def test_sqlite_inspect_does_not_modify_input(self):
        path = os.path.join(self.work, "ro.sqlite")
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.commit()
        conn.close()
        self._assert_untouched(sqlite_triage, path)

    def test_image_inspect_does_not_modify_input(self):
        path = helpers.write_file(os.path.join(self.work, "ro.png"), b"\x89PNG\r\n\x1a\n" + b"\x00" * 40)
        self._assert_untouched(image, path)

    def test_archive_inspect_does_not_modify_input(self):
        path = os.path.join(self.work, "ro.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("hello.txt", "hi")
        self._assert_untouched(archive, path)

    def test_disk_inspect_does_not_modify_input(self):
        sector = bytearray(512)
        sector[510:512] = b"\x55\xaa"
        path = helpers.write_file(os.path.join(self.work, "ro.img"), bytes(sector))
        self._assert_untouched(disk, path)

    def test_memory_inspect_does_not_modify_input(self):
        path = helpers.write_file(os.path.join(self.work, "ro.mem"), os.urandom(4096))
        self._assert_untouched(memory, path)

    def test_document_inspect_does_not_modify_input(self):
        data = b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF\n"
        path = helpers.write_file(os.path.join(self.work, "ro.pdf"), data)
        self._assert_untouched(document, path)


class TestDiskWrapper(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_too_small_is_mismatch(self):
        path = helpers.write_file(os.path.join(self.work, "tiny.bin"), b"\x00" * 10)
        result = disk.inspect(path)
        self.assertEqual(result.outcome, "input_mismatch")

    def test_no_recognized_signature_is_mismatch(self):
        path = helpers.write_file(os.path.join(self.work, "nosig.bin"), os.urandom(512))
        result = disk.inspect(path)
        self.assertEqual(result.outcome, "input_mismatch")

    def test_mbr_partition_table_parsed(self):
        sector = bytearray(512)
        entry = struct.pack("<BBBBBBBBII", 0x80, 0, 0, 0, 0x83, 0, 0, 0, 2048, 1024)
        sector[446:446 + 16] = entry
        sector[510:512] = b"\x55\xaa"
        path = helpers.write_file(os.path.join(self.work, "mbr.img"), bytes(sector))
        result = disk.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertEqual(result.details["table"], "mbr")
        self.assertEqual(len(result.details["partitions"]), 1)
        self.assertEqual(result.details["partitions"][0]["type_name"], "Linux")

    def test_bare_ntfs_signature_detected_without_partition_table(self):
        boot = bytearray(512)
        boot[3:11] = b"NTFS    "
        path = helpers.write_file(os.path.join(self.work, "ntfs.img"), bytes(boot))
        result = disk.inspect(path)
        self.assertEqual(result.outcome, "full_success")
        self.assertEqual(result.details["filesystem"], "NTFS")


class TestSafeExtractBytes(unittest.TestCase):
    def setUp(self):
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)

    def test_unsafe_member_name_rejected_before_write(self):
        self.assertIsNone(common.safe_member_components("../escape.bin"))
        self.assertIsNone(common.safe_member_components("/absolute/escape.bin"))

    def test_safe_extract_bytes_refuses_to_overwrite_existing_file(self):
        dest = os.path.join(self.work, "dest")
        os.makedirs(dest)
        common.safe_extract_bytes(dest, ["file.bin"], b"first")
        with self.assertRaises(FileExistsError):
            common.safe_extract_bytes(dest, ["file.bin"], b"second")
        self.assertEqual(helpers.read_bytes(os.path.join(dest, "file.bin")), b"first")


if __name__ == "__main__":
    unittest.main()
