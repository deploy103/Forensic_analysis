"""Adversarial tests for the structured reviewer/final-result gate (15.7)."""

from __future__ import annotations

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

from pyforensic import caselayout, case, commandlog, gate  # noqa: E402


class TestGateBase(unittest.TestCase):
    def setUp(self):
        self.cases_root = helpers.make_cases_root()
        self.addCleanup(helpers.rmtree_force, self.cases_root)
        self.work = helpers.make_workdir()
        self.addCleanup(helpers.rmtree_force, self.work)
        src = helpers.write_file(os.path.join(self.work, "eventlog.bin"), b"evidence-bytes")
        self.case_dir = case.create_case(self.cases_root, "gatecase", [src])
        self.evidence_path = "eventlog.bin"

    def run_ok_command(self):
        return commandlog.run_and_log(self.cases_root, "gatecase", ["printf", "%s", "found-it"])

    def make_candidate(self, log_id=None):
        if log_id is None:
            log_id = self.run_ok_command().log_id
        return gate.add_candidate(
            self.cases_root, "gatecase",
            flag="flag{gate_test}", evidence_path=self.evidence_path,
            locator={"offset": 0}, transformation="none", log_id=log_id,
        )

    def full_happy_path(self):
        candidate = self.make_candidate()
        gate.add_review(
            self.cases_root, "gatecase",
            reviewer="alice", verdict="verified", candidate_ids=[candidate["candidate_id"]],
        )
        repro_log = self.run_ok_command()
        gate.set_reproduction(
            self.cases_root, "gatecase",
            candidate_id=candidate["candidate_id"], log_id=repro_log.log_id,
            commands_summary="printf found-it",
        )
        gate.set_final(self.cases_root, "gatecase", candidate_id=candidate["candidate_id"])
        return candidate


class TestHappyPath(TestGateBase):
    def test_full_chain_passes_gate(self):
        self.full_happy_path()
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertTrue(result.ok, result.reasons)
        self.assertEqual(result.reasons, [])


class TestMissingPieces(TestGateBase):
    def test_gate_fails_with_no_final_json(self):
        self.make_candidate()
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(any("final.json" in r for r in result.reasons))

    def test_gate_fails_with_no_reproduction(self):
        candidate = self.make_candidate()
        gate.add_review(
            self.cases_root, "gatecase",
            reviewer="alice", verdict="verified", candidate_ids=[candidate["candidate_id"]],
        )
        gate.set_final(self.cases_root, "gatecase", candidate_id=candidate["candidate_id"])
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(any("reproduction.json" in r for r in result.reasons))

    def test_gate_fails_with_no_verifying_review(self):
        candidate = self.make_candidate()
        repro_log = self.run_ok_command()
        gate.set_reproduction(
            self.cases_root, "gatecase",
            candidate_id=candidate["candidate_id"], log_id=repro_log.log_id,
            commands_summary="x",
        )
        gate.set_final(self.cases_root, "gatecase", candidate_id=candidate["candidate_id"])
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(any("no review record" in r for r in result.reasons))

    def test_rejected_verdict_does_not_satisfy_gate(self):
        candidate = self.make_candidate()
        gate.add_review(
            self.cases_root, "gatecase",
            reviewer="alice", verdict="rejected", candidate_ids=[candidate["candidate_id"]],
        )
        repro_log = self.run_ok_command()
        gate.set_reproduction(
            self.cases_root, "gatecase",
            candidate_id=candidate["candidate_id"], log_id=repro_log.log_id,
            commands_summary="x",
        )
        gate.set_final(self.cases_root, "gatecase", candidate_id=candidate["candidate_id"])
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)

    def test_pending_verdict_does_not_satisfy_gate(self):
        # "needs-more-evidence" is a valid verdict value (the reviewer did
        # act, and did not reject), but it must not be treated as equivalent
        # to "verified" -- a case must not be gate-passable while a review
        # is still pending further evidence.
        candidate = self.make_candidate()
        gate.add_review(
            self.cases_root, "gatecase",
            reviewer="alice", verdict="needs-more-evidence", candidate_ids=[candidate["candidate_id"]],
        )
        repro_log = self.run_ok_command()
        gate.set_reproduction(
            self.cases_root, "gatecase",
            candidate_id=candidate["candidate_id"], log_id=repro_log.log_id,
            commands_summary="x",
        )
        gate.set_final(self.cases_root, "gatecase", candidate_id=candidate["candidate_id"])
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(any("no review record" in r for r in result.reasons), result.reasons)


class TestStaleness(TestGateBase):
    def test_review_becomes_stale_after_candidates_file_changes(self):
        candidate = self.full_happy_path()
        # Add a second, unrelated candidate after the review was recorded;
        # this changes candidates.jsonl's content hash, so the *existing*
        # review's snapshotted binding no longer matches current state.
        log_id = self.run_ok_command().log_id
        gate.add_candidate(
            self.cases_root, "gatecase",
            flag="flag{unrelated}", evidence_path=self.evidence_path,
            locator={"offset": 5}, transformation="none", log_id=log_id,
        )
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(any("stale" in r for r in result.reasons), result.reasons)
        self.assertEqual(candidate["flag"], "flag{gate_test}")  # sanity: candidate unaffected

    def test_review_becomes_stale_after_evidence_added(self):
        self.full_happy_path()
        extra_src = helpers.write_file(os.path.join(self.work, "extra.bin"), b"more-evidence")
        from pyforensic import case as case_mod
        case_mod.add_evidence(self.cases_root, "gatecase", [extra_src])
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(any("stale" in r for r in result.reasons), result.reasons)


class TestEvidenceTamperedAfterFinal(TestGateBase):
    def test_evidence_bytes_changed_after_final_immediately_fails_gate(self):
        self.full_happy_path()
        evidence_file = os.path.join(self.case_dir, caselayout.EVIDENCE_DIR, self.evidence_path)
        original_mode = os.stat(evidence_file).st_mode
        os.chmod(evidence_file, 0o644)
        try:
            with open(evidence_file, "wb") as handle:
                handle.write(b"TAMPERED-AFTER-FINAL")
        finally:
            os.chmod(evidence_file, original_mode)
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(
            any("evidence integrity check failed" in r for r in result.reasons), result.reasons
        )


class TestReviewerIdentityTrustBoundary(TestGateBase):
    """Documents a known, deliberate trust boundary (see gate.py's module
    docstring): reviewer identity is a free-text field with no
    authentication behind it. The gate binds a review to *what was
    reviewed* (content hashes) but not to *who* actually reviewed it --
    anyone with write access to the case tree can record a review under any
    name. This is intentional (this module is tamper-evidence, not a
    cryptographic signature scheme) and is pinned here as a test so the
    behavior is documented rather than silently assumed.
    """

    def test_fabricated_reviewer_name_still_satisfies_the_gate(self):
        candidate = self.make_candidate()
        gate.add_review(
            self.cases_root, "gatecase",
            reviewer="definitely-not-a-real-reviewer-nobody-verified-this",
            verdict="verified", candidate_ids=[candidate["candidate_id"]],
        )
        repro_log = self.run_ok_command()
        gate.set_reproduction(
            self.cases_root, "gatecase",
            candidate_id=candidate["candidate_id"], log_id=repro_log.log_id,
            commands_summary="x",
        )
        gate.set_final(self.cases_root, "gatecase", candidate_id=candidate["candidate_id"])
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertTrue(result.ok, result.reasons)


class TestConflictingCandidatesDoNotBreakGate(TestGateBase):
    def test_unrelated_candidate_with_conflicting_flag_for_same_evidence_is_harmless(self):
        # Two candidates recorded for the exact same evidence_path+locator
        # with different flag guesses is not, by itself, a tamper signal --
        # candidates are hypotheses. Only the specific candidate bound
        # through review -> reproduction -> final matters to the gate; an
        # extra, never-reviewed conflicting guess sitting in candidates.jsonl
        # must not crash the gate or cause it to pass/fail incorrectly.
        log_id = self.run_ok_command().log_id
        real_candidate = gate.add_candidate(
            self.cases_root, "gatecase",
            flag="flag{real_one}", evidence_path=self.evidence_path,
            locator={"offset": 0}, transformation="none", log_id=log_id,
        )
        gate.add_candidate(
            self.cases_root, "gatecase",
            flag="flag{decoy_guess}", evidence_path=self.evidence_path,
            locator={"offset": 0}, transformation="none", log_id=log_id,
        )
        gate.add_review(
            self.cases_root, "gatecase",
            reviewer="alice", verdict="verified", candidate_ids=[real_candidate["candidate_id"]],
        )
        repro_log = self.run_ok_command()
        gate.set_reproduction(
            self.cases_root, "gatecase",
            candidate_id=real_candidate["candidate_id"], log_id=repro_log.log_id,
            commands_summary="x",
        )
        gate.set_final(self.cases_root, "gatecase", candidate_id=real_candidate["candidate_id"])
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertTrue(result.ok, result.reasons)


class TestLocatorBoundsTrustBoundary(TestGateBase):
    """gate.add_candidate stores ``locator`` opaquely (it is a free-form dict
    whose shape depends on the evidence type -- byte offset, pcap frame
    index, sqlite row id, ...); the gate never cross-checks it against the
    referenced evidence file's actual size or structure. Correctness of the
    locator is established by the human review + reproduction chain, not by
    gate-side bounds checking, which could not be done generically across
    evidence types. Pinned as a test rather than left as an undocumented
    assumption.
    """

    def test_out_of_bounds_offset_locator_is_accepted_not_validated(self):
        log_id = self.run_ok_command().log_id
        candidate = gate.add_candidate(
            self.cases_root, "gatecase",
            flag="flag{oob}", evidence_path=self.evidence_path,
            locator={"offset": 999_999_999}, transformation="none", log_id=log_id,
        )
        self.assertEqual(candidate["locator"], {"offset": 999_999_999})


class TestReproductionIntegrity(TestGateBase):
    def test_set_reproduction_rejects_nonzero_exit_command(self):
        candidate = self.make_candidate()
        bad_log = commandlog.run_and_log(self.cases_root, "gatecase", ["sh", "-c", "exit 3"])
        with self.assertRaises(gate.GateError):
            gate.set_reproduction(
                self.cases_root, "gatecase",
                candidate_id=candidate["candidate_id"], log_id=bad_log.log_id,
                commands_summary="x",
            )

    def test_gate_detects_tampered_reproduction_output(self):
        candidate = self.full_happy_path()
        repro = gate._read_json_object(
            os.path.join(self.case_dir, caselayout.REPRODUCTION_JSON), gate.REPRODUCTION_FIELDS, "reproduction.json"
        )
        commands = {r["log_id"]: r for r in commandlog.read_command_log(self.case_dir)}
        output_path = os.path.join(self.case_dir, commands[repro["log_id"]]["combined_output"])
        with open(output_path, "wb") as handle:
            handle.write(b"TAMPERED OUTPUT")
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(any("output_sha256" in r for r in result.reasons), result.reasons)


class TestCandidateAndReviewValidation(TestGateBase):
    def test_add_candidate_rejects_unknown_evidence_path(self):
        log_id = self.run_ok_command().log_id
        with self.assertRaises(gate.GateError):
            gate.add_candidate(
                self.cases_root, "gatecase",
                flag="flag{x}", evidence_path="does/not/exist.bin",
                locator={}, transformation="none", log_id=log_id,
            )

    def test_add_candidate_rejects_unknown_log_id(self):
        with self.assertRaises(gate.GateError):
            gate.add_candidate(
                self.cases_root, "gatecase",
                flag="flag{x}", evidence_path=self.evidence_path,
                locator={}, transformation="none", log_id="never-logged",
            )

    def test_add_candidate_rejects_blank_flag(self):
        log_id = self.run_ok_command().log_id
        with self.assertRaises(gate.GateError):
            gate.add_candidate(
                self.cases_root, "gatecase",
                flag="   ", evidence_path=self.evidence_path,
                locator={}, transformation="none", log_id=log_id,
            )

    def test_add_review_rejects_unknown_candidate_id(self):
        with self.assertRaises(gate.GateError):
            gate.add_review(
                self.cases_root, "gatecase",
                reviewer="alice", verdict="verified", candidate_ids=["c999"],
            )

    def test_add_review_rejects_invalid_verdict(self):
        candidate = self.make_candidate()
        with self.assertRaises(gate.GateError):
            gate.add_review(
                self.cases_root, "gatecase",
                reviewer="alice", verdict="lgtm", candidate_ids=[candidate["candidate_id"]],
            )

    def test_add_review_rejects_blank_reviewer(self):
        candidate = self.make_candidate()
        with self.assertRaises(gate.GateError):
            gate.add_review(
                self.cases_root, "gatecase",
                reviewer="  ", verdict="verified", candidate_ids=[candidate["candidate_id"]],
            )

    def test_set_final_rejects_unknown_candidate_id(self):
        with self.assertRaises(gate.GateError):
            gate.set_final(self.cases_root, "gatecase", candidate_id="c999")


class TestMalformedRecords(TestGateBase):
    def test_duplicate_candidate_id_reported_not_crashed(self):
        candidate = self.make_candidate()
        candidates_path = os.path.join(self.case_dir, caselayout.CANDIDATES_JSONL)
        duplicate = dict(candidate)
        duplicate["flag"] = "flag{duplicate_id}"
        with open(candidates_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(duplicate, sort_keys=True) + "\n")
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(any("duplicate candidate_id" in r for r in result.reasons), result.reasons)

    def test_malformed_json_line_in_candidates_reported_not_crashed(self):
        candidates_path = os.path.join(self.case_dir, caselayout.CANDIDATES_JSONL)
        os.makedirs(os.path.dirname(candidates_path), exist_ok=True)
        with open(candidates_path, "a", encoding="utf-8") as handle:
            handle.write("{not valid json\n")
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)

    def test_unknown_field_in_candidates_line_rejected(self):
        candidate = self.make_candidate()
        candidates_path = os.path.join(self.case_dir, caselayout.CANDIDATES_JSONL)
        with open(candidates_path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
        obj = json.loads(lines[0])
        obj["unexpected_extra_field"] = "sneaky"
        with open(candidates_path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(obj, sort_keys=True) + "\n")
        result = gate.run_gate(self.cases_root, "gatecase")
        self.assertFalse(result.ok)
        self.assertTrue(any("unknown field" in r for r in result.reasons), result.reasons)


class TestAddCandidateCliLocatorParsing(TestGateBase):
    """Regression test for a real bug in the bin/add-candidate CLI wiring.

    cmd_add_candidate in cli.py used to pass --locator's raw string argv
    value straight through to gate.add_candidate(locator=...), which
    declares locator as a dict. Nothing enforced that at runtime, so every
    candidate recorded through the actual CLI (as opposed to calling
    gate.add_candidate directly, which every prior test in this file does)
    silently stored locator as a JSON *string* like "{\"offset\": 0}"
    instead of a JSON object {"offset": 0} -- the schema documented in
    docs/case-schema.md and relied on by any downstream consumer that reads
    candidate["locator"]["offset"]. Fixed by json.loads-ing --locator in
    cmd_add_candidate before calling gate.add_candidate.
    """

    def test_locator_flag_is_parsed_as_a_json_object_not_stored_as_a_string(self):
        log_id = self.run_ok_command().log_id
        proc = helpers.run_bin(
            "add-candidate",
            ["gatecase", "--flag", "flag{cli_locator}", "--evidence", self.evidence_path,
             "--locator", '{"offset": 5}', "--transformation", "none", "--log-id", log_id, "--json"],
            cases_root=self.cases_root,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        record = json.loads(proc.stdout)
        self.assertEqual(record["locator"], {"offset": 5})
        candidates_path = os.path.join(self.case_dir, caselayout.CANDIDATES_JSONL)
        with open(candidates_path, "r", encoding="utf-8") as handle:
            stored = json.loads(handle.read().splitlines()[-1])
        self.assertEqual(stored["locator"], {"offset": 5})
        self.assertIsInstance(stored["locator"], dict)

    def test_non_json_locator_is_rejected_with_usage_error(self):
        log_id = self.run_ok_command().log_id
        proc = helpers.run_bin(
            "add-candidate",
            ["gatecase", "--flag", "flag{x}", "--evidence", self.evidence_path,
             "--locator", "not-json", "--transformation", "none", "--log-id", log_id],
            cases_root=self.cases_root,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"--locator", proc.stderr)

    def test_json_scalar_locator_is_rejected_because_it_is_not_an_object(self):
        log_id = self.run_ok_command().log_id
        proc = helpers.run_bin(
            "add-candidate",
            ["gatecase", "--flag", "flag{x}", "--evidence", self.evidence_path,
             "--locator", "5", "--transformation", "none", "--log-id", log_id],
            cases_root=self.cases_root,
        )
        self.assertNotEqual(proc.returncode, 0)


class TestFinalJsonSafeWrite(TestGateBase):
    def test_final_json_rejects_hardlinked_target(self):
        candidate = self.make_candidate()
        final_path = os.path.join(self.case_dir, caselayout.FINAL_JSON)
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        with open(final_path, "w", encoding="utf-8") as handle:
            handle.write("{}\n")
        alias = final_path + ".alias"
        os.link(final_path, alias)
        with self.assertRaises(gate.GateError):
            gate.set_final(self.cases_root, "gatecase", candidate_id=candidate["candidate_id"])

    def test_final_json_rejects_symlinked_target(self):
        # Distinct from the hardlink case above: a symlink at final.json's
        # path must be rejected as a clean GateError, not crash the CLI
        # with a raw OSError(ELOOP) -- cli.py's cmd_set_final only catches
        # gate.GateError, so any other exception type here would surface as
        # an unhandled traceback instead of a usage-level failure.
        candidate = self.make_candidate()
        final_path = os.path.join(self.case_dir, caselayout.FINAL_JSON)
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        target = os.path.join(self.work, "elsewhere.json")
        with open(target, "w", encoding="utf-8") as handle:
            handle.write("{}\n")
        os.symlink(target, final_path)
        with self.assertRaises(gate.GateError):
            gate.set_final(self.cases_root, "gatecase", candidate_id=candidate["candidate_id"])


if __name__ == "__main__":
    unittest.main()
