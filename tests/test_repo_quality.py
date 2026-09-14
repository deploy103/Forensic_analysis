"""Repository-quality adversarial tests (15.8): syntax, schema, and doc/CLI consistency.

These tests inspect the checked-in repository tree itself (never a throwaway
fixture root) -- there is nothing to fabricate here, only real files to
validate. Where a check reveals a genuine mismatch (as the README-vs-CLI
check did, before the README fix in this same change), the fix belongs in
the repository, not in a weakened assertion.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

ROOT = helpers.PROJECT_ROOT
BIN_DIR = helpers.BIN_DIR

# Directories whose contents are case *payload* or generated/tooling
# artifacts, not tracked repository source -- never scanned by these checks.
_EXCLUDED_DIR_NAMES = {".git", "__pycache__", "cases", ".claude"}


def _walk_repo_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIR_NAMES]
        for name in filenames:
            yield os.path.join(dirpath, name)


def _read_text(path: str) -> str:
    with open(path, "rb") as handle:
        return handle.read().decode("utf-8")


class TestBashSyntax(unittest.TestCase):
    def _shell_scripts(self):
        found = []
        for path in _walk_repo_files():
            try:
                with open(path, "rb") as handle:
                    head = handle.read(64)
            except OSError:
                continue
            if head.startswith(b"#!") and b"bash" in head.split(b"\n", 1)[0]:
                found.append(path)
        return found

    def test_at_least_the_known_bash_scripts_are_found(self):
        found = {os.path.relpath(p, ROOT) for p in self._shell_scripts()}
        self.assertIn("bin/forensic", found)
        self.assertIn("scripts/verify.sh", found)

    def test_every_bash_script_has_valid_syntax(self):
        for path in self._shell_scripts():
            proc = subprocess.run(
                ["bash", "-n", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15
            )
            self.assertEqual(proc.returncode, 0, f"{path}: {proc.stderr.decode()}")


class TestPythonCompile(unittest.TestCase):
    def _python_sources(self):
        found = []
        for path in _walk_repo_files():
            if path.endswith(".py"):
                found.append(path)
                continue
            if os.path.dirname(path) == BIN_DIR and os.path.basename(path) != "forensic":
                try:
                    with open(path, "rb") as handle:
                        head = handle.read(32)
                except OSError:
                    continue
                if head.startswith(b"#!") and b"python" in head.split(b"\n", 1)[0]:
                    found.append(path)
        return found

    def test_finds_lib_tests_and_bin_wrapper_sources(self):
        found = {os.path.relpath(p, ROOT) for p in self._python_sources()}
        self.assertIn("lib/pyforensic/cli.py", found)
        self.assertIn("tests/test_repo_quality.py", found)
        self.assertIn("bin/add-candidate", found)

    def test_every_python_source_compiles(self):
        import py_compile
        import tempfile

        # cfile redirects the compiled bytecode into a throwaway temp file
        # instead of the default source-adjacent __pycache__/*.pyc -- this
        # check must never leave new cache artifacts behind in bin/ or lib/.
        with tempfile.TemporaryDirectory(prefix="pyforensic-test-pycache-") as cache_dir:
            for path in self._python_sources():
                cfile = os.path.join(cache_dir, os.path.basename(path) + ".pyc")
                try:
                    py_compile.compile(path, cfile=cfile, doraise=True)
                except py_compile.PyCompileError as exc:
                    self.fail(f"{path} failed to compile: {exc}")


class TestBinShebangsAndPermissions(unittest.TestCase):
    def test_every_bin_entry_is_executable_with_a_shebang(self):
        entries = sorted(f for f in os.listdir(BIN_DIR) if os.path.isfile(os.path.join(BIN_DIR, f)))
        self.assertGreater(len(entries), 0)
        for name in entries:
            path = os.path.join(BIN_DIR, name)
            self.assertTrue(os.access(path, os.X_OK), f"{path} is not executable")
            with open(path, "rb") as handle:
                head = handle.read(2)
            self.assertEqual(head, b"#!", f"{path} has no shebang")


class TestNoCrlfTrailingWhitespaceOrJunkFiles(unittest.TestCase):
    _TEXT_EXTENSIONS = {".py", ".sh", ".toml", ".md", ".txt", ".jsonl", ".json", ".cfg", ""}
    _JUNK_SUFFIXES = (".bak", ".orig", "~")
    _JUNK_NAMES = {".DS_Store"}

    def _text_candidate_files(self):
        for path in _walk_repo_files():
            _, ext = os.path.splitext(path)
            if ext in self._TEXT_EXTENSIONS:
                yield path

    def test_no_crlf_line_endings(self):
        offenders = []
        for path in self._text_candidate_files():
            with open(path, "rb") as handle:
                data = handle.read()
            if b"\r\n" in data:
                offenders.append(os.path.relpath(path, ROOT))
        self.assertEqual(offenders, [])

    def test_no_trailing_whitespace(self):
        offenders = []
        for path in self._text_candidate_files():
            with open(path, "rb") as handle:
                data = handle.read()
            for lineno, line in enumerate(data.split(b"\n"), start=1):
                stripped = line.rstrip(b"\r")
                if stripped != stripped.rstrip(b" \t") and stripped.strip(b" \t"):
                    offenders.append(f"{os.path.relpath(path, ROOT)}:{lineno}")
        self.assertEqual(offenders, [])

    def test_no_backup_or_os_junk_files(self):
        offenders = []
        for path in _walk_repo_files():
            name = os.path.basename(path)
            if name in self._JUNK_NAMES or name.endswith(self._JUNK_SUFFIXES):
                offenders.append(os.path.relpath(path, ROOT))
        self.assertEqual(offenders, [])

    def test_no_unexpectedly_large_tracked_file(self):
        offenders = []
        for path in _walk_repo_files():
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size > 2 * 1024 * 1024:
                offenders.append((os.path.relpath(path, ROOT), size))
        self.assertEqual(offenders, [])


class TestSecretScan(unittest.TestCase):
    """Scan for leaked credentials, distinguishing them from documented placeholders."""

    _PRIVATE_KEY_HEADER = re.compile(rb"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
    _ASSIGNMENT = re.compile(
        rb"(?i)\b(password|passwd|token|api[_-]?key|secret)\b\s*[=:]\s*['\"]?([^\s'\"]{4,})"
    )
    # A bracketed placeholder like <FORENSIC_USER> or a config-key name like
    # "password" used as a bare label (no assigned value) must never trip
    # this scan -- only an assignment to something that looks like an actual
    # credential value should.
    _PLACEHOLDER_VALUE = re.compile(rb"^[<{].*[>}]$|^\$\{?[A-Z_]+\}?$|^(none|null|todo|xxx|changeme)$", re.IGNORECASE)

    def _scan_bytes(self, data: bytes):
        hits = []
        if self._PRIVATE_KEY_HEADER.search(data):
            hits.append("private-key-header")
        for match in self._ASSIGNMENT.finditer(data):
            value = match.group(2)
            if not self._PLACEHOLDER_VALUE.match(value):
                hits.append(f"credential-assignment:{match.group(1).decode()}={value.decode(errors='replace')}")
        return hits

    def test_scanner_detects_a_synthetic_private_key_and_credential(self):
        # Prove the scan logic itself works before trusting a clean result
        # against the real tree.
        fake_key = b"-----BEGIN RSA PRIVATE KEY-----\nMIIBOw==\n-----END RSA PRIVATE KEY-----\n"
        self.assertIn("private-key-header", self._scan_bytes(fake_key))
        fake_secret = b'password = "sup3r-secret-value"\n'
        hits = self._scan_bytes(fake_secret)
        self.assertTrue(any(h.startswith("credential-assignment:password") for h in hits), hits)

    def test_scanner_does_not_flag_documented_placeholders(self):
        placeholder_line = b'HostName <FORENSIC_SERVER_IP_OR_NAME>\nUser <FORENSIC_USER>\n'
        self.assertEqual(self._scan_bytes(placeholder_line), [])

    def test_repository_tree_is_currently_free_of_leaked_secrets(self):
        # This file itself intentionally contains synthetic secret literals
        # (see test_scanner_detects_a_synthetic_private_key_and_credential)
        # to prove the scanner works before trusting a clean result -- it is
        # the scanner's own fixture, not repository content to scan.
        self_path = os.path.abspath(__file__)
        offenders = {}
        for path in _walk_repo_files():
            if os.path.abspath(path) == self_path:
                continue
            _, ext = os.path.splitext(path)
            if ext not in {".py", ".sh", ".toml", ".md", ".txt", ".example", "", ".cfg", ".json", ".jsonl"}:
                continue
            try:
                with open(path, "rb") as handle:
                    data = handle.read()
            except OSError:
                continue
            hits = self._scan_bytes(data)
            if hits:
                offenders[os.path.relpath(path, ROOT)] = hits
        self.assertEqual(offenders, {})


class TestGitignoreBoundaries(unittest.TestCase):
    """Uses real ``git check-ignore`` semantics against the actual .gitignore."""

    def _is_ignored(self, relative_path: str) -> bool:
        proc = subprocess.run(
            ["git", "check-ignore", "-q", "--", relative_path],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
        )
        return proc.returncode == 0

    def test_case_payload_paths_are_ignored(self):
        for relative in (
            "cases/demo/evidence/disk.img",
            "cases/demo/workspace/extracted/file.bin",
            "cases/demo/workspace/dumps/mem.raw",
            "cases/demo/logs/output.log",
            "cases/demo/logs/output.raw",
            "cases/demo/logs/output.out",
            "cases/demo/logs/output.txt",
        ):
            self.assertTrue(self._is_ignored(relative), f"{relative} should be ignored")

    def test_case_record_paths_are_not_ignored(self):
        for relative in (
            "cases/demo/workspace/scripts/parse.py",
            "cases/demo/notes/case.md",
            "cases/demo/notes/evidence-manifest.jsonl",
            "cases/demo/notes/artifacts-manifest.jsonl",
            "cases/demo/logs/commands.jsonl",
            "cases/demo/logs/commands.md",
            "cases/demo/result/candidates.jsonl",
            "cases/demo/result/review.jsonl",
            "cases/demo/result/final.json",
            "cases/demo/result/reproduction.json",
        ):
            self.assertFalse(self._is_ignored(relative), f"{relative} should NOT be ignored")

    def test_real_ssh_config_ignored_but_example_is_not(self):
        self.assertTrue(self._is_ignored("config/ssh_config"))
        self.assertFalse(self._is_ignored("config/ssh_config.example"))

    def test_private_operator_material_is_ignored(self):
        for relative in (
            "AGENTS.md",
            "PROMPT.md",
            "PROMPORT.md",
            ".agent/config.json",
            ".agents/reviewer.toml",
            ".codex/config.toml",
            "요구사항.md",
            "개발요구사항.md",
            "개발작업일지.md",
            "서버작업",
            "server",
            "docs/environment.md",
            "docs/implementation.md",
            "docs/local-tools.md",
            "docs/TODO.md",
            "docs/validation.md",
        ):
            self.assertTrue(self._is_ignored(relative), f"{relative} should be ignored")


class TestDispatcherHelpMatchesCliInventory(unittest.TestCase):
    def _forensic_script_text(self) -> str:
        return _read_text(os.path.join(BIN_DIR, "forensic"))

    def _usage_heredoc_command_names(self) -> set[str]:
        text = self._forensic_script_text()
        heredoc = re.search(r"<<'EOF'\n(.*?)\nEOF", text, re.DOTALL)
        self.assertIsNotNone(heredoc, "bin/forensic usage() heredoc not found")
        names = set()
        for line in heredoc.group(1).splitlines():
            match = re.match(r"^  ([a-z][a-z0-9-]*)\s+\S", line)
            if match:
                names.add(match.group(1))
        return names

    def _case_statement_command_names(self) -> set[str]:
        text = self._forensic_script_text()
        block = re.search(r'case "\$command_name" in\n(.*?)\)\n\s*exec ', text, re.DOTALL)
        self.assertIsNotNone(block, "bin/forensic case statement not found")
        tokens = re.split(r"[|\\\s\n]+", block.group(1).strip())
        return {t for t in tokens if t}

    def _cli_command_names(self) -> set[str]:
        sys.path.insert(0, helpers.LIB_DIR)
        from pyforensic import cli
        return set(cli.COMMANDS.keys())

    def test_usage_heredoc_lists_a_nonempty_command_set(self):
        names = self._usage_heredoc_command_names()
        self.assertGreaterEqual(len(names), 25)

    def test_usage_heredoc_matches_case_statement_allowlist(self):
        self.assertEqual(self._usage_heredoc_command_names(), self._case_statement_command_names())

    def test_case_statement_allowlist_matches_cli_commands_dict(self):
        self.assertEqual(self._case_statement_command_names(), self._cli_command_names())

    def test_every_bin_wrapper_except_forensic_matches_a_cli_command(self):
        wrapper_names = {
            n for n in os.listdir(BIN_DIR)
            if n != "forensic" and os.path.isfile(os.path.join(BIN_DIR, n))
        }
        self.assertEqual(wrapper_names, self._cli_command_names())


class TestReadmeMatchesCli(unittest.TestCase):
    def _cli_command_names(self) -> set[str]:
        sys.path.insert(0, helpers.LIB_DIR)
        from pyforensic import cli
        return set(cli.COMMANDS.keys())

    def test_every_cli_command_is_mentioned_in_readme(self):
        readme = _read_text(os.path.join(ROOT, "README.md"))
        missing = [name for name in self._cli_command_names() if f"`bin/{name}`" not in readme and name not in readme]
        self.assertEqual(missing, [], f"README.md does not mention: {missing}")

    def test_readme_does_not_claim_mmap_based_flag_scan(self):
        # flagscan.py deliberately avoids mmap (see its module docstring) --
        # this is one of the explicitly forbidden "cheating" patterns for
        # this project, so the docs must not misdescribe it as such.
        readme = _read_text(os.path.join(ROOT, "README.md"))
        flag_scan_section = re.search(r"`bin/flag-scan`:.*", readme)
        self.assertIsNotNone(flag_scan_section)
        self.assertNotIn("mmap-based", flag_scan_section.group(0).lower())
        self.assertNotIn("mmap based", flag_scan_section.group(0).lower())

    def test_readme_and_workflow_warn_against_secrets_in_logged_argv(self):
        # commands.jsonl stores argv/cwd in plaintext (commandlog.py); an
        # analyst who passes a password/key as a CLI argument would leak it
        # into a tracked file, so both docs must warn against this.
        readme = _read_text(os.path.join(ROOT, "README.md")).lower()
        workflow = _read_text(os.path.join(ROOT, "docs", "case-workflow.md")).lower()
        for label, text in (("README.md", readme), ("docs/case-workflow.md", workflow)):
            self.assertIn("argv", text, f"{label} does not mention argv in its secret warning")
            self.assertIn("secret", text, f"{label} has no secret-handling warning at all")


if __name__ == "__main__":
    unittest.main()
