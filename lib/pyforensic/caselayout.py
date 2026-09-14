"""Fixed relative layout of a case directory. Single source of truth for paths."""

from __future__ import annotations

import os

SCHEMA_VERSION = 1

EVIDENCE_DIR = "evidence"
WORKSPACE_DIR = "workspace"
WORKSPACE_EXTRACTED = "workspace/extracted"
WORKSPACE_SCRIPTS = "workspace/scripts"
WORKSPACE_DUMPS = "workspace/dumps"
LOGS_DIR = "logs"
NOTES_DIR = "notes"
RESULT_DIR = "result"

CASE_META = "notes/case-meta.json"
CASE_NOTES = "notes/case.md"
EVIDENCE_MANIFEST = "notes/evidence-manifest.jsonl"
ARTIFACT_MANIFEST = "notes/artifacts-manifest.jsonl"
COMMANDS_MD = "logs/commands.md"
COMMANDS_JSONL = "logs/commands.jsonl"
CANDIDATES_JSONL = "result/candidates.jsonl"
REVIEW_JSONL = "result/review.jsonl"
FINAL_JSON = "result/final.json"
REPRODUCTION_JSON = "result/reproduction.json"

ALL_SUBDIRS = (
    EVIDENCE_DIR,
    WORKSPACE_EXTRACTED,
    WORKSPACE_SCRIPTS,
    WORKSPACE_DUMPS,
    LOGS_DIR,
    NOTES_DIR,
    RESULT_DIR,
)


def path_in_case(case_dir: str, relative: str) -> str:
    return os.path.join(case_dir, *relative.split("/"))
