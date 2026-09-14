"""Strict JSON parsing shared by the candidate/review/reproduction/final gate records.

Plain ``json.loads`` silently keeps the *last* value when a JSON object
has a repeated key -- an attacker (or a careless copy-paste edit) could
add a second ``"verdict": "verified"`` key after a genuine
``"verdict": "rejected"`` and every consumer that just calls
``json.loads`` would silently see the tampered value. This module uses an
``object_pairs_hook`` to detect and reject duplicate keys outright.

It also rejects any string value that is exactly ``TODO`` or contains the
standalone word ``TODO`` -- the placeholder text every template in this
project ships with -- so a record can never be judged "complete" while a
required field was simply left unfilled.
"""

from __future__ import annotations

import json
import re

_TODO_RE = re.compile(r"\bTODO\b")


class StrictJSONError(Exception):
    pass


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise StrictJSONError(f"duplicate JSON key {key!r}")
        seen[key] = value
    return seen


def _reject_todo(value: object, path: str) -> None:
    if isinstance(value, str):
        if _TODO_RE.search(value):
            raise StrictJSONError(f"{path}: placeholder TODO text was never filled in")
    elif isinstance(value, dict):
        for key, sub in value.items():
            _reject_todo(sub, f"{path}.{key}")
    elif isinstance(value, list):
        for idx, sub in enumerate(value):
            _reject_todo(sub, f"{path}[{idx}]")


def loads_strict(text: str, *, root_name: str = "$") -> object:
    try:
        obj = json.loads(text, object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as exc:
        raise StrictJSONError(f"invalid JSON: {exc}") from exc
    _reject_todo(obj, root_name)
    return obj
