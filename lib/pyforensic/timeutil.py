"""UTC timestamp and monotonic-duration helpers used across the case engine."""

from __future__ import annotations

import time
from datetime import datetime, timezone


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def monotonic() -> float:
    return time.monotonic()
