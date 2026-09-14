#!/usr/bin/env bash
# Repository verification entry point.
#
# The authoritative adversarial regression suite lives under tests/ (one
# unittest module per requirements section 15.1-15.8) and already covers
# every case/evidence/artifact/command-log/flag-scanner/triage/remote/
# reviewer-gate/repository-quality behavior this project has. This script
# is intentionally a thin wrapper around that suite rather than a second,
# hand-rolled shell smoke test that would drift out of sync with it.
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$project_root"
exec python3 -m unittest discover -s tests -v
