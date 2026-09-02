"""Where the committed test data lives, and how it is loaded.

Every path resolves from `test_data_dir()`, which is derived from THIS FILE's
location and never from the process CWD -- `core/tests/differential_replay.rs`
and the `clean-room conformance` CI job invoke the entrypoint from different
working directories.

One anchor, not nine. Before #593 each helper re-derived the layout inline, in
two different spellings (`.parent.parent` and `.parents[1]`), so the split's
one-level-deeper `__file__` broke them individually rather than in one place.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def test_data_dir() -> Path:
    """`core/tests/data/` -- the single anchor every fixture path hangs off.

    This file is `core/tests/python/conformance_lib/fixtures.py`; `parents[2]`
    is `core/tests`. Moving this module changes that index, and nothing else --
    which is the point of having exactly one of them.
    """
    return Path(__file__).resolve().parents[2] / "data"


def block_kat_path() -> Path:
    return test_data_dir() / "block_kat.json"


def golden_vault_path() -> Path:
    return test_data_dir() / "golden_vault_001"


def golden_vault_inputs_path() -> Path:
    return test_data_dir() / "golden_vault_001_inputs.json"


def revoke_kat_dir() -> Path:
    return test_data_dir() / "revoke_kat"


def sync_pass_kat_dir() -> Path:
    return test_data_dir() / "sync_pass_kat"


def conflict_kat_path() -> Path:
    return test_data_dir() / "conflict_kat.json"


def trash_merge_kat_path() -> Path:
    return test_data_dir() / "trash_merge_kat.json"


def retention_kat_path() -> Path:
    return test_data_dir() / "retention_kat.json"


def convergence_kat_path() -> Path:
    return test_data_dir() / "convergence_kat.json"


def manifest_canonicality_kat_path() -> Path:
    return test_data_dir() / "manifest_canonicality_kat.json"


def manifest_uniqueness_kat_path() -> Path:
    return test_data_dir() / "manifest_uniqueness_kat.json"


def manifest_body_seed(name: str) -> Path:
    """One committed `cargo-fuzz` seed from `core/fuzz/seeds/manifest_body/`.

    The guard sections build their mutations from a committed CANONICAL seed
    rather than from the encoder under test: a guard that generated its own
    input with the encoder could not express a body that encoder refuses to
    emit, which is most of what these sections exist to reject.
    """
    return test_data_dir().parent.parent / "fuzz" / "seeds" / "manifest_body" / name


def load_json_fixture(path: Path, label: str) -> dict:
    """Load a JSON fixture, or exit 2 with a `MISSING:` line.

    Exit 2 is the entrypoint's documented "a fixture file was missing or
    malformed" code -- deliberately distinct from 1 ("a check failed"), so a
    broken checkout is never reported as a conformance failure.
    """
    if not path.is_file():
        print(f"MISSING: {label}: {path}", file=sys.stderr)
        sys.exit(2)
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"MISSING: {label} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)


def _require_file(path: Path, label: str) -> bytes:
    if not path.is_file():
        print(f"MISSING: {label}: {path}", file=sys.stderr)
        sys.exit(2)
    return path.read_bytes()
