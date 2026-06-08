"""#187 pytest suite — sync_status / sync_vault / sync_commit_decisions.

Each test uses its own tempdir state_dir + a writable copy of
golden_vault_001 so the read-only on-disk fixtures are never touched.
The ConflictsPending round-trip (test_conflict_round_trip) is added in a
later step once the divergence fixture exists.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import secretary_ffi_py
from secretary_ffi_py import (
    VaultSyncFailed,
    sync_commit_decisions,
    sync_status,
    sync_vault,
)

VAULT_001_PASSWORD = b"correct horse battery staple"
NOW_MS = 1_715_000_000_000


def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core"
        / "tests"
        / "data"
        / f"golden_vault_{n:03d}"
    )


def _fresh_writable_vault(tmp_path: Path) -> Path:
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return dst


def test_sync_status_empty_state_dir_reports_no_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    status = sync_status(str(state_dir), bytes([9] * 16))
    assert status.has_state is False
    assert status.device_clocks == []
    assert status.last_state_write_ms is None


def test_sync_status_wrong_length_vault_uuid_raises_value_error(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    with pytest.raises(ValueError):
        sync_status(str(state_dir), bytes([0] * 15))


def test_sync_vault_fresh_state_applies_automatically(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    vault = _fresh_writable_vault(tmp_path)
    outcome = sync_vault(str(state_dir), str(vault), VAULT_001_PASSWORD, NOW_MS)
    assert outcome.kind == "AppliedAutomatically"
    # state was persisted -> a second pass over the now-current vault is NothingToDo
    again = sync_vault(str(state_dir), str(vault), VAULT_001_PASSWORD, NOW_MS)
    assert again.kind == "NothingToDo"


def test_sync_commit_decisions_bad_manifest_hash_raises_sync_failed(
    tmp_path: Path,
) -> None:
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    vault = _fresh_writable_vault(tmp_path)
    with pytest.raises(VaultSyncFailed):
        sync_commit_decisions(
            str(state_dir), str(vault), VAULT_001_PASSWORD, [], bytes(5), NOW_MS
        )
