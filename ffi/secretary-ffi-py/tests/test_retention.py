"""#402 pytest suite — retention preview + commit end-to-end via pyo3.

Each test opens its own writable copy of golden_vault_001 in pytest's
``tmp_path`` so the read-only fixture is never touched
(feedback_smoke_test_temp_copy_golden_vault).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import secretary_ffi_py
from secretary_ffi_py import (
    DEFAULT_RETENTION_WINDOW_MS,
    auto_purge_expired,
    expired_trash_entries,
)

VAULT_001_PASSWORD = b"correct horse battery staple"
DEVICE_UUID = bytes([0x07] * 16)
NOW_MS = 1_715_000_000_000
HUGE_WINDOW = 10 ** 15  # far larger than any age → nothing eligible


def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}"
    )


def _fresh_writable_vault(tmp_path: Path):
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return secretary_ffi_py.open_vault_with_password(str(dst), VAULT_001_PASSWORD)


def test_default_window_is_ninety_days():
    assert DEFAULT_RETENTION_WINDOW_MS == 90 * 24 * 60 * 60 * 1000


def test_preview_empty_when_no_eligible_entries(tmp_path):
    with _fresh_writable_vault(tmp_path) as vault:
        entries = expired_trash_entries(vault.manifest, DEFAULT_RETENTION_WINDOW_MS, NOW_MS)
        assert entries == []


def test_commit_zero_count_echoes_window_and_no_write(tmp_path):
    with _fresh_writable_vault(tmp_path) as vault:
        report = auto_purge_expired(
            vault.identity, vault.manifest, HUGE_WINDOW, NOW_MS, DEVICE_UUID
        )
        assert report.purged_count == 0
        assert report.shared_count == 0
        assert report.owner_only_count == 0
        assert report.unknown_count == 0
        assert report.files_removed == 0
        assert report.files_failed == 0
        assert report.window_ms == HUGE_WINDOW


def test_commit_rejects_wrong_length_device_uuid(tmp_path):
    with _fresh_writable_vault(tmp_path) as vault:
        with pytest.raises(ValueError):
            auto_purge_expired(
                vault.identity, vault.manifest, HUGE_WINDOW, NOW_MS, bytes([0x07] * 15)
            )
