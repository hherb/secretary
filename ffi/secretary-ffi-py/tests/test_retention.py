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
    BlockInput,
    auto_purge_expired,
    expired_trash_entries,
)

VAULT_001_PASSWORD = b"correct horse battery staple"
DEVICE_UUID = bytes([0x07] * 16)
NOW_MS = 1_715_000_000_000
NOW_MS_BASE = 1_715_000_000_000
HUGE_WINDOW = 10 ** 15  # far larger than any age → nothing eligible

OLD_BLOCK_UUID = bytes([0xF1] * 16)


def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}"
    )


def _fresh_writable_vault(tmp_path: Path) -> tuple:
    """Copy golden_vault_001 into ``tmp_path / vault001/`` and open it.

    Returns ``(OpenVaultOutput, dst_path)``; the caller uses the output as
    a context manager (``with out as vault: ...``) and ``dst`` to inspect
    on-disk state (mirrors test_purge.py's fixture shape).
    """
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return (
        secretary_ffi_py.open_vault_with_password(str(dst), VAULT_001_PASSWORD),
        dst,
    )


def _save_one_record_block(identity, manifest, block_uuid: bytes, record_uuid: bytes) -> None:
    """Save a one-record block under ``block_uuid`` so the retention tests
    have something real to trash / purge."""
    inp = BlockInput(
        block_uuid=block_uuid,
        block_name="Notes",
        records=[
            secretary_ffi_py.RecordInput(
                record_uuid=record_uuid,
                fields=[
                    secretary_ffi_py.FieldInput(
                        "password",
                        secretary_ffi_py.FieldInputValue.text("hunter2"),
                    ),
                ],
            ),
        ],
    )
    secretary_ffi_py.save_block(identity, manifest, inp, DEVICE_UUID, NOW_MS_BASE)


def test_default_window_is_ninety_days():
    assert DEFAULT_RETENTION_WINDOW_MS == 90 * 24 * 60 * 60 * 1000


def test_preview_empty_when_no_eligible_entries(tmp_path):
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        entries = expired_trash_entries(vault.manifest, DEFAULT_RETENTION_WINDOW_MS, NOW_MS)
        assert entries == []


def test_commit_zero_count_echoes_window_and_no_write(tmp_path):
    out, dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        manifest_path = dst / "manifest.cbor.enc"
        before = manifest_path.read_bytes()

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

        # An empty target set must not re-sign / re-write the manifest — the
        # on-disk bytes are byte-identical to the pre-call state (the "no
        # write" half of this test's name, verified rather than assumed).
        assert manifest_path.read_bytes() == before


def test_commit_purges_expired_block(tmp_path):
    """Non-empty commit at the pyo3 projection layer: a trashed block older
    than the window is purged and reported (purged_count == 1), and a second
    preview is empty because the entry is now marked purged — proving the
    Ok-arm write-back and the age filter carry through the binding, not just
    the empty-target path."""
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        # identity / manifest are one-shot handles — capture once, reuse.
        with vault.identity as identity, vault.manifest as manifest:
            window_ms = 10_000
            trashed_at = NOW_MS_BASE + 1_000
            now_ms = NOW_MS_BASE + 1_000_000  # age 999_000 ≫ window_ms

            _save_one_record_block(
                identity, manifest, OLD_BLOCK_UUID, bytes([0xC1] * 16)
            )
            secretary_ffi_py.trash_block(
                identity, manifest, OLD_BLOCK_UUID, DEVICE_UUID, trashed_at
            )

            # Preview: exactly the old block, with the exact age arithmetic.
            preview = expired_trash_entries(manifest, window_ms, now_ms)
            assert len(preview) == 1
            assert bytes(preview[0].block_uuid) == OLD_BLOCK_UUID
            assert preview[0].tombstoned_at_ms == trashed_at
            assert preview[0].age_ms == 999_000

            report = auto_purge_expired(
                identity, manifest, window_ms, now_ms, DEVICE_UUID
            )
            assert report.purged_count == 1
            assert report.owner_only_count == 1
            assert report.shared_count == 0
            assert report.unknown_count == 0
            assert report.files_removed >= 1
            assert report.files_failed == 0
            assert report.window_ms == window_ms

            # The entry is now purged, so it is excluded from a re-preview.
            assert expired_trash_entries(manifest, window_ms, now_ms) == []


def test_commit_rejects_wrong_length_device_uuid(tmp_path):
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with pytest.raises(ValueError):
            auto_purge_expired(
                vault.identity, vault.manifest, HUGE_WINDOW, NOW_MS, bytes([0x07] * 15)
            )
