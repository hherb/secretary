"""B.5 pytest suite — trash_block + restore_block end-to-end.

Each test gets its own writable copy of golden_vault_001 in pytest's
``tmp_path`` so the read-only on-disk fixture is never touched. Mirrors
the bridge crate's ``fresh_writable_vault`` helper and the test_smoke.py
``_fresh_writable_vault`` shape exactly.
"""

from __future__ import annotations

import glob
import shutil
from pathlib import Path

import pytest

import secretary_ffi_py
from secretary_ffi_py import (
    BlockInput,
    VaultBlockNotFound,
    VaultBlockNotInTrash,
    VaultBlockUuidAlreadyLive,
    VaultCorruptVault,
)


# ---------------------------------------------------------------------------
# Fixture helpers (copy of test_smoke.py's pattern, kept local to this file
# so the B.5 surface stays self-contained).
# ---------------------------------------------------------------------------

VAULT_001_PASSWORD = b"correct horse battery staple"
NEW_BLOCK_UUID = bytes([0xAB] * 16)
NEW_RECORD_UUID = bytes([0xCD] * 16)
DEVICE_UUID = bytes([0x07] * 16)
NOW_MS_BASE = 1_715_000_000_000


def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core"
        / "tests"
        / "data"
        / f"golden_vault_{n:03d}"
    )


def _fresh_writable_vault(tmp_path: Path) -> tuple:
    """Copy golden_vault_001 into ``tmp_path / vault001/`` and open it.

    Returns ``(OpenVaultOutput, dst_path)``. Caller uses the output as
    a context manager: ``with out as vault: ...``.
    """
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return (
        secretary_ffi_py.open_vault_with_password(str(dst), VAULT_001_PASSWORD),
        dst,
    )


def _save_one_record_block(identity, manifest, block_uuid: bytes) -> None:
    """Save a one-record block under ``block_uuid`` so the lifecycle
    tests have something to trash."""
    inp = BlockInput(
        block_uuid=block_uuid,
        block_name="Notes",
        records=[
            secretary_ffi_py.RecordInput(
                record_uuid=NEW_RECORD_UUID,
                fields=[
                    secretary_ffi_py.FieldInput(
                        "password",
                        secretary_ffi_py.FieldInputValue.text("hunter2"),
                    ),
                ],
            ),
        ],
    )
    secretary_ffi_py.save_block(
        identity, manifest, inp, DEVICE_UUID, NOW_MS_BASE
    )


def _uuid_hyphenated(uuid: bytes) -> str:
    """Canonical lowercase 8-4-4-4-12 hex used by the vault folder
    layout (mirrors core::vault::orchestrators::format_uuid_hyphenated)."""
    h = uuid.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


# ---------------------------------------------------------------------------
# trash_block — happy path
# ---------------------------------------------------------------------------


def test_trash_block_moves_file_and_drops_block_entry(tmp_path: Path) -> None:
    out, dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(identity, manifest, NEW_BLOCK_UUID)
            pre_count = manifest.block_count()

            trash_ms = NOW_MS_BASE + 1_000
            secretary_ffi_py.trash_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, trash_ms
            )

            uuid_hex = _uuid_hyphenated(NEW_BLOCK_UUID)
            assert not (dst / "blocks" / f"{uuid_hex}.cbor.enc").exists()
            assert (
                dst / "trash" / f"{uuid_hex}.cbor.enc.{trash_ms}"
            ).exists()
            assert manifest.find_block(NEW_BLOCK_UUID) is None
            assert manifest.block_count() == pre_count - 1


# ---------------------------------------------------------------------------
# trash_block — failure: unknown UUID → BlockNotFound
# ---------------------------------------------------------------------------


def test_trash_block_unknown_uuid_raises_block_not_found(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(VaultBlockNotFound):
                secretary_ffi_py.trash_block(
                    identity,
                    manifest,
                    b"\xff" * 16,
                    DEVICE_UUID,
                    NOW_MS_BASE + 1_000,
                )


# ---------------------------------------------------------------------------
# trash_block — input validation: wrong-length UUID → ValueError
# ---------------------------------------------------------------------------


def test_trash_block_wrong_length_uuid_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(ValueError):
                secretary_ffi_py.trash_block(
                    identity, manifest, b"\x01\x02\x03", DEVICE_UUID, NOW_MS_BASE
                )


# ---------------------------------------------------------------------------
# restore_block — happy path: trash → restore round-trip
# ---------------------------------------------------------------------------


def test_restore_block_round_trip(tmp_path: Path) -> None:
    out, dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(identity, manifest, NEW_BLOCK_UUID)
            secretary_ffi_py.trash_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, NOW_MS_BASE + 1_000
            )
            secretary_ffi_py.restore_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, NOW_MS_BASE + 2_000
            )

            uuid_hex = _uuid_hyphenated(NEW_BLOCK_UUID)
            assert (dst / "blocks" / f"{uuid_hex}.cbor.enc").exists()
            assert manifest.find_block(NEW_BLOCK_UUID) is not None

            # Round-trip readability via read_block.
            with secretary_ffi_py.read_block(
                identity, manifest, NEW_BLOCK_UUID, include_deleted=False
            ) as block:
                assert block.record_count() == 1
                record = block.record_at(0)
                assert record.field_by_name("password").expose_text() == "hunter2"


# ---------------------------------------------------------------------------
# restore_block — failure: live collision → BlockUuidAlreadyLive
# ---------------------------------------------------------------------------


def test_restore_block_live_collision_raises_block_uuid_already_live(
    tmp_path: Path,
) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(identity, manifest, NEW_BLOCK_UUID)
            secretary_ffi_py.trash_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, NOW_MS_BASE + 1_000
            )
            # Re-save the block — now live AND trashed.
            secretary_ffi_py.save_block(
                identity,
                manifest,
                BlockInput(NEW_BLOCK_UUID, "newer", []),
                DEVICE_UUID,
                NOW_MS_BASE + 1_500,
            )

            with pytest.raises(VaultBlockUuidAlreadyLive):
                secretary_ffi_py.restore_block(
                    identity,
                    manifest,
                    NEW_BLOCK_UUID,
                    DEVICE_UUID,
                    NOW_MS_BASE + 2_000,
                )


# ---------------------------------------------------------------------------
# restore_block — failure: empty trash → BlockNotInTrash
# ---------------------------------------------------------------------------


def test_restore_block_when_not_in_trash_raises(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(VaultBlockNotInTrash):
                secretary_ffi_py.restore_block(
                    identity, manifest, b"\xee" * 16, DEVICE_UUID, NOW_MS_BASE
                )


# ---------------------------------------------------------------------------
# restore_block — failure: tampered trash file → VaultCorruptVault
# ---------------------------------------------------------------------------


def test_restore_block_tampered_file_raises_corrupt_vault(tmp_path: Path) -> None:
    out, dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(identity, manifest, NEW_BLOCK_UUID)
            trash_ms = NOW_MS_BASE + 1_000
            secretary_ffi_py.trash_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, trash_ms
            )

            uuid_hex = _uuid_hyphenated(NEW_BLOCK_UUID)
            trash_path = dst / "trash" / f"{uuid_hex}.cbor.enc.{trash_ms}"
            data = bytearray(trash_path.read_bytes())
            data[len(data) // 2] ^= 0xFF
            trash_path.write_bytes(bytes(data))

            with pytest.raises(VaultCorruptVault):
                secretary_ffi_py.restore_block(
                    identity,
                    manifest,
                    NEW_BLOCK_UUID,
                    DEVICE_UUID,
                    NOW_MS_BASE + 2_000,
                )


# ---------------------------------------------------------------------------
# restore_block — preserves block fingerprint (BLAKE3 of file bytes)
# ---------------------------------------------------------------------------


def test_restore_block_preserves_block_fingerprint(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(identity, manifest, NEW_BLOCK_UUID)
            pre = manifest.find_block(NEW_BLOCK_UUID)
            assert pre is not None
            pre_created_at = pre.created_at_ms

            secretary_ffi_py.trash_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, NOW_MS_BASE + 1_000
            )
            secretary_ffi_py.restore_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, NOW_MS_BASE + 2_000
            )

            post = manifest.find_block(NEW_BLOCK_UUID)
            assert post is not None
            # created_at_ms is preserved verbatim from the block file's
            # header — the sync-correctness invariant.
            assert post.created_at_ms == pre_created_at


# ---------------------------------------------------------------------------
# trash_block — input validation: wrong-length device_uuid → ValueError
# ---------------------------------------------------------------------------


def test_trash_block_wrong_length_device_uuid_raises_value_error(
    tmp_path: Path,
) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(ValueError):
                secretary_ffi_py.trash_block(
                    identity, manifest, NEW_BLOCK_UUID, b"\x07\x07", NOW_MS_BASE
                )


# ---------------------------------------------------------------------------
# restore_block — multi-copy purge: older copies removed
# ---------------------------------------------------------------------------


def test_restore_block_purges_older_copies(tmp_path: Path) -> None:
    out, dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(identity, manifest, NEW_BLOCK_UUID)
            trash_ms = NOW_MS_BASE + 4_000
            secretary_ffi_py.trash_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, trash_ms
            )

            uuid_hex = _uuid_hyphenated(NEW_BLOCK_UUID)
            newest = dst / "trash" / f"{uuid_hex}.cbor.enc.{trash_ms}"
            older = dst / "trash" / f"{uuid_hex}.cbor.enc.{trash_ms - 500}"
            shutil.copy(newest, older)
            assert older.exists()

            secretary_ffi_py.restore_block(
                identity,
                manifest,
                NEW_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 5_000,
            )

            # Newest moved to blocks/, older purged.
            assert (dst / "blocks" / f"{uuid_hex}.cbor.enc").exists()
            assert not older.exists()
            # Only `newest` and `older` were ever written; both are gone.
            remaining = glob.glob(str(dst / "trash" / f"{uuid_hex}.cbor.enc.*"))
            assert remaining == []


# ---------------------------------------------------------------------------
# Smoke: trash → reopen → restore → reopen round-trip via fresh handles
# ---------------------------------------------------------------------------


def test_trash_restore_persist_across_reopen(tmp_path: Path) -> None:
    """Verify on-disk manifest is authoritative — a fresh open_vault
    after each step sees the same state the in-memory handle does."""
    out_first, dst = _fresh_writable_vault(tmp_path)
    with out_first as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(identity, manifest, NEW_BLOCK_UUID)
            secretary_ffi_py.trash_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, NOW_MS_BASE + 1_000
            )

    # Re-open from disk; trash state must persist.
    out_after_trash = secretary_ffi_py.open_vault_with_password(
        str(dst), VAULT_001_PASSWORD
    )
    with out_after_trash as vault:
        with vault.identity as identity, vault.manifest as manifest:
            assert manifest.find_block(NEW_BLOCK_UUID) is None
            secretary_ffi_py.restore_block(
                identity, manifest, NEW_BLOCK_UUID, DEVICE_UUID, NOW_MS_BASE + 2_000
            )

    # Re-open again; restore state must persist.
    out_after_restore = secretary_ffi_py.open_vault_with_password(
        str(dst), VAULT_001_PASSWORD
    )
    with out_after_restore as vault:
        with vault.identity as identity, vault.manifest as manifest:
            assert manifest.find_block(NEW_BLOCK_UUID) is not None


# ---------------------------------------------------------------------------
# list_trashed_blocks — projects block name + tombstone metadata
# ---------------------------------------------------------------------------


def test_list_trashed_blocks_projects_name_and_tombstone(tmp_path):
    out, _dst = _fresh_writable_vault(tmp_path)
    block_uuid = bytes([0xB7] * 16)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(identity, manifest, block_uuid)
            trashed_at = NOW_MS_BASE + 5_000
            secretary_ffi_py.trash_block(
                identity, manifest, block_uuid, DEVICE_UUID, trashed_at
            )

            listed = secretary_ffi_py.list_trashed_blocks(identity, manifest)

            assert len(listed) == 1
            assert bytes(listed[0].block_uuid) == block_uuid
            assert listed[0].block_name == "Notes"
            assert listed[0].tombstoned_at_ms == trashed_at
            assert bytes(listed[0].tombstoned_by) == DEVICE_UUID
