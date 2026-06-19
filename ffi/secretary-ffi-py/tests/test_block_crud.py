"""block-CRUD slice pytest — create_block / rename_block / move_record end-to-end.

Mirrors the uniffi projection (``namespace/block_crud.rs``) and the Swift/Kotlin
smoke runners: each op gets a round-trip plus the wrong-length-uuid and
same-block guards that live at the binding wrapper (the bridge trusts its
caller on uuid lengths and on the source≠target precondition).

Each test gets its own writable copy of golden_vault_001 in pytest's
``tmp_path`` so the read-only on-disk fixture is never touched.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import secretary_ffi_py
from secretary_ffi_py import (
    FieldInput,
    FieldInputValue,
    VaultBlockNotFound,
    VaultRecordNotFound,
)

VAULT_001_PASSWORD = b"correct horse battery staple"
SOURCE_BLOCK_UUID = bytes([0xB1] * 16)
TARGET_BLOCK_UUID = bytes([0xB2] * 16)
RECORD_UUID = bytes([0xC2] * 16)
NEW_RECORD_UUID = bytes([0xC9] * 16)
DEVICE_UUID = bytes([0x07] * 16)
NOW_MS_BASE = 1_715_000_000_000


def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}"
    )


def _fresh_writable_vault(tmp_path: Path):
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return secretary_ffi_py.open_vault_with_password(str(dst), VAULT_001_PASSWORD), dst


def _seed_source_block(identity, manifest) -> None:
    """Seed SOURCE_BLOCK_UUID with one live login record (RECORD_UUID)."""
    inp = secretary_ffi_py.BlockInput(
        block_uuid=SOURCE_BLOCK_UUID,
        block_name="Logins",
        records=[
            secretary_ffi_py.RecordInput(
                record_uuid=RECORD_UUID,
                fields=[
                    FieldInput("user", FieldInputValue.text("alice")),
                    FieldInput("pass", FieldInputValue.text("hunter2")),
                ],
                record_type="login",
                tags=["work"],
            ),
        ],
    )
    secretary_ffi_py.save_block(identity, manifest, inp, DEVICE_UUID, NOW_MS_BASE)


# ---------------------------------------------------------------------------
# create_block
# ---------------------------------------------------------------------------


def test_create_block_adds_empty_block(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            secretary_ffi_py.create_block(
                identity, manifest, TARGET_BLOCK_UUID, "Archive", DEVICE_UUID, NOW_MS_BASE
            )
            summary = manifest.find_block(TARGET_BLOCK_UUID)
            assert summary is not None
            assert summary.block_name == "Archive"
            with secretary_ffi_py.read_block(
                identity, manifest, TARGET_BLOCK_UUID, include_deleted=False
            ) as block:
                assert block.record_count() == 0


def test_create_block_wrong_length_block_uuid_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(ValueError):
                secretary_ffi_py.create_block(
                    identity, manifest, b"\x01" * 15, "Archive", DEVICE_UUID, NOW_MS_BASE
                )


def test_create_block_wrong_length_device_uuid_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(ValueError):
                secretary_ffi_py.create_block(
                    identity, manifest, TARGET_BLOCK_UUID, "Archive", b"\x07" * 17, NOW_MS_BASE
                )


# ---------------------------------------------------------------------------
# rename_block
# ---------------------------------------------------------------------------


def test_rename_block_changes_name_preserving_records(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_source_block(identity, manifest)
            secretary_ffi_py.rename_block(
                identity, manifest, SOURCE_BLOCK_UUID, "Renamed", DEVICE_UUID, NOW_MS_BASE + 1_000
            )
            summary = manifest.find_block(SOURCE_BLOCK_UUID)
            assert summary is not None
            assert summary.block_name == "Renamed"
            with secretary_ffi_py.read_block(
                identity, manifest, SOURCE_BLOCK_UUID, include_deleted=False
            ) as block:
                assert block.record_count() == 1
                assert block.record_at(0).field_by_name("pass").expose_text() == "hunter2"


def test_rename_absent_block_raises_block_not_found(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(VaultBlockNotFound):
                secretary_ffi_py.rename_block(
                    identity, manifest, b"\xff" * 16, "Renamed", DEVICE_UUID, NOW_MS_BASE + 1_000
                )


def test_rename_block_wrong_length_block_uuid_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_source_block(identity, manifest)
            with pytest.raises(ValueError):
                secretary_ffi_py.rename_block(
                    identity, manifest, b"\x01" * 15, "Renamed", DEVICE_UUID, NOW_MS_BASE + 1_000
                )


def test_rename_block_wrong_length_device_uuid_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_source_block(identity, manifest)
            with pytest.raises(ValueError):
                secretary_ffi_py.rename_block(
                    identity, manifest, SOURCE_BLOCK_UUID, "Renamed", b"\x07\x07", NOW_MS_BASE + 1_000
                )


# ---------------------------------------------------------------------------
# move_record
# ---------------------------------------------------------------------------


def test_move_record_between_blocks_round_trip(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_source_block(identity, manifest)
            secretary_ffi_py.create_block(
                identity, manifest, TARGET_BLOCK_UUID, "Archive", DEVICE_UUID, NOW_MS_BASE + 1_000
            )
            secretary_ffi_py.move_record(
                identity, manifest,
                SOURCE_BLOCK_UUID, TARGET_BLOCK_UUID, RECORD_UUID, NEW_RECORD_UUID,
                DEVICE_UUID, NOW_MS_BASE + 2_000,
            )
            # The target now holds the moved record under its fresh UUID, with
            # the field values preserved.
            with secretary_ffi_py.read_block(
                identity, manifest, TARGET_BLOCK_UUID, include_deleted=False
            ) as block:
                assert block.record_count() == 1
                moved = block.record_at(0)
                assert bytes(moved.record_uuid()) == NEW_RECORD_UUID
                assert moved.field_by_name("pass").expose_text() == "hunter2"
            # The source record is now tombstoned (copy-before-delete).
            with secretary_ffi_py.read_block(
                identity, manifest, SOURCE_BLOCK_UUID, include_deleted=True
            ) as block:
                assert block.record_at(0).tombstone() is True


def test_move_record_same_block_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_source_block(identity, manifest)
            with pytest.raises(ValueError):
                secretary_ffi_py.move_record(
                    identity, manifest,
                    SOURCE_BLOCK_UUID, SOURCE_BLOCK_UUID, RECORD_UUID, NEW_RECORD_UUID,
                    DEVICE_UUID, NOW_MS_BASE + 2_000,
                )


def test_move_record_wrong_length_uuid_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_source_block(identity, manifest)
            with pytest.raises(ValueError):
                secretary_ffi_py.move_record(
                    identity, manifest,
                    b"\x01" * 15, TARGET_BLOCK_UUID, RECORD_UUID, NEW_RECORD_UUID,
                    DEVICE_UUID, NOW_MS_BASE + 2_000,
                )


def test_move_absent_source_record_raises_record_not_found(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_source_block(identity, manifest)
            secretary_ffi_py.create_block(
                identity, manifest, TARGET_BLOCK_UUID, "Archive", DEVICE_UUID, NOW_MS_BASE + 1_000
            )
            with pytest.raises(VaultRecordNotFound):
                secretary_ffi_py.move_record(
                    identity, manifest,
                    SOURCE_BLOCK_UUID, TARGET_BLOCK_UUID, b"\xaa" * 16, NEW_RECORD_UUID,
                    DEVICE_UUID, NOW_MS_BASE + 2_000,
                )
