"""record-edit slice pytest — append/edit/tombstone/resurrect end-to-end.

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
    RecordContent,
    VaultRecordNotFound,
)

VAULT_001_PASSWORD = b"correct horse battery staple"
BLOCK_UUID = bytes([0xB1] * 16)
RECORD_UUID = bytes([0xC2] * 16)
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


def _seed_block(identity, manifest) -> None:
    inp = secretary_ffi_py.BlockInput(
        block_uuid=BLOCK_UUID,
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


def test_append_record_adds_live_record(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            second = bytes([0xD3] * 16)
            secretary_ffi_py.append_record(
                identity, manifest, BLOCK_UUID, second,
                RecordContent([FieldInput("body", FieldInputValue.text("remember"))], "note", []),
                DEVICE_UUID, NOW_MS_BASE + 1_000,
            )
            with secretary_ffi_py.read_block(identity, manifest, BLOCK_UUID, include_deleted=False) as block:
                assert block.record_count() == 2


def test_edit_record_changes_value_and_preserves_untouched_field_clock(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            edit_device = bytes([0x09] * 16)
            secretary_ffi_py.edit_record(
                identity, manifest, BLOCK_UUID, RECORD_UUID,
                RecordContent(
                    [
                        FieldInput("user", FieldInputValue.text("alice")),    # unchanged
                        FieldInput("pass", FieldInputValue.text("s3cret!")),  # changed
                    ],
                    "login", ["work"],
                ),
                edit_device, NOW_MS_BASE + 2_000,
            )
            with secretary_ffi_py.read_block(identity, manifest, BLOCK_UUID, include_deleted=False) as block:
                record = block.record_at(0)
                assert record.field_by_name("pass").expose_text() == "s3cret!"
                assert bytes(record.field_by_name("user").device_uuid()) == DEVICE_UUID
                assert bytes(record.field_by_name("pass").device_uuid()) == edit_device


def test_tombstone_then_resurrect_round_trip(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            secretary_ffi_py.tombstone_record(
                identity, manifest, BLOCK_UUID, RECORD_UUID, DEVICE_UUID, NOW_MS_BASE + 1_000
            )
            with secretary_ffi_py.read_block(identity, manifest, BLOCK_UUID, include_deleted=True) as block:
                assert block.record_count() == 1
                assert block.record_at(0).tombstone() is True
            secretary_ffi_py.resurrect_record(
                identity, manifest, BLOCK_UUID, RECORD_UUID, DEVICE_UUID, NOW_MS_BASE + 2_000
            )
            with secretary_ffi_py.read_block(identity, manifest, BLOCK_UUID, include_deleted=False) as block:
                assert block.record_at(0).tombstone() is False


def test_edit_unknown_record_raises_record_not_found(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            with pytest.raises(VaultRecordNotFound):
                secretary_ffi_py.edit_record(
                    identity, manifest, BLOCK_UUID, b"\xff" * 16,
                    RecordContent([], "x", []), DEVICE_UUID, NOW_MS_BASE + 1_000,
                )


def test_tombstone_wrong_length_device_uuid_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            with pytest.raises(ValueError):
                secretary_ffi_py.tombstone_record(
                    identity, manifest, BLOCK_UUID, RECORD_UUID, b"\x07\x07", NOW_MS_BASE + 1_000
                )
