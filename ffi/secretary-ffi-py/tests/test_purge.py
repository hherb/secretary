"""#399 Task 11a pytest suite — purge_block + empty_trash end-to-end.

Mirrors test_trash_restore.py's fixture shape exactly: each test gets its
own writable copy of golden_vault_001 in pytest's ``tmp_path`` so the
read-only on-disk fixture is never touched.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import secretary_ffi_py
from secretary_ffi_py import (
    BlockInput,
    VaultBlockNotInTrash,
    VaultBlockPurged,
)


# ---------------------------------------------------------------------------
# Fixture helpers (copy of test_trash_restore.py's pattern, kept local to
# this file so the purge surface stays self-contained).
# ---------------------------------------------------------------------------

VAULT_001_PASSWORD = b"correct horse battery staple"
DEVICE_UUID = bytes([0x07] * 16)
NOW_MS_BASE = 1_715_000_000_000

OWNER_ONLY_BLOCK_UUID = bytes([0xE1] * 16)
SHARED_BLOCK_UUID = bytes([0xE2] * 16)
ALREADY_PURGED_BLOCK_UUID = bytes([0xE3] * 16)


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


def _save_one_record_block(identity, manifest, block_uuid: bytes, record_uuid: bytes) -> None:
    """Save a one-record block under ``block_uuid`` so the lifecycle
    tests have something to trash / purge."""
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
    secretary_ffi_py.save_block(
        identity, manifest, inp, DEVICE_UUID, NOW_MS_BASE
    )


# ---------------------------------------------------------------------------
# purge_block — happy path: owner-only trashed block, report fields, then
# restore rejects with BlockPurged.
# ---------------------------------------------------------------------------


def test_purge_block_owner_only_then_restore_raises_block_purged(
    tmp_path: Path,
) -> None:
    out, dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(
                identity, manifest, OWNER_ONLY_BLOCK_UUID, bytes([0xC1] * 16)
            )
            secretary_ffi_py.trash_block(
                identity,
                manifest,
                OWNER_ONLY_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 1_000,
            )

            report = secretary_ffi_py.purge_block(
                identity,
                manifest,
                OWNER_ONLY_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 2_000,
            )

            assert bytes(report.block_uuid) == OWNER_ONLY_BLOCK_UUID
            assert report.was_shared is False
            assert report.recipient_count == 1
            assert report.files_removed >= 1

            # trash/ no longer holds a file for this UUID.
            uuid_hex = _uuid_hyphenated(OWNER_ONLY_BLOCK_UUID)
            trash_dir = dst / "trash"
            remaining = [
                p for p in trash_dir.iterdir() if p.name.startswith(uuid_hex)
            ]
            assert remaining == []

            with pytest.raises(VaultBlockPurged):
                secretary_ffi_py.restore_block(
                    identity,
                    manifest,
                    OWNER_ONLY_BLOCK_UUID,
                    DEVICE_UUID,
                    NOW_MS_BASE + 3_000,
                )


# ---------------------------------------------------------------------------
# purge_block — failure: unknown UUID → VaultBlockNotInTrash
# ---------------------------------------------------------------------------


def test_purge_block_unknown_uuid_raises_block_not_in_trash(
    tmp_path: Path,
) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(VaultBlockNotInTrash):
                secretary_ffi_py.purge_block(
                    identity,
                    manifest,
                    OWNER_ONLY_BLOCK_UUID,
                    DEVICE_UUID,
                    NOW_MS_BASE,
                )


# ---------------------------------------------------------------------------
# purge_block — input validation: wrong-length UUID → ValueError
# ---------------------------------------------------------------------------


def test_purge_block_wrong_length_uuid_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(ValueError):
                secretary_ffi_py.purge_block(
                    identity, manifest, b"\x01\x02\x03", DEVICE_UUID, NOW_MS_BASE
                )


# ---------------------------------------------------------------------------
# purge_block — idempotent re-purge: second call succeeds with an honest
# "unknown" classification.
# ---------------------------------------------------------------------------


def test_purge_block_is_idempotent_on_second_call(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _save_one_record_block(
                identity, manifest, OWNER_ONLY_BLOCK_UUID, bytes([0xC1] * 16)
            )
            secretary_ffi_py.trash_block(
                identity,
                manifest,
                OWNER_ONLY_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 1_000,
            )
            secretary_ffi_py.purge_block(
                identity,
                manifest,
                OWNER_ONLY_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 2_000,
            )

            second = secretary_ffi_py.purge_block(
                identity,
                manifest,
                OWNER_ONLY_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 3_000,
            )

            assert second.was_shared is None
            assert second.recipient_count is None
            assert second.files_removed == 0


# ---------------------------------------------------------------------------
# empty_trash — aggregates a mixed owner-only + shared trash, excludes an
# already-purged entry, then restore of a purged entry raises BlockPurged.
# ---------------------------------------------------------------------------


def test_empty_trash_aggregates_mixed_trash_and_excludes_already_purged(
    tmp_path: Path,
) -> None:
    out, dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            # Owner-only block: save + trash.
            _save_one_record_block(
                identity, manifest, OWNER_ONLY_BLOCK_UUID, bytes([0xC1] * 16)
            )
            secretary_ffi_py.trash_block(
                identity,
                manifest,
                OWNER_ONLY_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 1_000,
            )

            # Shared block: save, share to alice (golden_vault_001's
            # pre-existing fixture contact card — same uuid the
            # conformance_kat.json share_block_happy vector uses), then
            # trash.
            _save_one_record_block(
                identity, manifest, SHARED_BLOCK_UUID, bytes([0xC2] * 16)
            )
            owner_card_bytes = manifest.owner_card_bytes()
            assert owner_card_bytes is not None
            alice_card_bytes = _read_contact_card_bytes(
                dst, "7921b6ed8fa8cff2baf61a43f3a66a9f"
            )
            secretary_ffi_py.share_block(
                identity,
                manifest,
                SHARED_BLOCK_UUID,
                [owner_card_bytes],
                alice_card_bytes,
                DEVICE_UUID,
                NOW_MS_BASE + 1_500,
            )
            secretary_ffi_py.trash_block(
                identity,
                manifest,
                SHARED_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 2_000,
            )

            # Already-purged block: save, trash, purge — before
            # empty_trash runs. Must not be double-counted.
            _save_one_record_block(
                identity, manifest, ALREADY_PURGED_BLOCK_UUID, bytes([0xC3] * 16)
            )
            secretary_ffi_py.trash_block(
                identity,
                manifest,
                ALREADY_PURGED_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 2_500,
            )
            secretary_ffi_py.purge_block(
                identity,
                manifest,
                ALREADY_PURGED_BLOCK_UUID,
                DEVICE_UUID,
                NOW_MS_BASE + 3_000,
            )

            report = secretary_ffi_py.empty_trash(
                identity, manifest, DEVICE_UUID, NOW_MS_BASE + 4_000
            )

            assert report.purged_count == 2
            assert report.shared_count == 1
            assert report.owner_only_count == 1
            assert report.unknown_count == 0
            assert report.files_removed >= 2
            assert report.files_failed == 0

            # trash/ no longer holds files for either newly-purged UUID.
            trash_dir = dst / "trash"
            for uuid in (OWNER_ONLY_BLOCK_UUID, SHARED_BLOCK_UUID):
                uuid_hex = _uuid_hyphenated(uuid)
                remaining = [
                    p for p in trash_dir.iterdir() if p.name.startswith(uuid_hex)
                ]
                assert remaining == []

            # A follow-up restore of one of the just-purged blocks is
            # rejected as permanently purged.
            with pytest.raises(VaultBlockPurged):
                secretary_ffi_py.restore_block(
                    identity,
                    manifest,
                    OWNER_ONLY_BLOCK_UUID,
                    DEVICE_UUID,
                    NOW_MS_BASE + 5_000,
                )


# ---------------------------------------------------------------------------
# empty_trash — nothing to purge → all-zero report
# ---------------------------------------------------------------------------


def test_empty_trash_on_empty_trash_returns_zero_report(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            report = secretary_ffi_py.empty_trash(
                identity, manifest, DEVICE_UUID, NOW_MS_BASE
            )

            assert report.purged_count == 0
            assert report.shared_count == 0
            assert report.owner_only_count == 0
            assert report.unknown_count == 0
            assert report.files_removed == 0
            assert report.files_failed == 0


# ---------------------------------------------------------------------------
# empty_trash — input validation: wrong-length device_uuid → ValueError
# ---------------------------------------------------------------------------


def test_empty_trash_wrong_length_device_uuid_raises_value_error(
    tmp_path: Path,
) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            with pytest.raises(ValueError):
                secretary_ffi_py.empty_trash(
                    identity, manifest, b"\x07\x07", NOW_MS_BASE
                )


def _uuid_hyphenated(uuid: bytes) -> str:
    """Canonical lowercase 8-4-4-4-12 hex used by the vault folder
    layout (mirrors core::vault::orchestrators::format_uuid_hyphenated)."""
    h = uuid.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _read_contact_card_bytes(vault_dir: Path, user_uuid_hex: str) -> bytes:
    """Read the canonical-CBOR bytes of a contact card from a vault's
    contacts/ directory (mirrors
    conformance_kat_helpers::fixtures::read_contact_card_bytes)."""
    hyphenated = _uuid_hyphenated(bytes.fromhex(user_uuid_hex))
    return (vault_dir / "contacts" / f"{hyphenated}.card").read_bytes()
