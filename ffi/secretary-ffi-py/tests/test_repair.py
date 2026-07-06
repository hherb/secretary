"""#374 pytest suite — repair_vault FFI projection (repair_with_password /
repair_with_recovery / repair_with_device_secret).

Crash residue is staged the same way as the bridge crate's own
``ffi/secretary-ffi-bridge/src/repair/tests.rs`` (which mirrors
``core/tests/crash_recovery.rs``), but driven entirely through the Python
surface: save a block (v1), snapshot ``manifest.cbor.enc``, save again (v2),
then restore the v1 manifest bytes to simulate a crash between the v2 block
hitting disk and its manifest write landing. Each test gets its own
writable copy of golden_vault_001 in pytest's ``tmp_path`` so the read-only
fixture is never touched (mirrors test_smoke.py / test_trash_restore.py).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import secretary_ffi_py
from secretary_ffi_py import (
    BlockInput,
    VaultNeedsRepair,
    VaultRepairRejected,
)

VAULT_001_PASSWORD = b"correct horse battery staple"
BLOCK_UUID = bytes([0xAB] * 16)
DEVICE_UUID = bytes([0x07] * 16)
NOW_MS_BASE = 1_715_000_000_000


def _golden_vault_path(n: int = 1) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core"
        / "tests"
        / "data"
        / f"golden_vault_{n:03d}"
    )


def _golden_vault_password(n: int = 1) -> bytes:
    inputs_path = (
        Path(__file__).resolve().parents[3]
        / "core"
        / "tests"
        / "data"
        / f"golden_vault_{n:03d}_inputs.json"
    )
    with inputs_path.open() as fh:
        data = json.load(fh)
    return data["password"].encode("utf-8")


def _fresh_writable_vault(tmp_path: Path, n: int = 1) -> Path:
    dst = tmp_path / f"vault{n:03d}"
    shutil.copytree(_golden_vault_path(n), dst)
    return dst


def _save_named_block(identity, manifest, block_uuid: bytes, name: str, now_ms: int) -> None:
    inp = BlockInput(block_uuid=block_uuid, block_name=name, records=[])
    secretary_ffi_py.save_block(identity, manifest, inp, DEVICE_UUID, now_ms)


def _manifest_path(vault: Path) -> Path:
    return vault / "manifest.cbor.enc"


def _a_peer_card(vault: Path, owner_uuid: bytes) -> bytes:
    """Return the canonical-CBOR bytes of a non-owner contact card shipped
    in the fixture's contacts/ dir (golden_vault_001 ships at least one)."""
    for f in sorted((vault / "contacts").glob("*.card")):
        uuid = bytes.fromhex(f.stem.replace("-", ""))
        if uuid != owner_uuid:
            return f.read_bytes()
    raise AssertionError("fixture has no non-owner contact card")


# ---------------------------------------------------------------------------
# Case 1: happy-adopt — repair_with_password adopts a crashed save.
# ---------------------------------------------------------------------------


def test_repair_with_password_adopts_crashed_save(tmp_path: Path) -> None:
    vault = _fresh_writable_vault(tmp_path)
    password = _golden_vault_password()

    out = secretary_ffi_py.open_vault_with_password(str(vault), password)
    with out as opened:
        with opened.identity as identity, opened.manifest as manifest:
            _save_named_block(identity, manifest, BLOCK_UUID, "v1", NOW_MS_BASE)
            manifest_v1 = _manifest_path(vault).read_bytes()
            _save_named_block(identity, manifest, BLOCK_UUID, "v2", NOW_MS_BASE + 1_000)

    # Crash simulation: the v2 block hit disk, the v2 manifest write was lost.
    _manifest_path(vault).write_bytes(manifest_v1)

    # The plain open must surface the actionable typed "needs repair" signal.
    with pytest.raises(VaultNeedsRepair):
        secretary_ffi_py.open_vault_with_password(str(vault), password)

    # repair_with_password adopts the on-disk v2 generation.
    repaired = secretary_ffi_py.repair_with_password(
        str(vault).encode(), password, DEVICE_UUID, NOW_MS_BASE + 2_000
    )
    with repaired as vault_out:
        with vault_out.identity as identity, vault_out.manifest as manifest:
            entry = manifest.find_block(BLOCK_UUID)
            assert entry is not None
            assert entry.block_name == "v2"

    # A subsequent plain open is green.
    reopened = secretary_ffi_py.open_vault_with_password(str(vault), password)
    with reopened as vault_out:
        with vault_out.identity as identity, vault_out.manifest as manifest:
            assert manifest.find_block(BLOCK_UUID) is not None


# ---------------------------------------------------------------------------
# Case 2: rejected — repair_with_password refuses a recipient-widening
# crash residue (fail-closed; documented limitation).
# ---------------------------------------------------------------------------


def _stage_recipient_widening_residue(tmp_path: Path) -> Path:
    """Stage a crash residue vault whose crashed manifest write would have
    committed a recipient-widening `share_block`: save a block, snapshot
    the pre-share manifest, share it to a peer, then roll the on-disk
    manifest back to the pre-share snapshot to simulate the widening's
    manifest commit never landing. Returns the vault path; the caller can
    re-read `_manifest_path(vault)` for the pre-share bytes since that is
    exactly what's on disk once this returns.

    Factored out of the original recipient-widening rejection test (below)
    for reuse by the informed-consent (`preview_repair`/`ApprovedWidening`)
    tests added in #374 Task 8.
    """
    vault = _fresh_writable_vault(tmp_path)
    password = _golden_vault_password()

    out = secretary_ffi_py.open_vault_with_password(str(vault), password)
    with out as opened:
        with opened.identity as identity, opened.manifest as manifest:
            owner_uuid = bytes(identity.user_uuid())
            peer_card_bytes = _a_peer_card(vault, owner_uuid)
            owner_card_bytes = manifest.owner_card_bytes()
            assert owner_card_bytes is not None

            _save_named_block(identity, manifest, BLOCK_UUID, "mine", NOW_MS_BASE)
            manifest_pre_share = _manifest_path(vault).read_bytes()

            # Widen the recipient set: share to the peer. The manifest write
            # committing this widening is what we'll roll back below.
            secretary_ffi_py.share_block(
                identity,
                manifest,
                BLOCK_UUID,
                [owner_card_bytes],
                peer_card_bytes,
                DEVICE_UUID,
                NOW_MS_BASE + 1_000,
            )

    # Crash simulation: the {owner, peer} block hit disk, but the manifest
    # write that would have committed the widened recipient set was lost.
    _manifest_path(vault).write_bytes(manifest_pre_share)
    return vault


def test_repair_rejects_recipient_widening(tmp_path: Path) -> None:
    vault = _stage_recipient_widening_residue(tmp_path)
    password = _golden_vault_password()
    manifest_pre_share = _manifest_path(vault).read_bytes()

    with pytest.raises(VaultRepairRejected):
        secretary_ffi_py.repair_with_password(
            str(vault).encode(), password, DEVICE_UUID, NOW_MS_BASE + 2_000
        )

    # All-or-nothing: the rejected repair must not have touched the manifest.
    assert _manifest_path(vault).read_bytes() == manifest_pre_share


# ---------------------------------------------------------------------------
# Case 3: informed consent — refusal without approvals mentions "consent";
# preview_repair surfaces the widening with a display_name; passing the
# preview-derived approval back adopts the widening and the vault reopens
# clean. (#374 Task 8)
# ---------------------------------------------------------------------------


def test_repair_without_approvals_mentions_consent(tmp_path: Path) -> None:
    vault = _stage_recipient_widening_residue(tmp_path)
    password = _golden_vault_password()

    with pytest.raises(VaultRepairRejected) as exc_info:
        # approvals defaults to None -> fails closed, same as omitting it
        # entirely; this also proves existing (pre-Task-8) call sites that
        # never pass `approvals` keep working unchanged.
        secretary_ffi_py.repair_with_password(
            str(vault).encode(), password, DEVICE_UUID, NOW_MS_BASE + 2_000
        )

    assert "consent" in str(exc_info.value)


def test_preview_repair_with_password_returns_widening_with_display_name(
    tmp_path: Path,
) -> None:
    vault = _stage_recipient_widening_residue(tmp_path)
    password = _golden_vault_password()

    preview = secretary_ffi_py.preview_repair_with_password(
        str(vault).encode(), password
    )

    assert len(preview.widenings) == 1
    widening = preview.widenings[0]
    assert widening.block_uuid_hex
    assert widening.file_fingerprint_hex
    assert len(widening.added) == 1
    added = widening.added[0]
    assert isinstance(added.display_name, str) and added.display_name
    assert added.uuid_hex


def test_repair_with_password_adopts_approved_widening(tmp_path: Path) -> None:
    vault = _stage_recipient_widening_residue(tmp_path)
    password = _golden_vault_password()

    preview = secretary_ffi_py.preview_repair_with_password(
        str(vault).encode(), password
    )
    widening = preview.widenings[0]
    added = widening.added[0]

    approval = secretary_ffi_py.ApprovedWidening(
        block_uuid=bytes.fromhex(widening.block_uuid_hex.replace("-", "")),
        file_fingerprint=bytes.fromhex(widening.file_fingerprint_hex),
        added_recipients=[bytes.fromhex(added.uuid_hex.replace("-", ""))],
    )

    repaired = secretary_ffi_py.repair_with_password(
        str(vault).encode(),
        password,
        DEVICE_UUID,
        NOW_MS_BASE + 2_000,
        approvals=[approval],
    )
    with repaired as vault_out:
        with vault_out.identity as identity, vault_out.manifest as manifest:
            entry = manifest.find_block(BLOCK_UUID)
            assert entry is not None

    # A subsequent plain open is green: the widening was durably adopted.
    reopened = secretary_ffi_py.open_vault_with_password(str(vault), password)
    with reopened as vault_out:
        with vault_out.identity as identity, vault_out.manifest as manifest:
            assert manifest.find_block(BLOCK_UUID) is not None


def test_approved_widening_wrong_length_block_uuid_raises_value_error() -> None:
    with pytest.raises(ValueError):
        secretary_ffi_py.ApprovedWidening(
            block_uuid=bytes(15),
            file_fingerprint=bytes(32),
            added_recipients=[],
        )


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_repair_with_password_wrong_length_device_uuid_raises_value_error(
    tmp_path: Path,
) -> None:
    vault = _fresh_writable_vault(tmp_path)
    password = _golden_vault_password()
    with pytest.raises(ValueError):
        secretary_ffi_py.repair_with_password(
            str(vault).encode(), password, b"\x07\x07", NOW_MS_BASE
        )


def test_repair_with_device_secret_wrong_length_secret_raises_value_error(
    tmp_path: Path,
) -> None:
    vault = _fresh_writable_vault(tmp_path)
    with pytest.raises(ValueError):
        secretary_ffi_py.repair_with_device_secret(
            str(vault).encode(), bytes(16), bytes(31), NOW_MS_BASE
        )
