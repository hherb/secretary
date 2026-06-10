"""ADR 0009 (B.2) pytest suite — device-slot ops (add / open / remove).

Each test that mutates on-disk state gets its own writable copy of
golden_vault_001 in pytest's ``tmp_path`` so the read-only fixture is
never touched.  Mirrors the pattern in test_smoke.py and
test_trash_restore.py exactly.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import secretary_ffi_py


# ---------------------------------------------------------------------------
# Helpers — same pattern as test_smoke.py / test_trash_restore.py
# ---------------------------------------------------------------------------

def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core"
        / "tests"
        / "data"
        / f"golden_vault_{n:03d}"
    )


def _golden_vault_password(n: int) -> bytes:
    """Read the pinned ``password`` field from
    ``core/tests/data/golden_vault_{n:03d}_inputs.json`` and return it as
    UTF-8 bytes ready for ``add_device_slot``."""
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
    """Copy golden_vault_NNN into ``tmp_path / vaultNNN/`` and return the
    destination path.  The on-disk copy lives until ``tmp_path`` is reaped
    by pytest so mutations are visible to subsequent re-opens within the
    same test."""
    dst = tmp_path / f"vault{n:03d}"
    shutil.copytree(_golden_vault_path(n), dst)
    return dst


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_enroll_then_open_round_trip(tmp_path: Path) -> None:
    """add_device_slot → take_secret (one-shot) → open_with_device_secret
    round-trip.  Pins: device_uuid is 16 bytes; take_secret first call
    returns 32 bytes; second call returns None; opened vault has 16-byte
    user_uuid."""
    vault = _fresh_writable_vault(tmp_path)
    password = bytearray(_golden_vault_password(1))

    out = secretary_ffi_py.add_device_slot(str(vault).encode(), bytes(password))
    # Caller-zeroize discipline — mirror add_device_slot's password discipline.
    for i in range(len(password)):
        password[i] = 0

    # device_uuid must be 16 bytes.
    assert len(bytes(out.device_uuid)) == 16

    # Take the DeviceSecretOutput handle (destructive getter).
    secret_handle = out.device_secret
    assert secret_handle is not None

    # First take_secret → 32 bytes.
    secret_bytes = secret_handle.take_secret()
    assert secret_bytes is not None
    assert isinstance(secret_bytes, bytes)
    assert len(secret_bytes) == 32

    # Second take_secret → None (one-shot semantics).
    assert secret_handle.take_secret() is None

    # Open the vault with the device secret.
    opened = secretary_ffi_py.open_with_device_secret(
        str(vault).encode(),
        bytes(out.device_uuid),
        secret_bytes,
    )
    with opened as vault_out:
        with vault_out.identity as identity:
            assert len(identity.user_uuid()) == 16


def test_open_absent_slot_raises_device_slot_not_found(tmp_path: Path) -> None:
    """16-byte UUID with no matching .wrap file →
    VaultDeviceSlotNotFound."""
    vault = _fresh_writable_vault(tmp_path)
    with pytest.raises(secretary_ffi_py.VaultDeviceSlotNotFound):
        secretary_ffi_py.open_with_device_secret(
            str(vault).encode(),
            bytes(16),   # all-zero UUID — no such slot
            bytes(32),   # all-zero secret
        )


def test_open_wrong_length_secret_raises_value_error(tmp_path: Path) -> None:
    """31-byte device_secret (not 32) → ValueError (programmer error, not
    data error)."""
    vault = _fresh_writable_vault(tmp_path)
    with pytest.raises(ValueError):
        secretary_ffi_py.open_with_device_secret(
            str(vault).encode(),
            bytes(16),
            bytes(31),   # wrong length — must be 32
        )


def test_remove_twice_raises_device_slot_not_found(tmp_path: Path) -> None:
    """Enrol a slot, remove it once (OK), remove again → VaultDeviceSlotNotFound."""
    vault = _fresh_writable_vault(tmp_path)
    password = _golden_vault_password(1)

    out = secretary_ffi_py.add_device_slot(str(vault).encode(), password)
    device_uuid = bytes(out.device_uuid)
    # Wipe the secret handle — we don't need to open; we're testing revoke.
    out.device_secret.close()

    # First remove — must succeed.
    secretary_ffi_py.remove_device_slot(str(vault).encode(), device_uuid)

    # Second remove of the same UUID → VaultDeviceSlotNotFound.
    with pytest.raises(secretary_ffi_py.VaultDeviceSlotNotFound):
        secretary_ffi_py.remove_device_slot(str(vault).encode(), device_uuid)
