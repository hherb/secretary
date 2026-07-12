"""Round-trip + field-preservation for the settings FFI surface (pyo3).

Mirrors tests/test_retention.py's fixture shape: each test opens its own
writable copy of golden_vault_001 in pytest's ``tmp_path`` so the read-only
fixture is never touched (feedback_smoke_test_temp_copy_golden_vault).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
import secretary_ffi_py
from secretary_ffi_py import Settings, read_settings, write_settings

VAULT_001_PASSWORD = b"correct horse battery staple"
DEVICE_UUID = bytes([0x07] * 16)
NOW_MS = 1_715_000_000_000
MS_PER_DAY = 86_400_000


def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}"
    )


def _fresh_writable_vault(tmp_path: Path):
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return (
        secretary_ffi_py.open_vault_with_password(str(dst), VAULT_001_PASSWORD),
        dst,
    )


def test_read_absent_returns_defaults(tmp_path):
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        s = read_settings(vault.identity, vault.manifest)
        # golden_vault_001 has no settings block → bridge returns defaults.
        assert s.retention_window_ms == 90 * MS_PER_DAY


def test_partial_update_preserves_other_fields(tmp_path):
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            seeded = Settings(
                auto_lock_timeout_ms=900_000,
                require_password_before_edits=False,
                reauth_grace_window_ms=42_000,
                retention_window_ms=30 * MS_PER_DAY,
            )
            write_settings(identity, manifest, seeded, DEVICE_UUID, NOW_MS)

            got = read_settings(identity, manifest)
            got.retention_window_ms = 90 * MS_PER_DAY
            write_settings(identity, manifest, got, DEVICE_UUID, NOW_MS + 1)

            final = read_settings(identity, manifest)
            assert final.retention_window_ms == 90 * MS_PER_DAY
            assert final.auto_lock_timeout_ms == 900_000
            assert final.require_password_before_edits is False
            assert final.reauth_grace_window_ms == 42_000


def test_write_out_of_range_raises_value_error(tmp_path):
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            # retention_window_ms below the 1-day floor is rejected at the
            # binding wrapper (adversarial-IPC guard) before any vault write.
            bad = Settings(
                auto_lock_timeout_ms=600_000,
                require_password_before_edits=True,
                reauth_grace_window_ms=120_000,
                retention_window_ms=999,
            )
            with pytest.raises(ValueError):
                write_settings(identity, manifest, bad, DEVICE_UUID, NOW_MS)
