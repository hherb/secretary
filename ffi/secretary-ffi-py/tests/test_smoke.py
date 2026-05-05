"""B.1 round-trip smoke tests for the secretary_ffi_py PyO3 extension.

These tests assert the same surface as the Rust #[cfg(test)] unit tests in
src/lib.rs, exercised through the maturin-built wheel and Python's import
machinery. They prove the binding pipeline (PyO3 + maturin + uv venv +
import) works end-to-end.
"""

import json
from pathlib import Path

import pytest

import secretary_ffi_py


def test_add_returns_arithmetic_sum() -> None:
    assert secretary_ffi_py.add(2, 3) == 5


def test_add_wraps_on_overflow() -> None:
    # Mirror the Rust unit test in src/lib.rs that pins the wrapping
    # contract through the FFI boundary. u32::MAX = 4_294_967_295.
    assert secretary_ffi_py.add(4_294_967_295, 1) == 0


def test_version_matches_format_version() -> None:
    # FORMAT_VERSION is pinned at 1 in core/src/version.rs; if the Rust
    # core bumps the format version this test will fail and demand an
    # explicit update — that's intentional, the wire-format constant is
    # security-critical and shouldn't drift silently.
    assert secretary_ffi_py.version() == 1


# ---------------------------------------------------------------------------
# B.2: open_with_password tests against golden_vault_001 + golden_vault_002.
# ---------------------------------------------------------------------------


def _golden_vault_dir(n: int) -> Path:
    """Resolve `core/tests/data/golden_vault_{n:03d}/` relative to this test
    file. Walks up 3 parents from `ffi/secretary-ffi-py/tests/` to repo root.
    """
    return Path(__file__).resolve().parents[3] / "core" / "tests" / "data" / f"golden_vault_{n:03d}"


def _read_fixture(n: int, name: str) -> bytes:
    return (_golden_vault_dir(n) / name).read_bytes()


def _golden_vault_phrase(n: int) -> bytes:
    """Read the pinned `recovery_mnemonic_phrase` field from
    `core/tests/data/golden_vault_{n:03d}_inputs.json` and return it as
    UTF-8 bytes ready for `open_with_recovery`. The fixture builder
    asserts the JSON pin matches `bip39::Mnemonic::from_entropy(...)
    .to_string()`, so this stays honest as long as the JSON does."""
    inputs_path = (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}_inputs.json"
    )
    with inputs_path.open() as fh:
        data = json.load(fh)
    return data["recovery_mnemonic_phrase"].encode("utf-8")


# Pinned KAT values — must match secretary-ffi-bridge's tests and the
# golden_vault_001_inputs.json source of truth. KAT drift cannot land
# silently: bridge tests + this file + Swift/Kotlin smoke runners all
# pin the same values.
VAULT_001_PASSWORD = b"correct horse battery staple"
VAULT_001_OWNER_DISPLAY_NAME = "Owner"
VAULT_001_OWNER_USER_UUID = bytes.fromhex("bf08a3300cd994b877e1a15baa28df35")

# Number of trailing bytes stripped to corrupt the TOML structurally.
# Empirically large enough to break the document past any tolerant
# parser; mirrors the bridge crate's unlock.rs negative-test value.
#
# Why robust under v1: vault.toml is plain TOML and contains no AEAD-
# framed payloads (those live in identity.bundle.enc), so any
# truncation must fail at TOML parse / required-field-present checks
# long before the AEAD step that produces WrongPasswordOrCorrupt.
# The same constant + reasoning is pinned in the bridge crate's
# unlock.rs and the Swift / Kotlin smoke runners.
_TRUNCATION_SUFFIX_BYTES = 50


def test_open_with_password_success_returns_pinned_identity() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with secretary_ffi_py.open_with_password(toml, bundle, VAULT_001_PASSWORD) as identity:
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
        assert identity.user_uuid() == VAULT_001_OWNER_USER_UUID


def test_open_with_password_wrong_password_raises_wrong_password_or_corrupt() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.WrongPasswordOrCorrupt):
        secretary_ffi_py.open_with_password(toml, bundle, b"definitely wrong")


def test_open_with_password_swapped_files_raises_vault_mismatch() -> None:
    # vault_001's vault.toml + vault_002's identity.bundle.enc → cross-check
    # at core/src/unlock/mod.rs's vault_uuid + created_at_ms comparison fails.
    toml_001 = _read_fixture(1, "vault.toml")
    bundle_002 = _read_fixture(2, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.VaultMismatch):
        secretary_ffi_py.open_with_password(toml_001, bundle_002, VAULT_001_PASSWORD)


def test_open_with_password_truncated_toml_raises_corrupt_vault() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    truncated = toml[:-_TRUNCATION_SUFFIX_BYTES]
    with pytest.raises(secretary_ffi_py.CorruptVault):
        secretary_ffi_py.open_with_password(truncated, bundle, VAULT_001_PASSWORD)


def test_close_is_idempotent() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    identity = secretary_ffi_py.open_with_password(toml, bundle, VAULT_001_PASSWORD)
    identity.close()
    identity.close()  # second call must not raise
    identity.close()  # third call must not raise


def test_use_after_close_returns_empty_values() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    identity = secretary_ffi_py.open_with_password(toml, bundle, VAULT_001_PASSWORD)
    identity.close()
    assert identity.display_name() == ""
    assert identity.user_uuid() == b"\x00" * 16


def test_open_with_password_accepts_bytearray_for_caller_zeroize_discipline() -> None:
    """Documents the design: passwords accepted as bytes-like; disciplined
    callers can zero a mutable bytearray after the call."""
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    pw = bytearray(VAULT_001_PASSWORD)
    with secretary_ffi_py.open_with_password(toml, bundle, pw) as identity:
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
    # Caller's zeroize discipline (recommended for first-party clients):
    for i in range(len(pw)):
        pw[i] = 0
    assert all(b == 0 for b in pw)


# ---------------------------------------------------------------------------
# B.3a: open_with_recovery tests against golden_vault_001 + golden_vault_002.
# ---------------------------------------------------------------------------


def test_open_with_recovery_success_returns_pinned_identity() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    phrase = _golden_vault_phrase(1)
    with secretary_ffi_py.open_with_recovery(toml, bundle, phrase) as identity:
        # Same KAT as the open_with_password success path — both unlock
        # paths converge on byte-identical secret state per §3/§4 dual-
        # KEK design.
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
        assert identity.user_uuid() == VAULT_001_OWNER_USER_UUID


def test_open_with_recovery_wrong_mnemonic_raises_wrong_mnemonic_or_corrupt() -> None:
    # vault_002's phrase against vault_001's vault — valid 24-word phrase
    # but wrong vault, so AEAD-decrypt under recovery_kek tag-fails →
    # WrongMnemonicOrCorrupt (anti-oracle preserving).
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    wrong_phrase = _golden_vault_phrase(2)
    with pytest.raises(secretary_ffi_py.WrongMnemonicOrCorrupt):
        secretary_ffi_py.open_with_recovery(toml, bundle, wrong_phrase)


def test_open_with_recovery_wrong_length_raises_invalid_mnemonic() -> None:
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.InvalidMnemonic) as exc_info:
        secretary_ffi_py.open_with_recovery(toml, bundle, b"only three words")
    assert "got 3" in str(exc_info.value)


def test_open_with_recovery_invalid_utf8_raises_invalid_mnemonic() -> None:
    # 0xFF is not valid UTF-8 in any byte position; the bridge's UTF-8
    # validation seam catches this before the BIP-39 wordlist lookup.
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    with pytest.raises(secretary_ffi_py.InvalidMnemonic) as exc_info:
        secretary_ffi_py.open_with_recovery(toml, bundle, bytes([0xFF] * 32))
    assert "UTF-8" in str(exc_info.value)


def test_open_with_recovery_swapped_files_raises_vault_mismatch() -> None:
    # vault_001 toml + vault_002 bundle + vault_001 phrase. The vault_uuid
    # comparison fires BEFORE mnemonic parsing, so even an "invalid" phrase
    # would still produce VaultMismatch on this input pair.
    toml_001 = _read_fixture(1, "vault.toml")
    bundle_002 = _read_fixture(2, "identity.bundle.enc")
    phrase_001 = _golden_vault_phrase(1)
    with pytest.raises(secretary_ffi_py.VaultMismatch):
        secretary_ffi_py.open_with_recovery(toml_001, bundle_002, phrase_001)


def test_open_with_recovery_accepts_bytearray_for_caller_zeroize_discipline() -> None:
    """Documents the design: mnemonic accepted as bytes-like; disciplined
    callers can zero a mutable bytearray after the call (parallel to the
    password-input pattern from B.2)."""
    toml = _read_fixture(1, "vault.toml")
    bundle = _read_fixture(1, "identity.bundle.enc")
    phrase = bytearray(_golden_vault_phrase(1))
    with secretary_ffi_py.open_with_recovery(toml, bundle, phrase) as identity:
        assert identity.display_name() == VAULT_001_OWNER_DISPLAY_NAME
    # Caller's zeroize discipline (recommended for first-party clients):
    for i in range(len(phrase)):
        phrase[i] = 0
    assert all(b == 0 for b in phrase)
